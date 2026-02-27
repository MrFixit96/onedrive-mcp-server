"""Microsoft Graph API client for OneDrive file operations.

Handles list, upload (simple + resumable session), download (path-validated),
sharing link creation, metadata retrieval, and search.
Error messages are sanitized before propagation.
"""

import asyncio
import logging
import re
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

import httpx

logger = logging.getLogger("onedrive_mcp.graph")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB upload chunks
SIMPLE_UPLOAD_LIMIT = 4 * 1024 * 1024  # Files under 4 MB use simple PUT

# Patterns to strip from error messages before returning to the LLM
_SANITIZE_PATTERNS = [
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
    re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"),
    re.compile(r"https://[^\s]*upload\.microsoft\.com[^\s]*"),
]


def _sanitize_error(msg: str) -> str:
    """Remove tokens, correlation IDs, and internal URLs from error text."""
    for pattern in _SANITIZE_PATTERNS:
        msg = pattern.sub("[REDACTED]", msg)
    return msg


class GraphAPIError(Exception):
    """Raised when the Graph API returns an error response."""

    def __init__(self, status: int, message: str):
        self.status = status
        self.safe_message = _sanitize_error(message)
        super().__init__(f"Graph API {status}: {self.safe_message}")


class GraphClient:
    """Async client for OneDrive operations via Microsoft Graph."""

    def __init__(self, token_provider: Callable[[], str]):
        self._token_provider = token_provider
        self._client: httpx.AsyncClient | None = None

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=GRAPH_BASE,
                timeout=60.0,
                follow_redirects=False,
            )
        return self._client

    async def _get_headers(self) -> dict[str, str]:
        token = await asyncio.to_thread(self._token_provider)
        return {"Authorization": f"Bearer {token}"}

    async def _request(
        self, method: str, path: str, **kwargs: Any
    ) -> httpx.Response:
        client = await self._ensure_client()
        headers = {**kwargs.pop("headers", {}), **(await self._get_headers())}
        resp = await client.request(method, path, headers=headers, **kwargs)
        if resp.status_code >= 400:
            try:
                msg = resp.json().get("error", {}).get("message", resp.text)
            except Exception:
                msg = resp.text
            raise GraphAPIError(resp.status_code, msg)
        return resp

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Normalize a OneDrive path, stripping leading/trailing slashes."""
        cleaned = path.strip().strip("/")
        p = PurePosixPath(cleaned) if cleaned else PurePosixPath(".")
        return str(p) if str(p) != "." else ""

    # ── List ────────────────────────────────────────────────────────────

    async def list_files(self, folder_path: str = "/") -> list[dict[str, Any]]:
        normalized = self._normalize_path(folder_path)
        url = (
            f"/me/drive/root:/{normalized}:/children"
            if normalized
            else "/me/drive/root/children"
        )
        resp = await self._request("GET", url, params={"$top": "100"})
        return [self._format_item(item) for item in resp.json().get("value", [])]

    # ── Metadata ────────────────────────────────────────────────────────

    async def get_file_metadata(self, file_path: str) -> dict[str, Any]:
        normalized = self._normalize_path(file_path)
        if not normalized:
            raise ValueError("File path cannot be empty")
        item = (await self._request("GET", f"/me/drive/root:/{normalized}:")).json()
        return {
            "name": item["name"],
            "size": item.get("size", 0),
            "mimeType": item.get("file", {}).get("mimeType", ""),
            "lastModified": item.get("lastModifiedDateTime", ""),
            "createdBy": (
                item.get("createdBy", {}).get("user", {}).get("displayName", "")
            ),
            "webUrl": item.get("webUrl", ""),
            "id": item.get("id", ""),
        }

    # ── Upload ──────────────────────────────────────────────────────────

    async def upload_file(
        self, local_path: Path, remote_path: str
    ) -> dict[str, Any]:
        normalized = self._normalize_path(remote_path)
        if not normalized:
            raise ValueError("Remote path cannot be empty")
        if not local_path.exists():
            raise FileNotFoundError(f"Local file not found: {local_path}")

        file_size = local_path.stat().st_size
        if file_size <= SIMPLE_UPLOAD_LIMIT:
            return await self._simple_upload(local_path, normalized)
        return await self._session_upload(local_path, normalized, file_size)

    async def _simple_upload(
        self, local_path: Path, remote_path: str
    ) -> dict[str, Any]:
        content = local_path.read_bytes()
        resp = await self._request(
            "PUT",
            f"/me/drive/root:/{remote_path}:/content",
            content=content,
            headers={"Content-Type": "application/octet-stream"},
        )
        item = resp.json()
        return self._format_result(item)

    async def _session_upload(
        self, local_path: Path, remote_path: str, file_size: int
    ) -> dict[str, Any]:
        resp = await self._request(
            "POST",
            f"/me/drive/root:/{remote_path}:/createUploadSession",
            json={"item": {"@microsoft.graph.conflictBehavior": "replace"}},
        )
        upload_url = resp.json()["uploadUrl"]

        # Upload session URL is pre-authenticated — no Bearer token needed
        client = await self._ensure_client()
        with open(local_path, "rb") as f:
            offset = 0
            while offset < file_size:
                chunk = f.read(CHUNK_SIZE)
                chunk_end = offset + len(chunk) - 1
                resp = await client.put(
                    upload_url,
                    content=chunk,
                    headers={
                        "Content-Length": str(len(chunk)),
                        "Content-Range": f"bytes {offset}-{chunk_end}/{file_size}",
                    },
                    timeout=120.0,
                )
                if resp.status_code >= 400:
                    raise GraphAPIError(resp.status_code, resp.text)
                offset += len(chunk)

        return self._format_result(resp.json())

    # ── Sharing Link ────────────────────────────────────────────────────

    async def create_sharing_link(
        self,
        file_path: str,
        link_type: str = "view",
        scope: str = "organization",
    ) -> dict[str, str]:
        normalized = self._normalize_path(file_path)
        if not normalized:
            raise ValueError("File path cannot be empty")
        if link_type not in ("view", "edit"):
            raise ValueError("link_type must be 'view' or 'edit'")
        if scope not in ("anonymous", "organization"):
            raise ValueError("scope must be 'anonymous' or 'organization'")

        resp = await self._request(
            "POST",
            f"/me/drive/root:/{normalized}:/createLink",
            json={"type": link_type, "scope": scope},
        )
        link = resp.json().get("link", {})
        return {
            "webUrl": link.get("webUrl", ""),
            "type": link.get("type", ""),
            "scope": link.get("scope", ""),
        }

    # ── Download ────────────────────────────────────────────────────────

    async def download_file(self, remote_path: str, save_dir: Path) -> Path:
        normalized = self._normalize_path(remote_path)
        if not normalized:
            raise ValueError("Remote path cannot be empty")

        metadata = await self.get_file_metadata(remote_path)
        filename = metadata["name"]

        # Path traversal protection
        save_path = (save_dir / filename).resolve()
        safe_base = save_dir.resolve()
        if not str(save_path).startswith(str(safe_base)):
            raise ValueError(f"Path traversal blocked: {filename}")

        resp = await self._request(
            "GET", f"/me/drive/root:/{normalized}:/content"
        )
        if resp.status_code == 302:
            download_url = resp.headers["Location"]
            client = await self._ensure_client()
            resp = await client.get(download_url, timeout=120.0)
            if resp.status_code >= 400:
                raise GraphAPIError(resp.status_code, "Download failed")

        save_path.write_bytes(resp.content)
        return save_path

    # ── Search ──────────────────────────────────────────────────────────

    async def search_files(self, query: str) -> list[dict[str, Any]]:
        encoded = quote(query)
        resp = await self._request(
            "GET",
            f"/me/drive/root/search(q='{encoded}')",
            params={"$top": "25"},
        )
        items = []
        for item in resp.json().get("value", []):
            parent = item.get("parentReference", {})
            entry = self._format_item(item)
            entry["path"] = (
                parent.get("path", "").replace("/drive/root:", "")
                + "/"
                + item["name"]
            )
            items.append(entry)
        return items

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _format_item(item: dict[str, Any]) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "name": item["name"],
            "type": "folder" if "folder" in item else "file",
            "size": item.get("size", 0),
            "lastModified": item.get("lastModifiedDateTime", ""),
            "webUrl": item.get("webUrl", ""),
        }
        if "folder" in item:
            entry["childCount"] = item["folder"].get("childCount", 0)
        return entry

    @staticmethod
    def _format_result(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "name": item.get("name", ""),
            "webUrl": item.get("webUrl", ""),
            "size": item.get("size", 0),
        }

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
