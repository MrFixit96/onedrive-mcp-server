"""MCP server exposing OneDrive file operations as tools.

Tools: list_files, get_file_metadata, upload_file, download_file,
create_sharing_link, search_files.

Supports two transport modes:
  - stdio:  MSAL-based auth (device code / broker) — default
  - http:   RFC 9728 Bearer token passthrough — MCP client handles OAuth

All tool invocations are audit-logged to stderr as structured JSON.
Errors are sanitized before returning to the LLM.
"""

import json
import logging
import os
import sys
import time
from collections.abc import Callable, Coroutine
from functools import wraps
from pathlib import Path
from typing import Any
from urllib.parse import quote

if sys.platform == "win32":
    import winreg

import jwt
from mcp.server.auth.provider import AccessToken
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import AuthSettings
from mcp.types import ToolAnnotations

from .graph import GraphClient

# ── Logging setup ───────────────────────────────────────────────────────

logging.basicConfig(
    level=os.environ.get("ONEDRIVE_MCP_LOG_LEVEL", "INFO").upper(),
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
    stream=__import__("sys").stderr,
)
logger = logging.getLogger("onedrive_mcp.server")

# ── Configuration ───────────────────────────────────────────────────────

CLIENT_ID = os.environ.get("ONEDRIVE_MCP_CLIENT_ID") or None
TENANT_ID = os.environ.get("ONEDRIVE_MCP_TENANT_ID") or None
DOWNLOAD_DIR = Path(os.environ.get("ONEDRIVE_MCP_DOWNLOAD_DIR", ".")).resolve()
HTTP_PORT = int(os.environ.get("ONEDRIVE_MCP_PORT", "3001"))

# Transport mode: set by serve() or serve_http()
_transport_mode: str = "stdio"

mcp = FastMCP(
    "onedrive",
    instructions=(
        "OneDrive file operations: list, upload, download, share, "
        "and search files in Microsoft OneDrive."
    ),
)

_auth: Any = None  # Auth instance (stdio mode only)
_graph: GraphClient | None = None


def _http_token_provider() -> str:
    """Read Bearer token from the MCP auth context (HTTP mode only)."""
    from mcp.server.auth.middleware.auth_context import get_access_token

    access_token = get_access_token()
    if access_token is None:
        raise RuntimeError("No authenticated user — is the MCP client sending a Bearer token?")
    return access_token.token


def _get_graph() -> GraphClient:
    global _auth, _graph
    if _transport_mode == "http":
        # HTTP mode: reuse client, token comes from auth context per-request
        if _graph is None:
            _graph = GraphClient(token_provider=_http_token_provider)
        return _graph
    else:
        # Stdio mode: use MSAL auth
        if _graph is None:
            from .auth import Auth

            _auth = Auth(CLIENT_ID, TENANT_ID)
            _graph = GraphClient(token_provider=_auth.get_token)
        return _graph


# ── Token verifier (HTTP mode) ─────────────────────────────────────────


class PassthroughTokenVerifier:
    """Decode JWT claims without cryptographic verification.

    The MCP client (VS Code) already authenticated the user.
    Microsoft Graph validates the token server-side on every API call.
    We extract claims only for audit logging and expiry checking.
    """

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
            return AccessToken(
                token=token,
                client_id=claims.get("appid", claims.get("azp", "unknown")),
                scopes=claims.get("scp", "").split(),
                expires_at=claims.get("exp"),
            )
        except Exception:
            return None


# ── Audit + error wrapper ──────────────────────────────────────────────

def _redact_path(path: str) -> str:
    """Show only the filename, not the full local path."""
    return Path(path).name if path else ""


def audited_tool(fn: Callable[..., Coroutine[Any, Any, str]]):
    """Wrap a tool function with audit logging and error sanitization."""

    @wraps(fn)
    async def wrapper(**kwargs: Any) -> str:
        tool_name = fn.__name__
        # Redact local paths in audit log
        safe_args = {
            k: _redact_path(v) if "path" in k.lower() and isinstance(v, str) else v
            for k, v in kwargs.items()
        }
        start = time.monotonic()
        try:
            result = await fn(**kwargs)
            elapsed = time.monotonic() - start
            logger.info(
                'tool="%s" args=%s status="ok" elapsed_ms=%.0f',
                tool_name,
                json.dumps(safe_args),
                elapsed * 1000,
            )
            return result
        except Exception as exc:
            elapsed = time.monotonic() - start
            # Log the real error internally
            logger.error(
                'tool="%s" args=%s status="error" error="%s" elapsed_ms=%.0f',
                tool_name,
                json.dumps(safe_args),
                str(exc),
                elapsed * 1000,
            )
            # Return a safe error message to the LLM
            safe_msg = str(exc)
            # Strip anything after "Graph API NNN:" if present
            if hasattr(exc, "safe_message"):
                safe_msg = f"Graph API error: {exc.safe_message}"
            return json.dumps({"error": safe_msg})

    return wrapper


# ── Tools ───────────────────────────────────────────────────────────────

@mcp.tool(
    annotations=ToolAnnotations(
        title="List OneDrive Files",
        readOnlyHint=True,
        destructiveHint=False,
        openWorldHint=False,
    ),
)
@audited_tool
async def list_files(folder_path: str = "/") -> str:
    """List files and folders in a OneDrive directory.

    Args:
        folder_path: Path in OneDrive. Use "/" for root, or e.g. "Documents/Reports".
    """
    graph = _get_graph()
    items = await graph.list_files(folder_path)
    return json.dumps(items, indent=2)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get File Metadata",
        readOnlyHint=True,
        destructiveHint=False,
        openWorldHint=False,
    ),
)
@audited_tool
async def get_file_metadata(file_path: str) -> str:
    """Get metadata for a file in OneDrive (size, type, modified date, creator).

    Args:
        file_path: Path to the file (e.g. "Documents/report.docx").
    """
    graph = _get_graph()
    metadata = await graph.get_file_metadata(file_path)
    return json.dumps(metadata, indent=2)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Upload File to OneDrive",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
@audited_tool
async def upload_file(local_path: str, remote_path: str) -> str:
    """Upload a local file to OneDrive. Files over 4 MB use resumable upload.

    Args:
        local_path: Absolute path to the local file.
        remote_path: Destination path in OneDrive (e.g. "Documents/report.docx").
    """
    local = Path(local_path).resolve()
    if not local.exists():
        return json.dumps({"error": f"File not found: {local.name}"})
    if not local.is_file():
        return json.dumps({"error": f"Not a file: {local.name}"})
    graph = _get_graph()
    result = await graph.upload_file(local, remote_path)
    return json.dumps(result, indent=2)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Create Sharing Link",
        readOnlyHint=False,
        destructiveHint=False,
        openWorldHint=True,
    ),
)
@audited_tool
async def create_sharing_link(
    file_path: str,
    link_type: str = "view",
    scope: str = "organization",
) -> str:
    """Create a sharing link for a file in OneDrive.

    Args:
        file_path: Path to the file (e.g. "Documents/report.docx").
        link_type: "view" for read-only, "edit" for read-write.
        scope: "organization" for internal sharing, "anonymous" for public.
    """
    graph = _get_graph()
    result = await graph.create_sharing_link(file_path, link_type, scope)
    return json.dumps(result, indent=2)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Download File from OneDrive",
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
@audited_tool
async def download_file(remote_path: str, save_directory: str = "") -> str:
    """Download a file from OneDrive to the local filesystem.

    Args:
        remote_path: Path to the file in OneDrive (e.g. "Documents/report.docx").
        save_directory: Local directory to save to. Defaults to ONEDRIVE_MCP_DOWNLOAD_DIR or cwd.
    """
    save_dir = Path(save_directory).resolve() if save_directory else DOWNLOAD_DIR
    if not save_dir.is_dir():
        return json.dumps({"error": "Save directory does not exist"})
    graph = _get_graph()
    saved = await graph.download_file(remote_path, save_dir)
    return json.dumps({"saved_to": str(saved), "size": saved.stat().st_size})


@mcp.tool(
    annotations=ToolAnnotations(
        title="Search OneDrive Files",
        readOnlyHint=True,
        destructiveHint=False,
        openWorldHint=False,
    ),
)
@audited_tool
async def search_files(query: str) -> str:
    """Search for files in OneDrive by name or content.

    Args:
        query: Search text (e.g. "quarterly report", "budget.xlsx").
    """
    graph = _get_graph()
    results = await graph.search_files(query)
    return json.dumps(results, indent=2)


def _discover_onedrive_accounts() -> list[dict[str, str]]:
    """Read OneDrive account mappings from the Windows registry.

    Returns a list of dicts with keys: local_folder, spo_url, email, type.
    Falls back to ONEDRIVE_MCP_SHARE_MAP env var on non-Windows platforms.
    Format: "local_path|spo_base_url;local_path2|spo_base_url2"
    """
    accounts: list[dict[str, str]] = []

    # Try Windows registry first
    if sys.platform == "win32":
        try:
            base_key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\OneDrive\Accounts",
            )
            idx = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(base_key, idx)
                    idx += 1
                    sub_key = winreg.OpenKey(base_key, sub_name)
                    try:
                        user_folder = winreg.QueryValueEx(sub_key, "UserFolder")[0]
                    except FileNotFoundError:
                        continue
                    spo_url = ""
                    email = ""
                    acct_type = "personal"
                    try:
                        endpoint = winreg.QueryValueEx(sub_key, "ServiceEndpointUri")[0]
                        # Strip /_api suffix to get the base SharePoint URL
                        spo_url = endpoint.rsplit("/_api", 1)[0]
                        acct_type = "business"
                    except FileNotFoundError:
                        pass
                    try:
                        email = winreg.QueryValueEx(sub_key, "UserEmail")[0]
                    except FileNotFoundError:
                        pass
                    accounts.append({
                        "local_folder": user_folder,
                        "spo_url": spo_url,
                        "email": email,
                        "type": acct_type,
                    })
                except OSError:
                    break
        except OSError:
            pass

    # Fallback: env var for non-Windows or if registry is empty
    if not accounts:
        share_map = os.environ.get("ONEDRIVE_MCP_SHARE_MAP", "")
        for entry in share_map.split(";"):
            if "|" in entry:
                local, url = entry.split("|", 1)
                accounts.append({
                    "local_folder": local.strip(),
                    "spo_url": url.strip(),
                    "email": "",
                    "type": "business",
                })

    return accounts


def _resolve_share_url(local_path: str) -> dict[str, str]:
    """Map a local file path to its SharePoint/OneDrive web URL.

    Returns dict with url, account_email, account_type, or error.
    """
    resolved = Path(local_path).resolve()
    if not resolved.exists():
        return {"error": f"File not found: {resolved.name}"}

    accounts = _discover_onedrive_accounts()
    if not accounts:
        return {"error": "No OneDrive accounts found. Set ONEDRIVE_MCP_SHARE_MAP env var."}

    # Sort by longest path first for best match
    accounts.sort(key=lambda a: len(a["local_folder"]), reverse=True)

    for acct in accounts:
        acct_folder = Path(acct["local_folder"]).resolve()
        try:
            rel = resolved.relative_to(acct_folder)
        except ValueError:
            continue

        if acct["type"] == "business" and acct["spo_url"]:
            # Business: construct SharePoint URL
            # OneDrive Business syncs to /Documents/ library
            rel_posix = rel.as_posix()
            encoded_path = quote(rel_posix, safe="/")
            url = f"{acct['spo_url']}/Documents/{encoded_path}"
            return {
                "url": url,
                "account_email": acct["email"],
                "account_type": "business",
                "note": "Recipients in the same tenant can open this URL directly with SSO.",
            }
        else:
            return {
                "error": "Personal OneDrive detected. Sharing links require Graph API.",
                "account_email": acct["email"],
                "account_type": "personal",
                "suggestion": "Move the file to your Business OneDrive folder "
                "for direct URL sharing.",
            }

    return {"error": f"File is not inside any synced OneDrive folder: {resolved.name}"}


@mcp.tool(
    annotations=ToolAnnotations(
        title="Generate Share URL",
        readOnlyHint=True,
        destructiveHint=False,
        openWorldHint=False,
    ),
)
@audited_tool
async def generate_share_url(local_path: str) -> str:
    """Generate a SharePoint direct URL for a locally synced OneDrive file.

    Works without Graph API authentication by reading the OneDrive sync
    configuration from the Windows registry and mapping local paths to
    their corresponding SharePoint URLs.

    Args:
        local_path: Absolute path to a file inside a synced OneDrive folder.
    """
    result = _resolve_share_url(local_path)
    return json.dumps(result, indent=2)


def serve() -> None:
    """Start the MCP server on stdio transport (MSAL auth)."""
    global _transport_mode
    _transport_mode = "stdio"
    logger.info("OneDrive MCP server starting (stdio)")
    mcp.run()


def serve_http(port: int | None = None) -> None:
    """Start the MCP server on HTTP transport (RFC 9728 Bearer token auth).

    The MCP client handles the full OAuth flow and passes Bearer tokens.
    """
    global _transport_mode
    _transport_mode = "http"
    actual_port = port or HTTP_PORT
    tenant = TENANT_ID or "organizations"

    # Configure auth for HTTP mode
    mcp.settings.auth = AuthSettings(
        issuer_url=f"https://login.microsoftonline.com/{tenant}/v2.0",
        resource_server_url=f"http://localhost:{actual_port}",
        required_scopes=["Files.ReadWrite", "User.Read"],
    )
    mcp._token_verifier = PassthroughTokenVerifier()
    mcp.settings.port = actual_port
    mcp.settings.host = "127.0.0.1"

    logger.info("OneDrive MCP server starting (HTTP on port %d)", actual_port)
    mcp.run(transport="streamable-http")
