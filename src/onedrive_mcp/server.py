"""MCP server exposing OneDrive file operations as tools.

Tools: list_files, get_file_metadata, upload_file, download_file,
create_sharing_link, search_files.

All tool invocations are audit-logged to stderr as structured JSON.
Errors are sanitized before returning to the LLM.
"""

import json
import logging
import os
import time
from collections.abc import Callable, Coroutine
from functools import wraps
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .auth import Auth
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
TENANT_ID = os.environ.get("ONEDRIVE_MCP_TENANT_ID", "common")
DOWNLOAD_DIR = Path(os.environ.get("ONEDRIVE_MCP_DOWNLOAD_DIR", ".")).resolve()

mcp = FastMCP(
    "onedrive",
    instructions=(
        "OneDrive file operations: list, upload, download, share, "
        "and search files in Microsoft OneDrive."
    ),
)

_auth: Auth | None = None
_graph: GraphClient | None = None


def _get_graph() -> GraphClient:
    global _auth, _graph
    if _graph is None:
        _auth = Auth(CLIENT_ID, TENANT_ID)
        _graph = GraphClient(_auth)
    return _graph


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


def serve() -> None:
    """Start the MCP server on stdio transport."""
    logger.info("OneDrive MCP server starting")
    mcp.run()
