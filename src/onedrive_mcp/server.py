"""MCP server exposing OneDrive file operations as tools.

Tools: list_files, get_file_metadata, upload_file, download_file,
create_sharing_link, search_files.
"""

import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .auth import Auth
from .graph import GraphClient

CLIENT_ID = os.environ.get("ONEDRIVE_MCP_CLIENT_ID", "")
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
        if not CLIENT_ID:
            raise RuntimeError(
                "ONEDRIVE_MCP_CLIENT_ID env var is required. "
                "Set it to your Azure AD app registration client ID."
            )
        _auth = Auth(CLIENT_ID, TENANT_ID)
        _graph = GraphClient(_auth)
    return _graph


@mcp.tool(
    annotations=ToolAnnotations(
        title="List OneDrive Files",
        readOnlyHint=True,
        destructiveHint=False,
        openWorldHint=False,
    ),
)
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
async def upload_file(local_path: str, remote_path: str) -> str:
    """Upload a local file to OneDrive. Files over 4 MB use resumable upload.

    Args:
        local_path: Absolute path to the local file.
        remote_path: Destination path in OneDrive (e.g. "Documents/report.docx").
    """
    local = Path(local_path).resolve()
    if not local.exists():
        return json.dumps({"error": f"File not found: {local_path}"})
    if not local.is_file():
        return json.dumps({"error": f"Not a file: {local_path}"})
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
async def download_file(remote_path: str, save_directory: str = "") -> str:
    """Download a file from OneDrive to the local filesystem.

    Args:
        remote_path: Path to the file in OneDrive (e.g. "Documents/report.docx").
        save_directory: Local directory to save to. Defaults to ONEDRIVE_MCP_DOWNLOAD_DIR or cwd.
    """
    save_dir = Path(save_directory).resolve() if save_directory else DOWNLOAD_DIR
    if not save_dir.is_dir():
        return json.dumps({"error": f"Directory not found: {save_dir}"})
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
    mcp.run()
