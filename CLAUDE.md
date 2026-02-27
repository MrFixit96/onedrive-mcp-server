# OneDrive MCP Server

## Overview
Minimal, secure MCP server providing OneDrive file operations via Microsoft Graph API. Built as a secure alternative to existing MCP servers (elyxlz/microsoft-mcp had 4 CRITICAL vulnerabilities).

## Architecture
- `src/onedrive_mcp/auth.py` — MSAL device code auth with secure token cache
- `src/onedrive_mcp/graph.py` — Async Microsoft Graph API client (httpx)
- `src/onedrive_mcp/server.py` — FastMCP server with 6 tools
- `src/onedrive_mcp/__main__.py` — CLI entry point (auth + serve)

## Tools
| Tool | Purpose | Read-only |
|------|---------|-----------|
| `list_files` | List files/folders at a path | Yes |
| `get_file_metadata` | Get file size, type, dates | Yes |
| `search_files` | Search by name/content | Yes |
| `upload_file` | Upload local file to OneDrive | No |
| `download_file` | Download file to local disk | No |
| `create_sharing_link` | Generate view/edit sharing link | No |

## Security Design
- OAuth scopes limited to `Files.ReadWrite` + `User.Read` (no mail, calendar, contacts)
- Token cache restricted to owner-only permissions (chmod 600 / icacls)
- Download paths validated against base directory (no path traversal)
- No `ast.literal_eval` or `eval` anywhere
- No `follow_redirects=True` on HTTP client
- All tool inputs validated before Graph API calls

## Usage
```bash
# Auth first
export ONEDRIVE_MCP_CLIENT_ID=<your-app-id>
onedrive-mcp auth

# Run as MCP server (stdio)
onedrive-mcp
```

## Key Conventions
- Python 3.11+
- Async httpx for HTTP, sync MSAL wrapped with asyncio.to_thread
- No third-party MCP wrappers — uses official `mcp` SDK
- Commits include `Co-authored-by: Copilot` trailer
