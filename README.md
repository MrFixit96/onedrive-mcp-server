# OneDrive MCP Server

Minimal, secure [MCP](https://modelcontextprotocol.io/) server for OneDrive file sharing via Microsoft Graph API.

Built as a secure alternative after a [security audit](https://github.com/MrFixit96/hc-platform-agent) found 4 CRITICAL vulnerabilities in `elyxlz/microsoft-mcp` and the official `microsoft/files-mcp-server` lacked sharing link support.

## Features

| Tool | Description |
|------|-------------|
| `list_files` | List files and folders at any OneDrive path |
| `get_file_metadata` | Get size, type, dates, creator for a file |
| `search_files` | Full-text search across file names and content |
| `upload_file` | Upload local files (resumable for >4 MB) |
| `download_file` | Download files with path-traversal protection |
| `create_sharing_link` | Generate view or edit sharing links |

## Security

This server was designed to address specific vulnerabilities found in existing MCP servers:

- **Narrow OAuth scopes**: Only `Files.ReadWrite` + `User.Read` — no mail, calendar, or contacts access
- **Secure token cache**: File permissions restricted to owner only (`chmod 600` / `icacls`)
- **Path traversal protection**: Download paths validated against a safe base directory
- **No eval/literal_eval**: Zero use of `eval`, `ast.literal_eval`, or `exec`
- **No auto-redirect**: HTTP client does not follow redirects automatically
- **Input validation**: All tool inputs validated before Graph API calls

## Prerequisites

### Azure AD App Registration

1. Go to [Azure Portal → App Registrations](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps)
2. Click **New registration**
   - Name: `OneDrive MCP`
   - Supported account types: **Accounts in any organizational directory and personal Microsoft accounts**
3. Under **Authentication** → **Add a platform** → **Mobile and desktop applications**
   - Redirect URI: `https://login.microsoftonline.com/common/oauth2/nativeclient`
4. Under **API permissions** → **Add a permission** → **Microsoft Graph** → **Delegated permissions**:
   - `Files.ReadWrite`
   - `User.Read`
5. Copy the **Application (client) ID** from the Overview page

## Installation

```bash
# Clone and install
git clone https://github.com/MrFixit96/onedrive-mcp-server.git
cd onedrive-mcp-server
pip install -e .

# Or install directly from GitHub
pip install git+https://github.com/MrFixit96/onedrive-mcp-server.git
```

## Authentication

```bash
# Set your client ID
export ONEDRIVE_MCP_CLIENT_ID=<your-client-id>

# Optional: set tenant (default: "common" for multi-tenant)
export ONEDRIVE_MCP_TENANT_ID=<your-tenant-id>

# Run interactive device-code auth
onedrive-mcp auth
```

This opens a browser-based sign-in flow. Tokens are cached securely at `~/.config/onedrive-mcp/token_cache.json` with owner-only file permissions.

## MCP Server Configuration

### Claude Code

Add to your Claude Code MCP settings (`.claude/settings.json` or via `claude mcp add`):

```json
{
  "mcpServers": {
    "onedrive": {
      "command": "onedrive-mcp",
      "env": {
        "ONEDRIVE_MCP_CLIENT_ID": "<your-client-id>"
      }
    }
  }
}
```

### GitHub Copilot CLI

Add to your MCP configuration:

```json
{
  "mcpServers": {
    "onedrive": {
      "command": "onedrive-mcp",
      "env": {
        "ONEDRIVE_MCP_CLIENT_ID": "<your-client-id>"
      }
    }
  }
}
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ONEDRIVE_MCP_CLIENT_ID` | Yes | — | Azure AD app registration client ID |
| `ONEDRIVE_MCP_TENANT_ID` | No | `common` | Azure AD tenant ID |
| `ONEDRIVE_MCP_DOWNLOAD_DIR` | No | `.` (cwd) | Base directory for file downloads |

## Usage Examples

Once configured as an MCP server, tools are available to your AI assistant:

```
"List my OneDrive files"
→ calls list_files("/")

"Upload docs/report.docx to my OneDrive Documents folder"
→ calls upload_file("C:\path\to\docs\report.docx", "Documents/report.docx")

"Create a sharing link for Documents/report.docx"
→ calls create_sharing_link("Documents/report.docx", "view", "organization")

"Search for files about quarterly budget"
→ calls search_files("quarterly budget")
```

## Architecture

```
src/onedrive_mcp/
├── __init__.py       # Package metadata
├── __main__.py       # CLI: auth subcommand + server startup
├── auth.py           # MSAL device-code flow + secure token cache
├── graph.py          # Async Microsoft Graph client (httpx)
└── server.py         # FastMCP server with 6 tools
```

- **~250 lines** of core logic (auth + graph + server)
- **Zero** third-party MCP wrappers — uses official `mcp` SDK
- **Async** httpx for HTTP, sync MSAL wrapped via `asyncio.to_thread`
- **Stdio** transport (standard MCP protocol)

## License

MIT
