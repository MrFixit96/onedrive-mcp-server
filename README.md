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

## Quick Start

```bash
# Install
pip install git+https://github.com/MrFixit96/onedrive-mcp-server.git

# Sign in with your Microsoft account (SSO — no app registration needed)
onedrive-mcp auth
```

That's it. On Windows, a native SSO popup uses your existing Microsoft account.
On other platforms, you'll get a device code to enter at microsoft.com/devicelogin.
Your org's SSO handles the rest.

## Security

- **Zero-config auth**: Uses Microsoft Graph Command Line Tools client ID (pre-approved in most enterprise tenants) — no Azure AD app registration required
- **Windows SSO**: WAM broker integration uses your existing Windows Microsoft account
- **OS keyring token storage**: Windows Credential Vault, macOS Keychain, or Linux SecretService (falls back to owner-only file)
- **Narrow OAuth scopes**: Only `Files.ReadWrite` + `User.Read` — no mail, calendar, or contacts access
- **Error sanitization**: Bearer tokens, correlation IDs, and internal URLs stripped from all error messages before reaching the LLM
- **Audit logging**: Structured JSON to stderr — every tool invocation logged with timing, redacted args, and status
- **Path traversal protection**: Download paths validated against a safe base directory
- **No eval/literal_eval**: Zero use of `eval`, `ast.literal_eval`, or `exec`

## Installation

```bash
# Clone and install
git clone https://github.com/MrFixit96/onedrive-mcp-server.git
cd onedrive-mcp-server
pip install -e .

# Optional: install Windows SSO broker support
pip install -e ".[broker]"

# Optional: install dev tools (pytest, ruff)
pip install -e ".[dev]"
```

## Authentication

```bash
# Just sign in — no environment variables needed
onedrive-mcp auth
```

**On Windows** (with broker installed): A native SSO popup appears using your existing Windows Microsoft account. One click, done.

**On other platforms**: Device code flow — visit the URL shown, enter the code, sign in with your corporate email. Your org's SSO/identity provider handles the login automatically.

Tokens are cached securely in your OS keyring (Windows Credential Vault / macOS Keychain / Linux SecretService).

### Advanced: Custom Azure AD App

If your organization requires a specific app registration, you can override the default:

```bash
export ONEDRIVE_MCP_CLIENT_ID=<your-client-id>
export ONEDRIVE_MCP_TENANT_ID=<your-tenant-id>
onedrive-mcp auth
```

## MCP Server Configuration

### Claude Code

```json
{
  "mcpServers": {
    "onedrive": {
      "command": "onedrive-mcp"
    }
  }
}
```

### GitHub Copilot CLI

```json
{
  "mcpServers": {
    "onedrive": {
      "command": "onedrive-mcp"
    }
  }
}
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ONEDRIVE_MCP_CLIENT_ID` | No | Graph CLI Tools ID | Override with custom Azure AD app client ID |
| `ONEDRIVE_MCP_TENANT_ID` | No | `common` | Azure AD tenant ID (multi-tenant by default) |
| `ONEDRIVE_MCP_DOWNLOAD_DIR` | No | `.` (cwd) | Base directory for file downloads |
| `ONEDRIVE_MCP_LOG_LEVEL` | No | `INFO` | Audit log level (DEBUG, INFO, WARNING, ERROR) |

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

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests (43 tests)
pytest tests/ -v

# Lint
ruff check src/ tests/

# Auto-fix lint issues
ruff check src/ tests/ --fix
```

## Architecture

```
src/onedrive_mcp/
├── __init__.py       # Package metadata
├── __main__.py       # CLI: auth subcommand + server startup
├── auth.py           # SSO broker + device-code flow + OS keyring cache
├── graph.py          # Async Microsoft Graph client (httpx) + error sanitization
└── server.py         # FastMCP server with 6 tools + audit logging
```

- **~350 lines** of core logic (auth + graph + server)
- **43 tests** covering auth, graph API, server tools, error sanitization, audit logging
- **Zero** third-party MCP wrappers — uses official `mcp` SDK
- **Async** httpx for HTTP, sync MSAL wrapped via `asyncio.to_thread`
- **Stdio** transport (standard MCP protocol)

## Auth Flow

```
onedrive-mcp auth
    │
    ├─ Cached token? ──→ Silent refresh ──→ Done
    │
    ├─ Windows + broker? ──→ Native SSO popup ──→ Done
    │
    └─ Device code flow ──→ microsoft.com/devicelogin
                               │
                               └─ Org SSO (IBM/Google/Okta/etc) ──→ Done
```

## License

MIT
