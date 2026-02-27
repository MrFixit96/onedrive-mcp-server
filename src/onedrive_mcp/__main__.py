"""CLI entry point for onedrive-mcp.

Usage:
    onedrive-mcp auth    # Interactive device-code sign-in
    onedrive-mcp         # Start MCP server (stdio)
"""

import os
import sys


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "auth":
        _run_auth()
    else:
        _run_server()


def _run_auth() -> None:
    from .auth import Auth

    client_id = os.environ.get("ONEDRIVE_MCP_CLIENT_ID", "")
    tenant_id = os.environ.get("ONEDRIVE_MCP_TENANT_ID", "common")

    if not client_id:
        print(
            "Error: ONEDRIVE_MCP_CLIENT_ID environment variable is required.\n"
            "\nSetup steps:\n"
            "  1. Go to https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps\n"
            "  2. New registration → name it 'OneDrive MCP'\n"
            "  3. Supported account types: personal + organizational\n"
            "  4. Add platform: Mobile and desktop applications\n"
            "     Redirect URI: https://login.microsoftonline.com/common/oauth2/nativeclient\n"
            "  5. API permissions → Add: Files.ReadWrite, User.Read\n"
            "  6. Copy the Application (client) ID\n"
            "  7. Set: export ONEDRIVE_MCP_CLIENT_ID=<client-id>",
            file=sys.stderr,
        )
        sys.exit(1)

    auth = Auth(client_id, tenant_id)
    try:
        auth.authenticate_interactive()
        print("Authentication successful. Token cached securely.", file=sys.stderr)
    except Exception as e:
        print(f"Authentication failed: {e}", file=sys.stderr)
        sys.exit(1)


def _run_server() -> None:
    from .server import serve

    serve()


if __name__ == "__main__":
    main()
