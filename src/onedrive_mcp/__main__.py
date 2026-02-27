"""CLI entry point for onedrive-mcp.

Usage:
    onedrive-mcp auth    # Sign in with your Microsoft account (SSO)
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

    # Both are optional — defaults to Microsoft Graph CLI Tools client ID
    client_id = os.environ.get("ONEDRIVE_MCP_CLIENT_ID") or None
    tenant_id = os.environ.get("ONEDRIVE_MCP_TENANT_ID", "common")

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
