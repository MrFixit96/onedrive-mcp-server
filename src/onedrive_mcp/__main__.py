"""CLI entry point for onedrive-mcp.

Usage:
    onedrive-mcp auth    # Sign in with your Microsoft account (SSO — stdio mode)
    onedrive-mcp         # Start MCP server (stdio, MSAL auth)
    onedrive-mcp --http  # Start MCP server (HTTP, Bearer token from MCP client)
"""

import os
import sys


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "auth":
        _run_auth()
    elif "--http" in sys.argv:
        _run_server_http()
    else:
        _run_server()


def _run_auth() -> None:
    from .auth import Auth

    # Both are optional — defaults to Office Desktop Apps client ID
    client_id = os.environ.get("ONEDRIVE_MCP_CLIENT_ID") or None
    tenant_id = os.environ.get("ONEDRIVE_MCP_TENANT_ID") or None

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


def _run_server_http() -> None:
    from .server import serve_http

    # Parse optional --port flag
    port = None
    for i, arg in enumerate(sys.argv):
        if arg == "--port" and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
    serve_http(port=port)


if __name__ == "__main__":
    main()
