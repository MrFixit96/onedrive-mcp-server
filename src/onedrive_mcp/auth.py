"""Secure MSAL authentication for Microsoft Graph API.

Uses device code flow for interactive auth and caches tokens with
restrictive file permissions to prevent credential leakage.
"""

import os
import stat
import subprocess
import sys
from pathlib import Path

import msal

CONFIG_DIR = Path.home() / ".config" / "onedrive-mcp"
CACHE_FILE = CONFIG_DIR / "token_cache.json"
SCOPES = ["Files.ReadWrite", "User.Read"]


class Auth:
    """MSAL public client auth with secure token caching."""

    def __init__(self, client_id: str, tenant_id: str = "common"):
        self.client_id = client_id
        self.tenant_id = tenant_id
        self.cache = msal.SerializableTokenCache()
        self._load_cache()
        self.app = msal.PublicClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            token_cache=self.cache,
        )

    def _load_cache(self) -> None:
        if CACHE_FILE.exists():
            self.cache.deserialize(CACHE_FILE.read_text(encoding="utf-8"))

    def _save_cache(self) -> None:
        if not self.cache.has_state_changed:
            return
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(self.cache.serialize(), encoding="utf-8")
        self._secure_cache_file()

    def _secure_cache_file(self) -> None:
        """Restrict token cache to owner-only access."""
        if os.name != "nt":
            os.chmod(CACHE_FILE, stat.S_IRUSR | stat.S_IWUSR)
        else:
            username = os.environ.get("USERNAME", "")
            if username:
                subprocess.run(
                    [
                        "icacls", str(CACHE_FILE),
                        "/inheritance:r",
                        "/grant:r", f"{username}:(R,W)",
                    ],
                    capture_output=True,
                    check=False,
                )

    def get_token(self) -> str:
        """Get a valid access token, refreshing silently if cached."""
        accounts = self.app.get_accounts()
        if accounts:
            result = self.app.acquire_token_silent(SCOPES, account=accounts[0])
            if result and "access_token" in result:
                self._save_cache()
                return result["access_token"]
        raise RuntimeError(
            "No cached credentials. Run `onedrive-mcp auth` to sign in."
        )

    def authenticate_interactive(self) -> str:
        """Run device code flow. Call from CLI only, not from MCP server."""
        flow = self.app.initiate_device_flow(scopes=SCOPES)
        if "user_code" not in flow:
            raise RuntimeError(
                f"Device flow failed: {flow.get('error_description', 'Unknown')}"
            )
        print(
            f"\nTo sign in, visit: {flow['verification_uri']}",
            file=sys.stderr,
        )
        print(f"Enter code: {flow['user_code']}\n", file=sys.stderr)

        result = self.app.acquire_token_by_device_flow(flow)
        if "access_token" not in result:
            raise RuntimeError(
                f"Auth failed: {result.get('error_description', 'Unknown')}"
            )
        self._save_cache()
        return result["access_token"]
