"""Secure MSAL authentication for Microsoft Graph API.

Zero-config SSO: Uses the Microsoft Graph Command Line Tools client ID
by default so users can sign in with their corporate Microsoft account
without registering an Azure AD app.

Auth methods tried in order:
1. Cached token (silent refresh)
2. WAM broker on Windows (native SSO popup — uses existing Windows account)
3. Device code flow (user visits URL and enters a code)

Token storage: OS keyring primary (Windows Credential Vault, macOS
Keychain, Linux SecretService), file fallback with owner-only perms.
"""

import logging
import os
import stat
import subprocess
import sys
from pathlib import Path

import msal

logger = logging.getLogger("onedrive_mcp.auth")

# Microsoft Graph Command Line Tools — a Microsoft first-party app
# commonly used for CLI-based Graph API access.  Supports device code flow.
# Override with ONEDRIVE_MCP_CLIENT_ID env var if needed.
DEFAULT_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
DEFAULT_TENANT = "organizations"

KEYRING_SERVICE = "onedrive-mcp"
KEYRING_KEY = "msal_token_cache"
CONFIG_DIR = Path.home() / ".config" / "onedrive-mcp"
CACHE_FILE = CONFIG_DIR / "token_cache.json"
SCOPES = ["Files.ReadWrite", "User.Read"]


def _keyring_available() -> bool:
    """Check if OS keyring backend is usable."""
    try:
        import keyring
        import keyring.errors

        backend = keyring.get_keyring()
        name = type(backend).__name__
        if "Fail" in name or "null" in name.lower():
            return False
        return True
    except Exception:
        return False


def _broker_available() -> bool:
    """Check if WAM broker (pymsalruntime) is installed."""
    try:
        import pymsalruntime  # noqa: F401

        return True
    except ImportError:
        return False


class Auth:
    """MSAL public client auth with SSO broker + OS-keyring token caching."""

    def __init__(
        self,
        client_id: str | None = None,
        tenant_id: str | None = None,
    ):
        self.client_id = client_id or DEFAULT_CLIENT_ID
        self.tenant_id = tenant_id or DEFAULT_TENANT
        self._use_keyring = _keyring_available()
        self._use_broker = _broker_available() and sys.platform == "win32"
        self.cache = msal.SerializableTokenCache()
        self._load_cache()

        broker_kwargs = {}
        if self._use_broker:
            broker_kwargs["enable_broker_on_windows"] = True

        self.app = msal.PublicClientApplication(
            self.client_id,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}",
            token_cache=self.cache,
            **broker_kwargs,
        )

        if self._use_broker:
            logger.debug("WAM broker enabled for SSO")
        if self._use_keyring:
            logger.debug("Using OS keyring for token storage")
        else:
            logger.debug("Keyring unavailable; falling back to file cache")

    # ── Cache I/O ───────────────────────────────────────────────────────

    def _load_cache(self) -> None:
        data = self._read_from_keyring() or self._read_from_file()
        if data:
            self.cache.deserialize(data)

    def _save_cache(self) -> None:
        if not self.cache.has_state_changed:
            return
        serialized = self.cache.serialize()
        if self._use_keyring:
            self._write_to_keyring(serialized)
            # Remove file cache if migrating to keyring
            if CACHE_FILE.exists():
                CACHE_FILE.unlink()
                logger.info("Migrated token cache from file to OS keyring")
        else:
            self._write_to_file(serialized)

    # ── Keyring backend ─────────────────────────────────────────────────

    def _read_from_keyring(self) -> str | None:
        if not self._use_keyring:
            return None
        try:
            import keyring

            return keyring.get_password(KEYRING_SERVICE, KEYRING_KEY)
        except Exception:
            return None

    def _write_to_keyring(self, data: str) -> None:
        try:
            import keyring

            keyring.set_password(KEYRING_SERVICE, KEYRING_KEY, data)
        except Exception as exc:
            logger.warning("Keyring write failed, falling back to file: %s", exc)
            self._use_keyring = False
            self._write_to_file(data)

    # ── File backend (fallback) ─────────────────────────────────────────

    def _read_from_file(self) -> str | None:
        if CACHE_FILE.exists():
            return CACHE_FILE.read_text(encoding="utf-8")
        return None

    def _write_to_file(self, data: str) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(data, encoding="utf-8")
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

    # ── Token acquisition ───────────────────────────────────────────────

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
        """Authenticate the user. Tries broker SSO first, falls back to device code."""
        # Try WAM broker (Windows SSO) — pops a native dialog, uses existing account
        if self._use_broker:
            try:
                print("Signing in via Windows SSO...", file=sys.stderr)
                result = self.app.acquire_token_interactive(
                    scopes=SCOPES,
                    parent_window_handle=self.app.CONSOLE_WINDOW_HANDLE,
                    prompt="select_account",
                )
                if result and "access_token" in result:
                    self._save_cache()
                    return result["access_token"]
                # Broker didn't work — fall through to device code
                logger.debug(
                    "Broker auth returned no token: %s",
                    result.get("error_description", "unknown"),
                )
            except Exception as exc:
                logger.debug("Broker auth failed, falling back to device code: %s", exc)

        # Device code flow — works everywhere
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
