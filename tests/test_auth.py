"""Tests for onedrive_mcp.auth — token caching and keyring integration."""

from unittest.mock import MagicMock, patch

import pytest

from onedrive_mcp.auth import DEFAULT_CLIENT_ID, Auth, _broker_available, _keyring_available


class TestKeyringDetection:
    def test_keyring_available_returns_bool(self):
        result = _keyring_available()
        assert isinstance(result, bool)

    def test_fail_backend_detected_via_module_name(self):
        """keyring.backends.fail.Keyring has __name__='Keyring' (no 'Fail').
        Checking only __name__ incorrectly returns True on headless Linux;
        the fix checks the fully-qualified module+class name instead."""

        class _FakeFailBackend:
            pass

        _FakeFailBackend.__module__ = "keyring.backends.fail"

        with patch("keyring.get_keyring", return_value=_FakeFailBackend()):
            assert _keyring_available() is False

    def test_null_backend_detected_via_module_name(self):
        class _FakeNullBackend:
            pass

        _FakeNullBackend.__module__ = "keyring.backends.null"

        with patch("keyring.get_keyring", return_value=_FakeNullBackend()):
            assert _keyring_available() is False

    def test_working_backend_is_available(self):
        class _FakeSecretService:
            pass

        _FakeSecretService.__module__ = "keyring.backends.SecretService"

        with patch("keyring.get_keyring", return_value=_FakeSecretService()):
            assert _keyring_available() is True


class TestBrokerDetection:
    def test_broker_available_returns_bool(self):
        result = _broker_available()
        assert isinstance(result, bool)


class TestAuthInit:
    @patch("onedrive_mcp.auth.msal.PublicClientApplication")
    @patch("onedrive_mcp.auth._broker_available", return_value=False)
    @patch("onedrive_mcp.auth._keyring_available", return_value=False)
    @patch("onedrive_mcp.auth.CACHE_FILE")
    def test_init_creates_app(self, mock_cache, mock_kr, mock_br, mock_msal_app):
        mock_cache.exists.return_value = False
        auth = Auth("test-client-id", "test-tenant")
        assert auth.client_id == "test-client-id"
        assert auth.tenant_id == "test-tenant"
        mock_msal_app.assert_called_once()

    @patch("onedrive_mcp.auth._broker_available", return_value=False)
    @patch("onedrive_mcp.auth._keyring_available", return_value=False)
    @patch("onedrive_mcp.auth.CACHE_FILE")
    def test_default_tenant_is_organizations(self, mock_cache, mock_kr, mock_br):
        mock_cache.exists.return_value = False
        auth = Auth("test-client-id")
        assert auth.tenant_id == "organizations"

    @patch("onedrive_mcp.auth._broker_available", return_value=False)
    @patch("onedrive_mcp.auth._keyring_available", return_value=False)
    @patch("onedrive_mcp.auth.CACHE_FILE")
    def test_default_client_id_when_none(self, mock_cache, mock_kr, mock_br):
        mock_cache.exists.return_value = False
        auth = Auth()
        assert auth.client_id == DEFAULT_CLIENT_ID


class TestGetToken:
    @patch("onedrive_mcp.auth._broker_available", return_value=False)
    @patch("onedrive_mcp.auth._keyring_available", return_value=False)
    @patch("onedrive_mcp.auth.CACHE_FILE")
    def test_no_accounts_raises(self, mock_cache, mock_kr, mock_br):
        mock_cache.exists.return_value = False
        auth = Auth("test-client-id")
        auth.app = MagicMock()
        auth.app.get_accounts.return_value = []
        with pytest.raises(RuntimeError, match="Run `onedrive-mcp auth`"):
            auth.get_token()

    @patch("onedrive_mcp.auth._broker_available", return_value=False)
    @patch("onedrive_mcp.auth._keyring_available", return_value=False)
    @patch("onedrive_mcp.auth.CACHE_FILE")
    def test_silent_success_returns_token(self, mock_cache, mock_kr, mock_br):
        mock_cache.exists.return_value = False
        auth = Auth("test-client-id")
        auth.app = MagicMock()
        auth.app.get_accounts.return_value = [{"username": "user@test.com"}]
        auth.app.acquire_token_silent.return_value = {
            "access_token": "test-token-123"
        }
        token = auth.get_token()
        assert token == "test-token-123"

    @patch("onedrive_mcp.auth._broker_available", return_value=False)
    @patch("onedrive_mcp.auth._keyring_available", return_value=False)
    @patch("onedrive_mcp.auth.CACHE_FILE")
    def test_silent_failure_raises(self, mock_cache, mock_kr, mock_br):
        mock_cache.exists.return_value = False
        auth = Auth("test-client-id")
        auth.app = MagicMock()
        auth.app.get_accounts.return_value = [{"username": "user@test.com"}]
        auth.app.acquire_token_silent.return_value = None
        with pytest.raises(RuntimeError):
            auth.get_token()


class TestSaveCacheKeyringFallback:
    @patch("onedrive_mcp.auth._broker_available", return_value=False)
    @patch("onedrive_mcp.auth._keyring_available", return_value=True)
    @patch("onedrive_mcp.auth.msal.PublicClientApplication")
    @patch("onedrive_mcp.auth.CACHE_FILE")
    @patch("onedrive_mcp.auth.CONFIG_DIR")
    def test_file_not_deleted_when_keyring_write_falls_back(
        self, mock_config_dir, mock_cache_file, mock_msal, mock_kr, mock_br
    ):
        """When keyring write fails and falls back to file, _save_cache must
        not delete the file it just wrote. The old code checked _use_keyring
        before _write_to_keyring could set it to False on failure."""
        mock_cache_file.exists.return_value = False  # no pre-existing file at init
        auth = Auth("test-client-id")
        auth.cache = MagicMock()
        auth.cache.has_state_changed = True
        auth.cache.serialize.return_value = '{"AccessToken": {}}'
        mock_cache_file.exists.return_value = True  # file exists after fallback write

        with patch("keyring.set_password", side_effect=Exception("no backend")):
            auth._save_cache()

        mock_cache_file.unlink.assert_not_called()

    @patch("onedrive_mcp.auth._broker_available", return_value=False)
    @patch("onedrive_mcp.auth._keyring_available", return_value=True)
    @patch("onedrive_mcp.auth.msal.PublicClientApplication")
    @patch("onedrive_mcp.auth.CACHE_FILE")
    def test_file_deleted_when_keyring_write_succeeds(
        self, mock_cache_file, mock_msal, mock_kr, mock_br
    ):
        """When keyring write succeeds, any leftover file cache should be removed."""
        mock_cache_file.exists.return_value = False  # no pre-existing file at init
        auth = Auth("test-client-id")
        auth.cache = MagicMock()
        auth.cache.has_state_changed = True
        auth.cache.serialize.return_value = '{"AccessToken": {}}'
        mock_cache_file.exists.return_value = True  # stale file exists

        with patch("keyring.set_password"):
            auth._save_cache()

        mock_cache_file.unlink.assert_called_once()


class TestCacheStorage:
    @patch("onedrive_mcp.auth._broker_available", return_value=False)
    @patch("onedrive_mcp.auth._keyring_available", return_value=True)
    @patch("onedrive_mcp.auth.CACHE_FILE")
    def test_prefers_keyring_when_available(self, mock_cache, mock_kr, mock_br):
        mock_cache.exists.return_value = False
        auth = Auth("test-client-id")
        assert auth._use_keyring is True

    @patch("onedrive_mcp.auth._broker_available", return_value=False)
    @patch("onedrive_mcp.auth._keyring_available", return_value=False)
    @patch("onedrive_mcp.auth.CACHE_FILE")
    def test_falls_back_to_file(self, mock_cache, mock_kr, mock_br):
        mock_cache.exists.return_value = False
        auth = Auth("test-client-id")
        assert auth._use_keyring is False
