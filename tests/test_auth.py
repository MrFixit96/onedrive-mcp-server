"""Tests for onedrive_mcp.auth — token caching and keyring integration."""

from unittest.mock import MagicMock, patch

import pytest

from onedrive_mcp.auth import DEFAULT_CLIENT_ID, Auth, _broker_available, _keyring_available


class TestKeyringDetection:
    def test_keyring_available_returns_bool(self):
        result = _keyring_available()
        assert isinstance(result, bool)


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
