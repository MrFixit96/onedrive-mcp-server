"""Tests for onedrive_mcp.server — tool registration, audit logging, error handling."""

import json
import logging
from unittest.mock import patch

import pytest

from onedrive_mcp.graph import GraphClient
from onedrive_mcp.server import (
    _get_graph,
    _redact_path,
    _resolve_share_url,
    _validate_spo_url,
    audited_tool,
    mcp,
)


class TestToolRegistration:
    def test_seven_tools_registered(self):
        tools = mcp._tool_manager._tools
        assert len(tools) == 7

    def test_tool_names(self):
        names = set(mcp._tool_manager._tools.keys())
        expected = {
            "list_files",
            "get_file_metadata",
            "upload_file",
            "download_file",
            "create_sharing_link",
            "search_files",
            "generate_share_url",
        }
        assert names == expected


class TestRedactPath:
    def test_redacts_full_path(self):
        assert _redact_path(r"C:\Users\james\secrets\file.txt") == "file.txt"

    def test_handles_empty(self):
        assert _redact_path("") == ""

    def test_keeps_filename_only(self):
        assert _redact_path("report.docx") == "report.docx"


class TestGetGraph:
    def test_default_client_id_creates_graph(self):
        """With no env var, _get_graph uses the default client ID (no error)."""
        import onedrive_mcp.server as srv

        srv._graph = None
        srv._auth = None
        srv._transport_mode = "stdio"
        with (
            patch("onedrive_mcp.server.CLIENT_ID", None),
            patch("onedrive_mcp.server.TENANT_ID", None),
            patch("onedrive_mcp.auth.Auth") as mock_auth,
            patch("onedrive_mcp.server.GraphClient") as mock_gc,
        ):
            mock_auth_instance = mock_auth.return_value
            mock_auth_instance.get_token = lambda: "fake"
            mock_gc.return_value = "graph_instance"
            graph = _get_graph()
            assert graph == "graph_instance"
            mock_auth.assert_called_once_with(None, None)


class TestAuditedToolDecorator:
    async def test_logs_success(self, caplog):
        @audited_tool
        async def dummy_tool(file_path: str = "test") -> str:
            return '{"ok": true}'

        with caplog.at_level(logging.INFO, logger="onedrive_mcp.server"):
            result = await dummy_tool(file_path="test")

        assert result == '{"ok": true}'
        assert any("dummy_tool" in r.message and "ok" in r.message for r in caplog.records)

    async def test_catches_and_logs_errors(self, caplog):
        @audited_tool
        async def failing_tool() -> str:
            raise ValueError("something broke")

        with caplog.at_level(logging.ERROR, logger="onedrive_mcp.server"):
            result = await failing_tool()

        parsed = json.loads(result)
        assert "error" in parsed
        assert "something broke" in parsed["error"]
        assert any("failing_tool" in r.message and "error" in r.message for r in caplog.records)

    async def test_sanitizes_graph_errors(self):
        from onedrive_mcp.graph import GraphAPIError

        @audited_tool
        async def graph_tool() -> str:
            raise GraphAPIError(401, "Bearer eyJ0eXAi.token.here was invalid")

        result = await graph_tool()
        parsed = json.loads(result)
        assert "eyJ0eXAi" not in parsed["error"]
        assert "REDACTED" in parsed["error"]

    async def test_redacts_paths_in_log(self, caplog):
        @audited_tool
        async def path_tool(local_path: str = "") -> str:
            return "{}"

        with caplog.at_level(logging.INFO, logger="onedrive_mcp.server"):
            await path_tool(local_path=r"C:\Users\james\secret\doc.txt")

        # Full path should NOT appear in logs
        assert not any(r"C:\Users\james\secret" in r.message for r in caplog.records)
        # Only filename should appear
        assert any("doc.txt" in r.message for r in caplog.records)


class TestPassthroughTokenVerifier:
    async def test_decodes_valid_jwt(self):
        import time

        import jwt as pyjwt

        from onedrive_mcp.server import PassthroughTokenVerifier

        verifier = PassthroughTokenVerifier()
        payload = {
            "appid": "test-app-id",
            "scp": "Files.ReadWrite User.Read",
            "exp": int(time.time()) + 3600,
        }
        token = pyjwt.encode(payload, "secret", algorithm="HS256")
        result = await verifier.verify_token(token)
        assert result is not None
        assert result.client_id == "test-app-id"
        assert "Files.ReadWrite" in result.scopes
        assert result.token == token

    async def test_returns_none_for_garbage(self):
        from onedrive_mcp.server import PassthroughTokenVerifier

        verifier = PassthroughTokenVerifier()
        result = await verifier.verify_token("not-a-jwt")
        assert result is None


class TestHTTPMode:
    def test_http_token_provider_raises_without_context(self):
        from onedrive_mcp.server import _http_token_provider

        with pytest.raises(RuntimeError, match="No authenticated user"):
            _http_token_provider()

    def test_get_graph_http_mode(self):
        import onedrive_mcp.server as srv

        srv._graph = None
        srv._transport_mode = "http"
        try:
            graph = _get_graph()
            assert isinstance(graph, GraphClient)
            assert graph._token_provider is srv._http_token_provider
        finally:
            srv._transport_mode = "stdio"
            srv._graph = None


class TestResolveShareUrl:
    def test_file_not_found(self, tmp_path):
        result = _resolve_share_url(str(tmp_path / "nonexistent.txt"))
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_business_account_mapping(self, tmp_path):
        """Test URL construction with mocked OneDrive accounts."""
        # Create a fake synced file
        docs = tmp_path / "Documents" / "Reports"
        docs.mkdir(parents=True)
        test_file = docs / "quarterly.docx"
        test_file.write_text("test")

        fake_accounts = [
            {
                "local_folder": str(tmp_path),
                "spo_url": "https://contoso-my.sharepoint.com/personal/user_contoso_com",
                "email": "user@contoso.com",
                "type": "business",
            }
        ]

        with patch("onedrive_mcp.server._discover_onedrive_accounts", return_value=fake_accounts):
            result = _resolve_share_url(str(test_file))

        assert "url" in result
        assert "contoso-my.sharepoint.com" in result["url"]
        assert "Documents/Reports/quarterly.docx" in result["url"]
        assert result["account_type"] == "business"

    def test_personal_account_returns_error(self, tmp_path):
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        fake_accounts = [
            {
                "local_folder": str(tmp_path),
                "spo_url": "",
                "email": "user@hotmail.com",
                "type": "personal",
            }
        ]

        with patch("onedrive_mcp.server._discover_onedrive_accounts", return_value=fake_accounts):
            result = _resolve_share_url(str(test_file))

        assert "error" in result
        assert result["account_type"] == "personal"

    def test_file_outside_onedrive(self, tmp_path):
        test_file = tmp_path / "outside.txt"
        test_file.write_text("test")

        fake_accounts = [
            {
                "local_folder": str(tmp_path / "OneDrive"),
                "spo_url": "https://example.sharepoint.com",
                "email": "a@b.com",
                "type": "business",
            }
        ]

        with patch("onedrive_mcp.server._discover_onedrive_accounts", return_value=fake_accounts):
            result = _resolve_share_url(str(test_file))

        assert "error" in result
        assert "not inside" in result["error"].lower()

    def test_no_accounts_found(self, tmp_path):
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        with patch("onedrive_mcp.server._discover_onedrive_accounts", return_value=[]):
            result = _resolve_share_url(str(test_file))

        assert "error" in result
        assert "no onedrive accounts" in result["error"].lower()

    def test_url_encodes_spaces(self, tmp_path):
        docs = tmp_path / "My Documents"
        docs.mkdir(parents=True)
        test_file = docs / "my report.docx"
        test_file.write_text("test")

        fake_accounts = [
            {
                "local_folder": str(tmp_path),
                "spo_url": "https://contoso-my.sharepoint.com/personal/user",
                "email": "user@contoso.com",
                "type": "business",
            }
        ]

        with patch("onedrive_mcp.server._discover_onedrive_accounts", return_value=fake_accounts):
            result = _resolve_share_url(str(test_file))

        assert "url" in result
        assert "%20" in result["url"] or "my%20report" in result["url"].lower()
        # No raw spaces in URL
        assert " " not in result["url"]

    def test_env_var_fallback(self, tmp_path, monkeypatch):
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        monkeypatch.setenv(
            "ONEDRIVE_MCP_SHARE_MAP",
            f"{tmp_path}|https://example.sharepoint.com/personal/user",
        )

        # Patch registry discovery to return empty (simulate non-Windows)
        with patch("onedrive_mcp.server.sys") as mock_sys:
            mock_sys.platform = "linux"
            # Re-import to test env var fallback path
            from onedrive_mcp.server import _discover_onedrive_accounts

            accounts = _discover_onedrive_accounts()

        # On actual Windows it'll find registry accounts; this tests the env var parsing
        assert len(accounts) >= 1


class TestValidateSpoUrl:
    """Security tests for URL validation against injection attacks."""

    def test_rejects_javascript_protocol(self):
        assert _validate_spo_url("javascript:alert(1)") is None

    def test_rejects_file_protocol(self):
        assert _validate_spo_url("file:///etc/passwd") is None

    def test_rejects_data_protocol(self):
        assert _validate_spo_url("data:text/html,<script>alert(1)</script>") is None

    def test_rejects_http_non_tls(self):
        assert _validate_spo_url("http://contoso.sharepoint.com/personal/u") is None

    def test_rejects_non_sharepoint_domain(self):
        assert _validate_spo_url("https://evil.com/personal/user") is None

    def test_strips_crlf_injection(self):
        result = _validate_spo_url(
            "https://contoso-my.sharepoint.com/personal/u\r\nX-Injected: true"
        )
        assert result is not None
        assert "\r" not in result
        assert "\n" not in result

    def test_accepts_valid_sharepoint_url(self):
        result = _validate_spo_url(
            "https://ibm-my.sharepoint.com/personal/james_anderton_ibm_com"
        )
        assert result == "https://ibm-my.sharepoint.com/personal/james_anderton_ibm_com"

    def test_strips_trailing_slash(self):
        result = _validate_spo_url(
            "https://contoso.sharepoint.com/personal/user/"
        )
        assert result is not None
        assert not result.endswith("/")

    def test_rejects_empty_string(self):
        assert _validate_spo_url("") is None

    def test_rejects_garbage(self):
        assert _validate_spo_url("not a url at all") is None


class TestShareUrlSecurityEdgeCases:
    """End-to-end security tests for generate_share_url pipeline."""

    def test_malicious_registry_url_rejected(self, tmp_path):
        test_file = tmp_path / "file.txt"
        test_file.write_text("test")

        malicious_accounts = [
            {
                "local_folder": str(tmp_path),
                "spo_url": "javascript:alert('xss')",
                "email": "user@contoso.com",
                "type": "business",
            }
        ]

        with patch(
            "onedrive_mcp.server._discover_onedrive_accounts",
            return_value=malicious_accounts,
        ):
            result = _resolve_share_url(str(test_file))

        # Should NOT produce a URL with javascript: scheme
        assert "url" not in result or "javascript:" not in result.get("url", "")

    def test_special_chars_in_filename_encoded(self, tmp_path):
        docs = tmp_path / "docs"
        docs.mkdir()
        test_file = docs / "report#1;drop=table.docx"
        test_file.write_text("test")

        fake_accounts = [
            {
                "local_folder": str(tmp_path),
                "spo_url": "https://c-my.sharepoint.com/personal/u",
                "email": "u@c.com",
                "type": "business",
            }
        ]

        with patch(
            "onedrive_mcp.server._discover_onedrive_accounts",
            return_value=fake_accounts,
        ):
            result = _resolve_share_url(str(test_file))

        assert "url" in result
        url = result["url"]
        # Hash and semicolons must be encoded
        assert "#" not in url.split("Documents/")[1]
        assert ";" not in url.split("Documents/")[1]

    def test_symlink_traversal_blocked(self, tmp_path):
        """Symlinks resolving outside OneDrive folder should be rejected."""
        od_folder = tmp_path / "OneDrive"
        od_folder.mkdir()
        secret_dir = tmp_path / "secrets"
        secret_dir.mkdir()
        secret_file = secret_dir / "passwords.txt"
        secret_file.write_text("hunter2")

        # Create symlink inside OneDrive pointing outside
        link = od_folder / "sneaky_link.txt"
        try:
            link.symlink_to(secret_file)
        except OSError:
            pytest.skip("Cannot create symlinks on this system")

        fake_accounts = [
            {
                "local_folder": str(od_folder),
                "spo_url": "https://c-my.sharepoint.com/personal/u",
                "email": "u@c.com",
                "type": "business",
            }
        ]

        with patch(
            "onedrive_mcp.server._discover_onedrive_accounts",
            return_value=fake_accounts,
        ):
            result = _resolve_share_url(str(link))

        # Path.resolve() follows symlink → secret_dir which is outside od_folder
        assert "error" in result
        assert "not inside" in result["error"].lower()
