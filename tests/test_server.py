"""Tests for onedrive_mcp.server — tool registration, audit logging, error handling."""

import json
import logging
from unittest.mock import patch

import pytest

from onedrive_mcp.graph import GraphClient
from onedrive_mcp.server import (
    _get_graph,
    _redact_path,
    audited_tool,
    mcp,
)


class TestToolRegistration:
    def test_six_tools_registered(self):
        tools = mcp._tool_manager._tools
        assert len(tools) == 6

    def test_tool_names(self):
        names = set(mcp._tool_manager._tools.keys())
        expected = {
            "list_files",
            "get_file_metadata",
            "upload_file",
            "download_file",
            "create_sharing_link",
            "search_files",
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
