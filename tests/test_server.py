"""Tests for onedrive_mcp.server — tool registration, audit logging, error handling."""

import json
import logging
from unittest.mock import patch

import pytest

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
    def test_missing_client_id_raises(self):
        with patch("onedrive_mcp.server.CLIENT_ID", ""):
            # Reset cached graph
            import onedrive_mcp.server as srv
            srv._graph = None
            srv._auth = None
            with pytest.raises(RuntimeError, match="ONEDRIVE_MCP_CLIENT_ID"):
                _get_graph()


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
