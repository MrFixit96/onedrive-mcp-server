"""Tests for onedrive_mcp.graph — API client with mocked HTTP."""

import httpx
import pytest
import respx

from onedrive_mcp.graph import (
    GRAPH_BASE,
    GraphAPIError,
    GraphClient,
    _sanitize_error,
)

# ── Error sanitization ─────────────────────────────────────────────────


class TestSanitizeError:
    def test_strips_bearer_tokens(self):
        msg = "Unauthorized: Bearer eyJ0eXAiOiJKV1Q.abc123.xyz"
        result = _sanitize_error(msg)
        assert "eyJ0eXAi" not in result
        assert "[REDACTED]" in result

    def test_strips_guids(self):
        msg = "Correlation ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        result = _sanitize_error(msg)
        assert "a1b2c3d4" not in result

    def test_strips_upload_urls(self):
        msg = "Failed at https://storage.upload.microsoft.com/some/path?token=abc"
        result = _sanitize_error(msg)
        assert "upload.microsoft.com" not in result

    def test_preserves_safe_text(self):
        msg = "Item not found"
        assert _sanitize_error(msg) == "Item not found"


class TestGraphAPIError:
    def test_sanitizes_message(self):
        err = GraphAPIError(401, "Bearer eyJ0eXAi.invalid_token")
        assert "eyJ0eXAi" not in str(err)
        assert "401" in str(err)


# ── Path normalization ──────────────────────────────────────────────────


class TestNormalizePath:
    def test_root(self):
        assert GraphClient._normalize_path("/") == ""

    def test_strips_slashes(self):
        assert GraphClient._normalize_path("/Documents/") == "Documents"

    def test_nested(self):
        assert GraphClient._normalize_path("a/b/c") == "a/b/c"

    def test_whitespace(self):
        assert GraphClient._normalize_path("  /foo/  ") == "foo"

    def test_empty(self):
        assert GraphClient._normalize_path("") == ""


# ── API methods (mocked HTTP) ──────────────────────────────────────────


@pytest.fixture
def mock_auth():
    return lambda: "fake-token"


@pytest.fixture
def graph(mock_auth):
    return GraphClient(token_provider=mock_auth)


class TestListFiles:
    @respx.mock
    async def test_list_root(self, graph):
        respx.get(f"{GRAPH_BASE}/me/drive/root/children").mock(
            return_value=httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "name": "report.docx",
                            "size": 1024,
                            "lastModifiedDateTime": "2025-01-01T00:00:00Z",
                            "webUrl": "https://example.com/report.docx",
                        },
                        {
                            "name": "Photos",
                            "size": 0,
                            "folder": {"childCount": 5},
                            "lastModifiedDateTime": "2025-01-01T00:00:00Z",
                            "webUrl": "https://example.com/Photos",
                        },
                    ]
                },
            )
        )
        items = await graph.list_files("/")
        assert len(items) == 2
        assert items[0]["name"] == "report.docx"
        assert items[0]["type"] == "file"
        assert items[1]["type"] == "folder"
        assert items[1]["childCount"] == 5

    @respx.mock
    async def test_list_subfolder(self, graph):
        respx.get(f"{GRAPH_BASE}/me/drive/root:/Documents:/children").mock(
            return_value=httpx.Response(200, json={"value": []})
        )
        items = await graph.list_files("Documents")
        assert items == []


class TestGetFileMetadata:
    @respx.mock
    async def test_returns_metadata(self, graph):
        respx.get(f"{GRAPH_BASE}/me/drive/root:/test.txt:").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "test.txt",
                    "size": 42,
                    "file": {"mimeType": "text/plain"},
                    "lastModifiedDateTime": "2025-06-01T00:00:00Z",
                    "createdBy": {"user": {"displayName": "Alice"}},
                    "webUrl": "https://example.com/test.txt",
                    "id": "item-123",
                },
            )
        )
        meta = await graph.get_file_metadata("test.txt")
        assert meta["name"] == "test.txt"
        assert meta["size"] == 42
        assert meta["mimeType"] == "text/plain"
        assert meta["createdBy"] == "Alice"

    async def test_empty_path_raises(self, graph):
        with pytest.raises(ValueError, match="cannot be empty"):
            await graph.get_file_metadata("")


class TestUploadFile:
    @respx.mock
    async def test_simple_upload(self, graph, tmp_path):
        test_file = tmp_path / "small.txt"
        test_file.write_text("hello world")

        respx.put(f"{GRAPH_BASE}/me/drive/root:/docs/small.txt:/content").mock(
            return_value=httpx.Response(
                201,
                json={"name": "small.txt", "webUrl": "https://example.com/small.txt", "size": 11},
            )
        )
        result = await graph.upload_file(test_file, "docs/small.txt")
        assert result["name"] == "small.txt"

    async def test_missing_file_raises(self, graph, tmp_path):
        with pytest.raises(FileNotFoundError):
            await graph.upload_file(tmp_path / "nope.txt", "dest.txt")

    async def test_empty_remote_raises(self, graph, tmp_path):
        f = tmp_path / "x.txt"
        f.write_text("data")
        with pytest.raises(ValueError, match="cannot be empty"):
            await graph.upload_file(f, "")


class TestCreateSharingLink:
    @respx.mock
    async def test_creates_view_link(self, graph):
        respx.post(f"{GRAPH_BASE}/me/drive/root:/doc.pdf:/createLink").mock(
            return_value=httpx.Response(
                200,
                json={
                    "link": {
                        "webUrl": "https://share.example.com/abc",
                        "type": "view",
                        "scope": "organization",
                    }
                },
            )
        )
        result = await graph.create_sharing_link("doc.pdf")
        assert result["webUrl"] == "https://share.example.com/abc"
        assert result["type"] == "view"

    async def test_invalid_type_raises(self, graph):
        with pytest.raises(ValueError, match="link_type"):
            await graph.create_sharing_link("x.pdf", link_type="delete")

    async def test_invalid_scope_raises(self, graph):
        with pytest.raises(ValueError, match="scope"):
            await graph.create_sharing_link("x.pdf", scope="everyone")


class TestDownloadFile:
    @respx.mock
    async def test_download_validates_path(self, graph, tmp_path):
        # Mock metadata call
        respx.get(f"{GRAPH_BASE}/me/drive/root:/..%2F..%2Fetc%2Fpasswd:").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "../../etc/passwd",
                    "size": 100,
                    "file": {"mimeType": "text/plain"},
                    "lastModifiedDateTime": "2025-01-01T00:00:00Z",
                    "createdBy": {"user": {"displayName": "Attacker"}},
                    "webUrl": "",
                    "id": "x",
                },
            )
        )
        with pytest.raises(ValueError, match="Path traversal"):
            await graph.download_file("../../etc/passwd", tmp_path)


class TestSearchFiles:
    @respx.mock
    async def test_returns_results(self, graph):
        respx.get(f"{GRAPH_BASE}/me/drive/root/search(q='report')").mock(
            return_value=httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "name": "Q4-report.xlsx",
                            "size": 5000,
                            "lastModifiedDateTime": "2025-03-01T00:00:00Z",
                            "webUrl": "https://example.com/Q4-report.xlsx",
                            "parentReference": {"path": "/drive/root:/Documents"},
                        }
                    ]
                },
            )
        )
        results = await graph.search_files("report")
        assert len(results) == 1
        assert results[0]["name"] == "Q4-report.xlsx"
        assert results[0]["path"] == "/Documents/Q4-report.xlsx"


class TestErrorHandling:
    @respx.mock
    async def test_400_raises_graph_error(self, graph):
        respx.get(f"{GRAPH_BASE}/me/drive/root/children").mock(
            return_value=httpx.Response(
                404,
                json={"error": {"message": "Item not found"}},
            )
        )
        with pytest.raises(GraphAPIError) as exc_info:
            await graph.list_files("/")
        assert exc_info.value.status == 404
        assert "Item not found" in str(exc_info.value)
