"""Tests for GitHub release caching."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from cyberfw.exceptions import CyberfwError, DownloadError
from cyberfw.manager.github_client import GitHubClient, GitHubRelease, ReleaseAsset


@pytest.fixture
def no_retry_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skip tenacity's backoff sleeps on every retried GitHubClient method."""
    for attr in vars(GitHubClient).values():
        retrying = getattr(attr, "retry", None)
        if retrying is not None:
            monkeypatch.setattr(retrying, "sleep", lambda *_: None)


def _json_response(url: str, status: int, payload: object) -> httpx.Response:
    return httpx.Response(status, json=payload, request=httpx.Request("GET", url))


def test_release_cache_preserves_version(tmp_path: Path) -> None:
    client = GitHubClient(cache_dir=tmp_path)
    release = GitHubRelease(
        tag="v2.6.6",
        assets=[ReleaseAsset("tool.zip", "https://example.test/tool.zip", 12)],
        checksums_url=None,
    )
    try:
        client._cache_save("org", "tool", release)
        cached = client._cache_may_load("org", "tool")
    finally:
        client.close()

    assert cached is not None
    assert cached.version == "2.6.6"


def test_cache_null_checksum_is_not_string_none(tmp_path: Path) -> None:
    client = GitHubClient(cache_dir=tmp_path)
    try:
        cached = client._from_cache_dict(
            {
                "tag": "v1.0.0",
                "checksums_url": None,
                "assets": [{"name": "tool.zip", "url": "https://example.test/tool.zip", "size": 1}],
            }
        )
    finally:
        client.close()

    assert cached.checksums_url is None


def test_latest_uses_github_token_for_authorization(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    client = GitHubClient(token="secret-token", cache_dir=tmp_path)
    captured: dict[str, str] = {}

    def fake_get(url: str, *, headers: dict[str, str]) -> httpx.Response:
        captured.update(headers)
        return httpx.Response(
            200,
            json={"tag_name": "v1.0.0", "assets": []},
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(client._client, "get", fake_get)
    try:
        client.latest("org", "tool")
    finally:
        client.close()

    assert captured["Authorization"] == "Bearer secret-token"


def test_client_timeout_is_configurable() -> None:
    client = GitHubClient(timeout=7.5)
    try:
        assert client._client.timeout == httpx.Timeout(7.5)
    finally:
        client.close()


def test_download_retries_transient_transport_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_retry_sleep: None
) -> None:
    client = GitHubClient()
    url = "https://example.test/tool.zip"
    attempts: list[int] = []

    class _Stream:
        def __enter__(self) -> httpx.Response:
            return httpx.Response(200, content=b"payload", request=httpx.Request("GET", url))

        def __exit__(self, *exc: object) -> None:
            return None

    def fake_stream(method: str, target: str) -> _Stream:
        attempts.append(1)
        if len(attempts) < 3:
            raise httpx.ReadTimeout("The read operation timed out", request=httpx.Request(method, target))
        return _Stream()

    monkeypatch.setattr(client._client, "stream", fake_stream)
    dst = tmp_path / "tool.zip"
    try:
        client.download(url, dst, expected_size=7)
    finally:
        client.close()

    assert len(attempts) == 3
    assert dst.read_bytes() == b"payload"


def test_download_gives_up_after_retries_with_download_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_retry_sleep: None
) -> None:
    client = GitHubClient()
    url = "https://example.test/tool.zip"
    attempts: list[int] = []

    def fake_stream(method: str, target: str) -> None:
        attempts.append(1)
        raise httpx.ConnectTimeout("_ssl.c:1064: The handshake operation timed out", request=httpx.Request(method, target))

    monkeypatch.setattr(client._client, "stream", fake_stream)
    try:
        with pytest.raises(DownloadError, match="Failed to download .* after 4 attempts"):
            client.download(url, tmp_path / "tool.zip")
    finally:
        client.close()

    assert len(attempts) == 4


def test_download_does_not_retry_http_status_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_retry_sleep: None
) -> None:
    client = GitHubClient()
    url = "https://example.test/missing.zip"
    attempts: list[int] = []

    class _Stream:
        def __enter__(self) -> httpx.Response:
            return httpx.Response(404, request=httpx.Request("GET", url))

        def __exit__(self, *exc: object) -> None:
            return None

    def fake_stream(method: str, target: str) -> _Stream:
        attempts.append(1)
        return _Stream()

    monkeypatch.setattr(client._client, "stream", fake_stream)
    try:
        with pytest.raises(DownloadError):
            client.download(url, tmp_path / "missing.zip")
    finally:
        client.close()

    assert len(attempts) == 1


def test_manager_client_uses_request_timeout(tmp_path: Path) -> None:
    from cyberfw.config import Settings
    from cyberfw.manager import ToolManager
    from cyberfw.manager.registry import ToolRegistry

    settings = Settings(root_dir=tmp_path, request_timeout=42.0, cache_dir=tmp_path / "cache")
    manager = ToolManager(settings, ToolRegistry({}))
    try:
        assert manager.client._client.timeout == httpx.Timeout(42.0)
    finally:
        manager.close()


def test_latest_gives_up_after_retries_with_download_error(
    monkeypatch: pytest.MonkeyPatch, no_retry_sleep: None
) -> None:
    client = GitHubClient()
    calls: list[int] = []

    def fake_get(url: str, *, headers: dict[str, str]) -> httpx.Response:
        calls.append(1)
        raise httpx.ConnectTimeout("timed out", request=httpx.Request("GET", url))

    monkeypatch.setattr(client._client, "get", fake_get)
    try:
        with pytest.raises(DownloadError, match="after 4 attempts") as info:
            client.latest("org", "tool")
    finally:
        client.close()

    assert isinstance(info.value, CyberfwError)
    assert len(calls) == 4


def test_latest_does_not_retry_not_found(monkeypatch: pytest.MonkeyPatch, no_retry_sleep: None) -> None:
    client = GitHubClient()
    calls: list[int] = []

    def fake_get(url: str, *, headers: dict[str, str]) -> httpx.Response:
        calls.append(1)
        return _json_response(url, 404, {"message": "Not Found"})

    monkeypatch.setattr(client._client, "get", fake_get)
    try:
        with pytest.raises(DownloadError, match="Repository not found: org/tool"):
            client.latest("org", "tool")
    finally:
        client.close()

    assert len(calls) == 1


def test_latest_does_not_retry_rate_limit(monkeypatch: pytest.MonkeyPatch, no_retry_sleep: None) -> None:
    client = GitHubClient()
    calls: list[int] = []

    def fake_get(url: str, *, headers: dict[str, str]) -> httpx.Response:
        calls.append(1)
        return _json_response(url, 403, {"message": "API rate limit exceeded"})

    monkeypatch.setattr(client._client, "get", fake_get)
    try:
        with pytest.raises(DownloadError, match=r"rate limit \(403\)"):
            client.latest("org", "tool")
    finally:
        client.close()

    assert len(calls) == 1


def test_latest_retries_server_errors(monkeypatch: pytest.MonkeyPatch, no_retry_sleep: None) -> None:
    client = GitHubClient()
    calls: list[int] = []

    def fake_get(url: str, *, headers: dict[str, str]) -> httpx.Response:
        calls.append(1)
        if len(calls) < 3:
            return _json_response(url, 503, {"message": "Service Unavailable"})
        return _json_response(url, 200, {"tag_name": "v1.2.3", "assets": []})

    monkeypatch.setattr(client._client, "get", fake_get)
    try:
        release = client.latest("org", "tool")
    finally:
        client.close()

    assert release.version == "1.2.3"
    assert len(calls) == 3


def test_download_retries_server_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_retry_sleep: None
) -> None:
    client = GitHubClient()
    url = "https://example.test/tool.zip"
    attempts: list[int] = []

    class _Stream:
        def __enter__(self) -> httpx.Response:
            status = 503 if len(attempts) < 3 else 200
            return httpx.Response(status, content=b"payload", request=httpx.Request("GET", url))

        def __exit__(self, *exc: object) -> None:
            return None

    def fake_stream(method: str, target: str) -> _Stream:
        attempts.append(1)
        return _Stream()

    monkeypatch.setattr(client._client, "stream", fake_stream)
    dst = tmp_path / "tool.zip"
    try:
        client.download(url, dst, expected_size=7)
    finally:
        client.close()

    assert len(attempts) == 3
    assert dst.read_bytes() == b"payload"


def test_download_removes_partial_file_on_final_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_retry_sleep: None
) -> None:
    client = GitHubClient()
    url = "https://example.test/tool.zip"

    class _Truncated(httpx.SyncByteStream):
        def __iter__(self):  # type: ignore[no-untyped-def]
            yield b"par"
            raise httpx.ReadTimeout("connection dropped", request=httpx.Request("GET", url))

    class _Stream:
        def __enter__(self) -> httpx.Response:
            return httpx.Response(200, stream=_Truncated(), request=httpx.Request("GET", url))

        def __exit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr(client._client, "stream", lambda method, target: _Stream())
    dst = tmp_path / "tool.zip"
    try:
        with pytest.raises(DownloadError, match="after 4 attempts"):
            client.download(url, dst)
    finally:
        client.close()

    assert list(tmp_path.iterdir()) == []


def test_download_wraps_filesystem_errors_in_download_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_retry_sleep: None
) -> None:
    client = GitHubClient()
    url = "https://example.test/tool.zip"

    class _Stream:
        def __enter__(self) -> httpx.Response:
            return httpx.Response(200, content=b"payload", request=httpx.Request("GET", url))

        def __exit__(self, *exc: object) -> None:
            return None

    def locked_move(src: str, dst: str) -> None:
        raise PermissionError(f"[WinError 32] The process cannot access the file: {src!r}")

    monkeypatch.setattr(client._client, "stream", lambda method, target: _Stream())
    monkeypatch.setattr("cyberfw.manager.github_client.shutil.move", locked_move)
    dst = tmp_path / "tool.zip"
    try:
        with pytest.raises(DownloadError, match="WinError 32"):
            client.download(url, dst)
    finally:
        client.close()

    assert list(tmp_path.iterdir()) == []


def test_fetch_text_gives_up_after_retries_with_download_error(
    monkeypatch: pytest.MonkeyPatch, no_retry_sleep: None
) -> None:
    client = GitHubClient()
    url = "https://example.test/checksums.txt"
    calls: list[int] = []

    def fake_get(target: str, **kwargs: object) -> httpx.Response:
        calls.append(1)
        raise httpx.ReadTimeout("timed out", request=httpx.Request("GET", target))

    monkeypatch.setattr(client._client, "get", fake_get)
    try:
        with pytest.raises(DownloadError, match="Failed to fetch .* after 4 attempts"):
            client.fetch_text(url)
    finally:
        client.close()

    assert len(calls) == 4


def test_fetch_text_retries_server_errors(monkeypatch: pytest.MonkeyPatch, no_retry_sleep: None) -> None:
    client = GitHubClient()
    url = "https://example.test/checksums.txt"
    calls: list[int] = []

    def fake_get(target: str, **kwargs: object) -> httpx.Response:
        calls.append(1)
        status = 502 if len(calls) == 1 else 200
        return httpx.Response(status, text="abc  tool.zip", request=httpx.Request("GET", target))

    monkeypatch.setattr(client._client, "get", fake_get)
    try:
        body = client.fetch_text(url)
    finally:
        client.close()

    assert body == "abc  tool.zip"
    assert len(calls) == 2


class TestReleaseByTag:
    def test_pinned_tag_uses_the_tags_endpoint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = GitHubClient()
        urls: list[str] = []

        def fake_get(url: str, *, headers: dict[str, str]) -> httpx.Response:
            urls.append(url)
            return _json_response(url, 200, {"tag_name": "v2.6.6", "assets": []})

        monkeypatch.setattr(client._client, "get", fake_get)
        try:
            release = client.release("org", "tool", "v2.6.6")
        finally:
            client.close()

        assert urls == ["https://api.github.com/repos/org/tool/releases/tags/v2.6.6"]
        assert release.version == "2.6.6"

    def test_latest_keyword_uses_the_latest_endpoint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = GitHubClient()
        urls: list[str] = []

        def fake_get(url: str, *, headers: dict[str, str]) -> httpx.Response:
            urls.append(url)
            return _json_response(url, 200, {"tag_name": "v3.0.0", "assets": []})

        monkeypatch.setattr(client._client, "get", fake_get)
        try:
            client.release("org", "tool", "latest")
        finally:
            client.close()

        assert urls == ["https://api.github.com/repos/org/tool/releases/latest"]

    def test_unknown_tag_names_the_tag(self, monkeypatch: pytest.MonkeyPatch, no_retry_sleep: None) -> None:
        client = GitHubClient()
        monkeypatch.setattr(client._client, "get", lambda url, *, headers: _json_response(url, 404, {}))
        try:
            with pytest.raises(DownloadError, match="v9.9.9"):
                client.release("org", "tool", "v9.9.9")
        finally:
            client.close()

    def test_pinned_and_latest_are_cached_separately(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        client = GitHubClient(cache_dir=tmp_path)
        tags = iter(["v3.0.0", "v2.6.6"])

        def fake_get(url: str, *, headers: dict[str, str]) -> httpx.Response:
            return _json_response(url, 200, {"tag_name": next(tags), "assets": []})

        monkeypatch.setattr(client._client, "get", fake_get)
        try:
            assert client.release("org", "tool", "latest").version == "3.0.0"
            assert client.release("org", "tool", "v2.6.6").version == "2.6.6"
            # both served from cache now: the iterator would raise StopIteration otherwise
            assert client.release("org", "tool", "latest").version == "3.0.0"
            assert client.release("org", "tool", "v2.6.6").version == "2.6.6"
        finally:
            client.close()
