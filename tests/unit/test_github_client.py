"""Tests for GitHub release caching."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from cyberfw.manager.github_client import GitHubClient, GitHubRelease, ReleaseAsset


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


def test_latest_uses_github_token_for_authorization(monkeypatch, tmp_path: Path) -> None:
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


def test_download_retries_transient_transport_errors(monkeypatch, tmp_path: Path) -> None:
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
    monkeypatch.setattr(GitHubClient._download_stream.retry, "sleep", lambda *_: None)
    dst = tmp_path / "tool.zip"
    try:
        client.download(url, dst, expected_size=7)
    finally:
        client.close()

    assert len(attempts) == 3
    assert dst.read_bytes() == b"payload"


def test_download_gives_up_after_retries_with_download_error(monkeypatch, tmp_path: Path) -> None:
    from cyberfw.exceptions import DownloadError

    client = GitHubClient()
    url = "https://example.test/tool.zip"
    attempts: list[int] = []

    def fake_stream(method: str, target: str) -> None:
        attempts.append(1)
        raise httpx.ConnectTimeout("_ssl.c:1064: The handshake operation timed out", request=httpx.Request(method, target))

    monkeypatch.setattr(client._client, "stream", fake_stream)
    monkeypatch.setattr(GitHubClient._download_stream.retry, "sleep", lambda *_: None)
    try:
        with pytest.raises(DownloadError, match="Failed to download .* after 4 attempts"):
            client.download(url, tmp_path / "tool.zip")
    finally:
        client.close()

    assert len(attempts) == 4


def test_download_does_not_retry_http_status_errors(monkeypatch, tmp_path: Path) -> None:
    from cyberfw.exceptions import DownloadError

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
    monkeypatch.setattr(GitHubClient._download_stream.retry, "sleep", lambda *_: None)
    try:
        with pytest.raises(DownloadError):
            client.download(url, tmp_path / "missing.zip")
    finally:
        client.close()

    assert len(attempts) == 1
