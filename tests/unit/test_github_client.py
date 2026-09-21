"""Tests for GitHub release caching."""

from __future__ import annotations

from pathlib import Path

import httpx

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
