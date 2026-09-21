"""Tests for the ToolManager facade (install bookkeeping, settings plumbing)."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from cyberfw.config import Settings
from cyberfw.exceptions import DownloadError
from cyberfw.manager import ToolManager
from cyberfw.manager.github_client import GitHubRelease, ReleaseAsset
from cyberfw.manager.platform_map import Mapping
from cyberfw.manager.registry import load_registry


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buffer.getvalue()


class _FakeClient:
    def __init__(self, release: GitHubRelease, archive_bytes: bytes) -> None:
        self.current = release
        self.archive_bytes = archive_bytes

    def latest(self, owner: str, repo: str) -> GitHubRelease:
        return self.current

    def release(self, owner: str, repo: str, tag: str) -> GitHubRelease:
        return self.current

    def download(self, url: str, destination: Path, *, expected_size: int | None = None) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.archive_bytes)

    def fetch_text(self, url: str) -> str:
        return ""

    def close(self) -> None:
        pass


def _manager(tmp_path: Path, archive: bytes, **settings: object) -> ToolManager:
    registry_path = tmp_path / "registry.yaml"
    registry_path.write_text(
        "subfinder:\n  repo: org/subfinder\n  asset_patterns: ['*linux*amd64*']\n  binary: subfinder\n"
        "  needs_checksum: false\n",
        encoding="utf-8",
    )
    asset = ReleaseAsset("subfinder_1.0.0_linux_amd64.zip", "http://x", len(archive))
    release = GitHubRelease(tag="v1.0.0", assets=[asset], checksums_url=None)
    manager = ToolManager(
        Settings(root_dir=tmp_path, **settings),  # type: ignore[arg-type]
        load_registry(registry_path),
        Mapping("linux", "amd64"),
    )
    manager.settings.ensure_dirs()
    manager._client = _FakeClient(release, archive)  # type: ignore[assignment]
    return manager


class TestInstall:
    def test_max_archive_size_setting_reaches_the_installer(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CYBERFW_MAX_ARCHIVE", raising=False)
        manager = _manager(tmp_path, _zip_bytes({"subfinder": b"#!/bin/sh\n" + b"x" * 100}), max_archive_size=16)

        with pytest.raises(DownloadError, match="limit 16"):
            manager.install("subfinder")
        assert manager.install_state("subfinder") is None

    def test_successful_install_records_state(self, tmp_path: Path) -> None:
        manager = _manager(tmp_path, _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n"}))

        result = manager.install("subfinder")

        state = manager.install_state("subfinder")
        assert state is not None
        assert state["version"] == "1.0.0"
        assert state["binary"] == str(result.binary.resolve())
        assert manager.is_installed("subfinder")


class _CountingClient(_FakeClient):
    def __init__(self, release: GitHubRelease, archive_bytes: bytes) -> None:
        super().__init__(release, archive_bytes)
        self.release_calls = 0
        self.downloads = 0

    def release(self, owner: str, repo: str, tag: str) -> GitHubRelease:
        self.release_calls += 1
        return self.current

    def download(self, url: str, destination: Path, *, expected_size: int | None = None) -> None:
        self.downloads += 1
        super().download(url, destination, expected_size=expected_size)


def _manager_with(
    tmp_path: Path, registry_yaml: str, archive: bytes, tag: str = "v1.0.0"
) -> tuple[ToolManager, _CountingClient]:
    (tmp_path / "registry.yaml").write_text(registry_yaml, encoding="utf-8")
    asset = ReleaseAsset(f"subfinder_{tag.lstrip('v')}_linux_amd64.zip", "http://x", len(archive))
    client = _CountingClient(GitHubRelease(tag=tag, assets=[asset], checksums_url=None), archive)
    manager = ToolManager(
        Settings(root_dir=tmp_path), load_registry(tmp_path / "registry.yaml"), Mapping("linux", "amd64")
    )
    manager.settings.ensure_dirs()
    manager._client = client  # type: ignore[assignment]
    return manager, client


_LATEST = (
    "subfinder:\n  repo: org/subfinder\n  asset_patterns: ['*linux*amd64*']\n"
    "  binary: subfinder\n  needs_checksum: false\n"
)
_PINNED = _LATEST + "  version: v1.0.0\n"


class TestSkipUpToDate:
    def test_second_install_of_the_same_version_downloads_nothing(self, tmp_path: Path) -> None:
        manager, client = _manager_with(tmp_path, _LATEST, _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n"}))
        first = manager.install("subfinder")
        second = manager.install("subfinder")

        assert client.downloads == 1
        assert first.up_to_date is False
        assert second.up_to_date is True
        assert second.binary == first.binary and second.version == "1.0.0"

    def test_force_reinstalls(self, tmp_path: Path) -> None:
        manager, client = _manager_with(tmp_path, _LATEST, _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n"}))
        manager.install("subfinder")
        result = manager.install("subfinder", force=True)

        assert client.downloads == 2
        assert result.up_to_date is False

    def test_pinned_version_already_installed_needs_no_network(self, tmp_path: Path) -> None:
        manager, client = _manager_with(tmp_path, _PINNED, _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n"}))
        manager.install("subfinder")
        calls_after_first = client.release_calls

        result = manager.install("subfinder")

        assert result.up_to_date is True
        assert client.release_calls == calls_after_first

    def test_newer_release_is_installed_over_the_old_one(self, tmp_path: Path) -> None:
        manager, client = _manager_with(tmp_path, _LATEST, _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n"}))
        manager.install("subfinder")
        newer = _zip_bytes({"subfinder": b"#!/bin/sh\necho v2\n"})
        client.current = GitHubRelease(
            tag="v2.0.0",
            assets=[ReleaseAsset("subfinder_2.0.0_linux_amd64.zip", "http://x", len(newer))],
            checksums_url=None,
        )
        client.archive_bytes = newer

        result = manager.install("subfinder")

        assert result.up_to_date is False
        assert result.version == "2.0.0"
        assert client.downloads == 2

    def test_missing_binary_is_reinstalled_despite_matching_state(self, tmp_path: Path) -> None:
        manager, client = _manager_with(tmp_path, _PINNED, _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n"}))
        first = manager.install("subfinder")
        first.binary.unlink()

        result = manager.install("subfinder")

        assert result.up_to_date is False
        assert client.downloads == 2
