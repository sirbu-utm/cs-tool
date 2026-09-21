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
        self.release = release
        self.archive_bytes = archive_bytes

    def latest(self, owner: str, repo: str) -> GitHubRelease:
        return self.release

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
