"""Tests for safe archive install (Zip Slip guard, checksums, binary placement)."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from cyberfw.exceptions import ArchiveSafetyError, ChecksumError, ToolNotFoundError
from cyberfw.manager.github_client import GitHubRelease, ReleaseAsset
from cyberfw.manager.installer import ToolInstaller
from cyberfw.manager.platform_map import Mapping
from cyberfw.manager.registry import ToolSpec
from cyberfw.manager.verify import sha256_hex


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buffer.getvalue()


def _spec(name: str = "subfinder", **overrides) -> ToolSpec:
    defaults = {
        "repo": "org/subfinder",
        "asset_patterns": ["*linux*amd64*"],
        "archive": "zip",
        "binary": "subfinder",
        "needs_checksum": False,
    }
    defaults.update(overrides)
    return ToolSpec(name=name, **defaults)


def _installer(tmp_path: Path, client, spec: ToolSpec) -> ToolInstaller:
    tools_dir = tmp_path / "tools_bin"
    tools_dir.mkdir(parents=True, exist_ok=True)
    return ToolInstaller(client, tools_dir, Mapping("linux", "amd64"))


def _installer_for_mapping(tmp_path: Path, client, mapping: Mapping) -> ToolInstaller:
    tools_dir = tmp_path / "tools_bin"
    tools_dir.mkdir(parents=True, exist_ok=True)
    return ToolInstaller(client, tools_dir, mapping)


class _FakeClient:
    def __init__(self, release, archive_bytes: bytes, checksums: str | None = None) -> None:
        self.release = release
        self.archive_bytes = archive_bytes
        self.checksums = checksums
        self.downloaded: list[Path] = []

    def latest(self, owner: str, repo: str) -> GitHubRelease:
        return self.release

    def download(self, url: str, destination: Path, *, expected_size: int | None = None) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.archive_bytes)
        self.downloaded.append(destination)

    def fetch_text(self, url: str) -> str:
        return self.checksums or ""


class TestSafeMember:
    def test_zip_slip_rejected(self, tmp_path: Path) -> None:
        installer = _installer(tmp_path, _FakeClient(None, b""), _spec())
        with pytest.raises(ArchiveSafetyError):
            installer._safe_member("../evil.txt")

    def test_nested_within_root_allowed(self, tmp_path: Path) -> None:
        installer = _installer(tmp_path, _FakeClient(None, b""), _spec())
        target = installer._safe_member("subfinder/subfinder")
        assert ".." not in str(target.relative_to(installer.tools_dir))


class TestInstall:
    def test_platform_asset_precedes_registry_fallback(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"ffuf/ffuf": b"#!/bin/sh\necho ok\n"})
        linux = ReleaseAsset("ffuf_2.3.0_linux_amd64.tar.gz", "http://linux", len(archive))
        windows = ReleaseAsset("ffuf_2.3.0_windows_amd64.zip", "http://windows", len(archive))
        release = GitHubRelease(tag="v2.3.0", assets=[linux, windows], checksums_url=None)
        client = _FakeClient(release, archive)
        spec = _spec(name="ffuf", binary="ffuf", asset_patterns=["*linux*amd64*"], archive="zip")
        installer = _installer_for_mapping(tmp_path, client, Mapping("windows", "amd64"))

        installer.install(spec)

        assert client.downloaded[0].name == windows.name

    def test_registry_patterns_are_filtered_to_platform(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"gitleaks/gitleaks": b"#!/bin/sh\necho ok\n"})
        darwin = ReleaseAsset("gitleaks_8.30.1_darwin_x64.tar.gz", "http://darwin", len(archive))
        windows = ReleaseAsset("gitleaks_8.30.1_windows_x64.zip", "http://windows", len(archive))
        release = GitHubRelease(tag="v8.30.1", assets=[darwin, windows], checksums_url=None)
        client = _FakeClient(release, archive)
        spec = _spec(
            name="gitleaks",
            binary="gitleaks",
            asset_patterns=["*linux*x64*", "*darwin*x64*", "*windows*x64*"],
            archive="zip",
        )
        installer = _installer_for_mapping(tmp_path, client, Mapping("windows", "amd64"))

        installer.install(spec)

        assert client.downloaded[0].name == windows.name

    def test_install_extracts_binary(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"subfinder_2.6.6_linux_amd64/subfinder": b"#!/bin/sh\necho hi\n"})
        asset = ReleaseAsset("subfinder_2.6.6_linux_amd64.zip", "http://x", len(archive))
        release = GitHubRelease(tag="v2.6.6", assets=[asset], checksums_url=None)
        client = _FakeClient(release, archive)
        installer = _installer(tmp_path, client, _spec())

        result = installer.install(_spec())
        assert result.version == "2.6.6"
        assert result.binary.exists()

    def test_install_replaces_stale_binary_variant(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"naabu.exe": b"#!/bin/sh\necho new\n"})
        asset = ReleaseAsset("naabu_1.0.0_windows_amd64.zip", "http://x", len(archive))
        release = GitHubRelease(tag="v1.0.0", assets=[asset], checksums_url=None)
        client = _FakeClient(release, archive)
        installer = _installer_for_mapping(tmp_path, client, Mapping("windows", "amd64"))
        (installer.tools_dir / "naabu").write_bytes(b"stale")

        result = installer.install(
            _spec(
                name="naabu",
                binary="naabu",
                asset_patterns=["*windows*amd64*"],
            )
        )

        assert not (installer.tools_dir / "naabu").exists()
        assert result.binary.name == "naabu.exe"

    def test_install_copies_raw_binary(self, tmp_path: Path) -> None:
        payload = b"#!/bin/sh\nraw executable"
        asset = ReleaseAsset("gowitness-2.5.2-linux-amd64", "http://x", len(payload))
        release = GitHubRelease(tag="v2.5.2", assets=[asset], checksums_url=None)
        client = _FakeClient(release, payload)
        spec = _spec(name="gowitness", binary="gowitness", archive="raw")
        installer = _installer(tmp_path, client, spec)

        result = installer.install(spec)

        assert result.version == "2.5.2"
        assert result.binary.read_bytes() == payload

    def test_checksum_mismatch_raises(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"f/f": b"data"})
        asset = ReleaseAsset("f_1.0.0_linux_amd64.zip", "http://x", len(archive))
        release = GitHubRelease(tag="v1.0.0", assets=[asset], checksums_url="http://x/sha")
        wrong = "0000000000000000000000000000000000000000000000000000000000000000  f_1.0.0_linux_amd64.zip"
        client = _FakeClient(release, archive, checksums=wrong)
        installer = _installer(tmp_path, client, _spec(name="f", binary="f"))
        spec = _spec(name="f", binary="f", needs_checksum=True)
        with pytest.raises(ChecksumError):
            installer.install(spec)

    def test_checksum_pass(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"g/g": b"#!/bin/sh\ndata"})
        asset = ReleaseAsset("g_1.0.0_linux_amd64.zip", "http://x", len(archive))
        release = GitHubRelease(tag="v1.0.0", assets=[asset], checksums_url="http://x/sha")
        good = f"{sha256_hex(Path(_write_tmp_archive(tmp_path, archive)))}  g_1.0.0_linux_amd64.zip"
        client = _FakeClient(release, archive, checksums=good)
        installer = _installer(tmp_path, client, _spec(name="g", binary="g"))
        result = installer.install(_spec(name="g", binary="g", needs_checksum=True))
        assert result.binary.exists()


def _write_tmp_archive(tmp_path: Path, data: bytes) -> Path:
    dest = tmp_path / "reference.zip"
    dest.write_bytes(data)
    return dest


def test_missing_binary_message_mentions_blocked_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tools_dir = tmp_path / "tools_bin"
    tools_dir.mkdir()
    blocked = tools_dir / "naabu.exe"
    blocked.write_bytes(b"blocked")
    monkeypatch.setattr("cyberfw.manager.verify.is_executable", lambda _: False)

    from cyberfw.manager.verify import ensure_binary

    with pytest.raises(ToolNotFoundError, match="downloaded but its executable could not be read"):
        ensure_binary(tools_dir, "naabu", "naabu")
