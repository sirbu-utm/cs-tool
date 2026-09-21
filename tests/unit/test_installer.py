"""Tests for safe archive install (Zip Slip guard, checksums, binary placement)."""

from __future__ import annotations

import io
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

from cyberfw.exceptions import ArchiveSafetyError, ChecksumError, DownloadError, ToolNotFoundError
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


def _lying_zip_bytes(name: str, real_size: int, declared_size: int) -> bytes:
    """A DEFLATE member that inflates to ``real_size`` but whose headers claim ``declared_size``.

    This is the "header-forged decompression bomb" shape: the size check that sums
    ``file_size`` over the central directory sees only ``declared_size``.
    """
    data = bytearray(_zip_bytes({name: b"A" * real_size}))
    packed = struct.pack("<I", declared_size)
    data[22:26] = packed  # local file header: uncompressed size
    central = data.rfind(b"PK\x01\x02")
    data[central + 24 : central + 28] = packed  # central directory: uncompressed size
    return bytes(data)


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
        self.current = release
        self.archive_bytes = archive_bytes
        self.checksums = checksums
        self.downloaded: list[Path] = []

    def latest(self, owner: str, repo: str) -> GitHubRelease:
        return self.current

    def release(self, owner: str, repo: str, tag: str) -> GitHubRelease:
        return self.current

    def download(self, url: str, destination: Path, *, expected_size: int | None = None) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.archive_bytes)
        self.downloaded.append(destination)

    def fetch_text(self, url: str) -> str:
        return self.checksums or ""


class TestArchiveBombs:
    def test_forged_size_header_cannot_write_more_than_declared(self, tmp_path: Path) -> None:
        """A member whose DEFLATE stream inflates to 4 MiB but declares 16 bytes must not
        land 4 MiB on disk — and the corrupt archive must surface as a clean DownloadError,
        not a bare ``zipfile.BadZipFile`` traceback."""
        declared, real = 16, 4 * 1024 * 1024
        archive = _lying_zip_bytes("subfinder", real_size=real, declared_size=declared)
        asset = ReleaseAsset("subfinder_1.0.0_linux_amd64.zip", "http://x", len(archive))
        release = GitHubRelease(tag="v1.0.0", assets=[asset], checksums_url=None)
        installer = _installer(tmp_path, _FakeClient(release, archive), _spec())

        with pytest.raises(DownloadError, match="corrupt"):
            installer.install(_spec())

        written = sum(
            p.stat().st_size for p in installer.tools_dir.rglob("*") if p.is_file() and p.suffix != ".zip"
        )
        assert written <= declared

    def test_truncated_tarball_is_a_clean_download_error(self, tmp_path: Path) -> None:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
            info = tarfile.TarInfo("subfinder")
            payload = b"#!/bin/sh\necho hi\n" * 200
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
        archive = buffer.getvalue()[: len(buffer.getvalue()) // 2]
        asset = ReleaseAsset("subfinder_1.0.0_linux_amd64.tar.gz", "http://x", len(archive))
        release = GitHubRelease(tag="v1.0.0", assets=[asset], checksums_url=None)
        installer = _installer(tmp_path, _FakeClient(release, archive), _spec(archive="tar"))

        with pytest.raises(DownloadError, match="corrupt"):
            installer.install(_spec(archive="tar"))


class TestSafeMember:
    def test_zip_slip_rejected(self, tmp_path: Path) -> None:
        installer = _installer(tmp_path, _FakeClient(None, b""), _spec())
        with pytest.raises(ArchiveSafetyError):
            installer._safe_member("../evil.txt", installer.tools_dir / "subfinder")

    def test_member_escaping_into_a_sibling_tool_dir_rejected(self, tmp_path: Path) -> None:
        installer = _installer(tmp_path, _FakeClient(None, b""), _spec())
        with pytest.raises(ArchiveSafetyError):
            installer._safe_member("../httpx/httpx", installer.tools_dir / "subfinder")

    def test_nested_within_root_allowed(self, tmp_path: Path) -> None:
        installer = _installer(tmp_path, _FakeClient(None, b""), _spec())
        target = installer._safe_member("subfinder_1.0/subfinder", installer.tools_dir / "subfinder")
        assert target.relative_to(installer.tools_dir / "subfinder") == Path("subfinder_1.0/subfinder")


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

    def test_no_asset_for_this_os_raises_instead_of_downloading_foreign_binary(self, tmp_path: Path) -> None:
        """Registry patterns for *other* OSes must never be used as a last resort."""
        archive = _zip_bytes({"rustscan": b"#!/bin/sh\necho ok\n"})
        linux = ReleaseAsset("x86_64-linux-rustscan.zip", "http://linux", len(archive))
        windows = ReleaseAsset("x86_64-windows-rustscan.zip", "http://windows", len(archive))
        release = GitHubRelease(tag="v2.4.1", assets=[linux, windows], checksums_url=None)
        client = _FakeClient(release, archive)
        spec = _spec(
            name="rustscan",
            binary="rustscan",
            asset_patterns=["*x86_64*linux*rustscan*.zip", "*x86_64*windows*rustscan*.zip"],
            archive="zip",
        )
        installer = _installer_for_mapping(tmp_path, client, Mapping("darwin", "amd64"))

        with pytest.raises(DownloadError, match="OS=darwin"):
            installer.install(spec)
        assert client.downloaded == []

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

        # The flat-layout binary is gone; ``tools_bin/naabu`` is now the tool's directory.
        assert not (installer.tools_dir / "naabu").is_file()
        assert result.binary == (installer.tools_dir / "naabu" / "naabu.exe").resolve()

    def test_locked_stale_binary_is_moved_aside_not_fatal(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Windows refuses to unlink a running/AV-scanned exe but allows renaming it; init must survive that."""
        archive = _zip_bytes({"naabu.exe": b"#!/bin/sh\necho new\n"})
        asset = ReleaseAsset("naabu_1.0.0_windows_amd64.zip", "http://x", len(archive))
        release = GitHubRelease(tag="v1.0.0", assets=[asset], checksums_url=None)
        client = _FakeClient(release, archive)
        installer = _installer_for_mapping(tmp_path, client, Mapping("windows", "amd64"))
        stale = installer.tools_dir / "naabu.exe"
        stale.write_bytes(b"stale")

        real_unlink = Path.unlink

        def locked_unlink(self: Path, missing_ok: bool = False) -> None:
            if self.read_bytes() == b"stale":
                raise PermissionError(32, "The process cannot access the file because it is being used")
            real_unlink(self, missing_ok=missing_ok)

        monkeypatch.setattr(Path, "unlink", locked_unlink)

        result = installer.install(_spec(name="naabu", binary="naabu", asset_patterns=["*windows*amd64*"]))

        assert result.binary == (installer.tools_dir / "naabu" / "naabu.exe").resolve()
        assert result.binary.read_bytes() == b"#!/bin/sh\necho new\n"
        # The locked file was renamed aside, so its old name no longer shadows anything.
        assert not stale.exists()

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


class TestArchiveSizeLimit:
    def test_limit_is_the_value_the_installer_was_given(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """``Settings.max_archive_size`` must reach the installer; it used to read a private
        ``CYBERFW_MAX_ARCHIVE`` env var instead, so the documented setting was silently ignored."""
        monkeypatch.delenv("CYBERFW_MAX_ARCHIVE", raising=False)
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\n" + b"x" * 100})
        asset = ReleaseAsset("subfinder_1.0.0_linux_amd64.zip", "http://x", len(archive))
        release = GitHubRelease(tag="v1.0.0", assets=[asset], checksums_url=None)
        installer = ToolInstaller(
            _FakeClient(release, archive), tmp_path / "tools_bin", Mapping("linux", "amd64"), max_archive_size=16
        )

        with pytest.raises(DownloadError, match="limit 16"):
            installer.install(_spec())

    def test_archive_within_limit_installs(self, tmp_path: Path) -> None:
        payload = b"#!/bin/sh\necho ok\n"
        archive = _zip_bytes({"subfinder": payload})
        asset = ReleaseAsset("subfinder_1.0.0_linux_amd64.zip", "http://x", len(archive))
        release = GitHubRelease(tag="v1.0.0", assets=[asset], checksums_url=None)
        installer = ToolInstaller(
            _FakeClient(release, archive),
            tmp_path / "tools_bin",
            Mapping("linux", "amd64"),
            max_archive_size=len(payload),
        )

        assert installer.install(_spec()).binary.read_bytes() == payload


class TestToolsDirLayout:
    """Every tool lives in ``tools_bin/<tool>/``; nothing but those directories (and the
    install-state files ToolManager keeps) may accumulate at the top level."""

    @staticmethod
    def _release(name: str, archive: bytes) -> GitHubRelease:
        asset = ReleaseAsset(name, "http://x", len(archive))
        return GitHubRelease(tag="v1.0.0", assets=[asset], checksums_url=None)

    def test_archive_members_land_in_a_per_tool_directory(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n", "README.md": b"docs", "LICENSE": b"mit"})
        client = _FakeClient(self._release("subfinder_1.0.0_linux_amd64.zip", archive), archive)
        installer = _installer(tmp_path, client, _spec())

        result = installer.install(_spec())

        tool_dir = installer.tools_dir / "subfinder"
        assert result.binary == (tool_dir / "subfinder").resolve()
        assert (tool_dir / "README.md").is_file()
        assert not (installer.tools_dir / "README.md").exists(), "docs from one tool must not clobber another's"

    def test_downloaded_archive_is_removed_after_extraction(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n"})
        client = _FakeClient(self._release("subfinder_1.0.0_linux_amd64.zip", archive), archive)
        installer = _installer(tmp_path, client, _spec())

        installer.install(_spec())

        assert not client.downloaded[0].exists()

    def test_corrupt_archive_is_not_left_behind_either(self, tmp_path: Path) -> None:
        archive = b"PK\x03\x04 definitely not a zip"
        client = _FakeClient(self._release("subfinder_1.0.0_linux_amd64.zip", archive), archive)
        installer = _installer(tmp_path, client, _spec())

        with pytest.raises(DownloadError):
            installer.install(_spec())

        assert not client.downloaded[0].exists()

    def test_raw_asset_leaves_no_copy_under_its_release_name(self, tmp_path: Path) -> None:
        payload = b"#!/bin/sh\nraw executable"
        client = _FakeClient(self._release("gowitness-1.0.0-linux-amd64", payload), payload)
        spec = _spec(name="gowitness", binary="gowitness", archive="raw")
        installer = _installer(tmp_path, client, spec)

        result = installer.install(spec)

        assert result.binary.parent == (installer.tools_dir / "gowitness").resolve()
        assert result.binary.stem == "gowitness"
        assert [p.name for p in installer.tools_dir.iterdir()] == ["gowitness"]

    def test_reinstall_discards_files_of_the_previous_version(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho new\n"})
        client = _FakeClient(self._release("subfinder_1.0.0_linux_amd64.zip", archive), archive)
        installer = _installer(tmp_path, client, _spec())
        old = installer.tools_dir / "subfinder" / "CHANGELOG-0.9.md"
        old.parent.mkdir(parents=True)
        old.write_text("old release notes", encoding="utf-8")

        installer.install(_spec())

        assert not old.exists()

    def test_legacy_flat_layout_binary_gives_way_to_the_tool_directory(self, tmp_path: Path) -> None:
        """Older installs put the binary at ``tools_bin/subfinder`` — the very path that is
        now the tool's directory. Re-installing must replace the file with the directory."""
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho new\n"})
        client = _FakeClient(self._release("subfinder_1.0.0_linux_amd64.zip", archive), archive)
        installer = _installer(tmp_path, client, _spec())
        legacy = installer.tools_dir / "subfinder"
        legacy.write_bytes(b"#!/bin/sh\necho old\n")

        result = installer.install(_spec())

        assert legacy.is_dir()
        assert result.binary == (legacy / "subfinder").resolve()
        assert result.binary.read_bytes() == b"#!/bin/sh\necho new\n"

    def test_stale_downloads_of_the_same_tool_are_removed(self, tmp_path: Path) -> None:
        """Earlier versions left the archive next to the binary; a re-install cleans up
        exactly those (they match this tool's asset patterns) and nothing else."""
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n"})
        client = _FakeClient(self._release("subfinder_1.0.0_linux_amd64.zip", archive), archive)
        installer = _installer(tmp_path, client, _spec())
        ours = installer.tools_dir / "subfinder_0.9.0_linux_amd64.zip"
        theirs = installer.tools_dir / "httpx_0.9.0_linux_amd64.zip"
        ours.write_bytes(b"old")
        theirs.write_bytes(b"not mine")

        installer.install(_spec(asset_patterns=["subfinder_*_linux_amd64.zip"]))

        assert not ours.exists()
        assert theirs.exists()


class _TagAwareClient(_FakeClient):
    """Fake that also answers ``release(owner, repo, tag)`` and remembers the tag asked for."""

    def __init__(self, release, archive_bytes: bytes, checksums: str | None = None) -> None:
        super().__init__(release, archive_bytes, checksums)
        self.tags: list[str] = []

    def release(self, owner: str, repo: str, tag: str) -> GitHubRelease:
        self.tags.append(tag)
        return self.current


class TestPinnedVersion:
    def test_pinned_spec_asks_for_that_tag(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n"})
        asset = ReleaseAsset("subfinder_2.6.6_linux_amd64.zip", "http://x", len(archive))
        release = GitHubRelease(tag="v2.6.6", assets=[asset], checksums_url=None)
        client = _TagAwareClient(release, archive)
        installer = _installer(tmp_path, client, _spec())

        result = installer.install(_spec(version="v2.6.6"))

        assert client.tags == ["v2.6.6"]
        assert result.version == "2.6.6"

    def test_unpinned_spec_asks_for_latest(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n"})
        asset = ReleaseAsset("subfinder_2.6.6_linux_amd64.zip", "http://x", len(archive))
        release = GitHubRelease(tag="v2.6.6", assets=[asset], checksums_url=None)
        client = _TagAwareClient(release, archive)
        installer = _installer(tmp_path, client, _spec())

        installer.install(_spec())

        assert client.tags == ["latest"]


class TestRegistryChecksums:
    @staticmethod
    def _release(archive: bytes) -> GitHubRelease:
        asset = ReleaseAsset("subfinder_1.0.0_linux_amd64.zip", "http://x", len(archive))
        return GitHubRelease(tag="v1.0.0", assets=[asset], checksums_url=None)

    def test_registry_digest_mismatch_rejects_the_download(self, tmp_path: Path) -> None:
        """A sha256 pinned in registry.yaml is checked even when upstream publishes no checksums."""
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n"})
        client = _TagAwareClient(self._release(archive), archive)
        installer = _installer(tmp_path, client, _spec())
        spec = _spec(sha256={"subfinder_1.0.0_linux_amd64.zip": "0" * 64})

        with pytest.raises(ChecksumError):
            installer.install(spec)

    def test_registry_digest_match_installs(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n"})
        client = _TagAwareClient(self._release(archive), archive)
        installer = _installer(tmp_path, client, _spec())
        digest = sha256_hex(_write_tmp_archive(tmp_path, archive))

        result = installer.install(_spec(sha256={"subfinder_1.0.0_linux_amd64.zip": digest}))

        assert result.binary.exists()

    def test_unverifiable_download_is_reported(self, tmp_path: Path, caplog) -> None:
        """needs_checksum with neither an upstream checksums file nor a registry digest:
        install, but say so — silence would look like verification happened."""
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n"})
        client = _TagAwareClient(self._release(archive), archive)
        installer = _installer(tmp_path, client, _spec())

        with caplog.at_level("WARNING", logger="cyberfw.manager"):
            installer.install(_spec(needs_checksum=True))

        assert any("not verified" in r.getMessage() for r in caplog.records)

    def test_upstream_file_without_an_entry_is_reported(self, tmp_path: Path, caplog) -> None:
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n"})
        asset = ReleaseAsset("subfinder_1.0.0_linux_amd64.zip", "http://x", len(archive))
        release = GitHubRelease(tag="v1.0.0", assets=[asset], checksums_url="http://x/sha")
        client = _TagAwareClient(release, archive, checksums="b" * 64 + "  something_else.zip")
        installer = _installer(tmp_path, client, _spec())

        with caplog.at_level("WARNING", logger="cyberfw.manager"):
            installer.install(_spec(needs_checksum=True))

        assert any("not verified" in r.getMessage() for r in caplog.records)
