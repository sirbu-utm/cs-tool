"""Tests for safe archive install (Zip Slip guard, lock verification, binary placement)."""

from __future__ import annotations

import hashlib
import io
import os
import stat
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

from cyberfw.core.workspace import binary_on_disk
from cyberfw.exceptions import ChecksumError, DownloadError, ToolNotFoundError
from cyberfw.manager.github_client import GitHubRelease, ReleaseAsset
from cyberfw.manager.installer import InstallResult, ToolInstaller, select_asset
from cyberfw.manager.lock import LockedAsset
from cyberfw.manager.platform_map import Mapping
from cyberfw.manager.registry import ToolSpec
from cyberfw.manager.verify import checksum_for, ensure_binary


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


def _spec(name: str = "subfinder", **overrides: object) -> ToolSpec:
    fields: dict[str, object] = {
        "repo": "org/subfinder",
        "asset_patterns": ["*linux*amd64*"],
        "archive": "zip",
        "binary": "subfinder",
    }
    fields.update(overrides)
    return ToolSpec(name=name, **fields)  # type: ignore[arg-type]


class _FakeClient:
    """Serves ``archive_bytes`` for any URL and remembers what was fetched."""

    def __init__(self, archive_bytes: bytes) -> None:
        self.archive_bytes = archive_bytes
        self.urls: list[str] = []
        self.downloaded: list[Path] = []

    def download(self, url: str, destination: Path, *, expected_size: int | None = None) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.archive_bytes)
        self.urls.append(url)
        self.downloaded.append(destination)


def _installer(tmp_path: Path, client: _FakeClient, mapping: Mapping | None = None, **kwargs: int) -> ToolInstaller:
    tools_dir = tmp_path / "tools_bin"
    tools_dir.mkdir(parents=True, exist_ok=True)
    return ToolInstaller(client, tools_dir, mapping or Mapping("linux", "amd64"), **kwargs)  # type: ignore[arg-type]


def _locked(name: str, payload: bytes, sha256: str | None = None) -> LockedAsset:
    """``name``'s lock entry; its hash is ``payload``'s unless one is given."""
    return LockedAsset(
        name=name,
        url=f"https://example.test/{name}",
        sha256=sha256 if sha256 is not None else hashlib.sha256(payload).hexdigest(),
        source="digest",
    )


def _install(
    installer: ToolInstaller, spec: ToolSpec, archive: bytes, name: str, version: str = "1.0.0"
) -> InstallResult:
    """Install ``archive`` as the locked asset ``name`` (its hash taken from the bytes served)."""
    return installer.install_locked(spec, version, _locked(name, archive))


_SUBFINDER_ZIP = "subfinder_1.0.0_linux_amd64.zip"


class TestArchiveBombs:
    def test_forged_size_header_cannot_write_more_than_declared(self, tmp_path: Path) -> None:
        """A member whose DEFLATE stream inflates to 4 MiB but declares 16 bytes must not
        land 4 MiB on disk — and the corrupt archive must surface as a clean DownloadError,
        not a bare ``zipfile.BadZipFile`` traceback."""
        declared, real = 16, 4 * 1024 * 1024
        archive = _lying_zip_bytes("subfinder", real_size=real, declared_size=declared)
        installer = _installer(tmp_path, _FakeClient(archive))

        with pytest.raises(DownloadError, match="corrupt"):
            _install(installer, _spec(), archive, _SUBFINDER_ZIP)

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
        installer = _installer(tmp_path, _FakeClient(archive))

        with pytest.raises(DownloadError, match="corrupt"):
            _install(installer, _spec(archive="tar"), archive, "subfinder_1.0.0_linux_amd64.tar.gz")


class TestDebugDiagnostics:
    def test_install_logs_the_asset_and_version(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        import logging

        archive = _zip_bytes({"subfinder/subfinder": b"#!/bin/sh\necho ok\n"})
        installer = _installer(tmp_path, _FakeClient(archive))

        logger = logging.getLogger("cyberfw.manager.installer")
        logger.addHandler(caplog.handler)
        logger.setLevel(logging.DEBUG)
        try:
            _install(installer, _spec(), archive, _SUBFINDER_ZIP)
        finally:
            logger.removeHandler(caplog.handler)

        messages = " ".join(r.getMessage() for r in caplog.records)
        assert _SUBFINDER_ZIP in messages  # the installed asset
        assert "1.0.0" in messages  # the installed version


class TestSelectAsset:
    """Which release asset a platform gets — shared by the installer and tools.lock."""

    def test_platform_asset_precedes_registry_fallback(self) -> None:
        linux = ReleaseAsset("ffuf_2.3.0_linux_amd64.tar.gz", "https://x/linux", 1)
        windows = ReleaseAsset("ffuf_2.3.0_windows_amd64.zip", "https://x/windows", 1)
        release = GitHubRelease(tag="v2.3.0", assets=[linux, windows], checksums_url=None)
        spec = _spec(name="ffuf", binary="ffuf", asset_patterns=["*linux*amd64*"])

        assert select_asset(release, spec, Mapping("windows", "amd64")) is windows

    def test_registry_patterns_are_filtered_to_platform(self) -> None:
        darwin = ReleaseAsset("gitleaks_8.30.1_darwin_x64.tar.gz", "https://x/darwin", 1)
        windows = ReleaseAsset("gitleaks_8.30.1_windows_x64.zip", "https://x/windows", 1)
        release = GitHubRelease(tag="v8.30.1", assets=[darwin, windows], checksums_url=None)
        spec = _spec(
            name="gitleaks", binary="gitleaks", asset_patterns=["*linux*x64*", "*darwin*x64*", "*windows*x64*"]
        )

        assert select_asset(release, spec, Mapping("windows", "amd64")) is windows

    def test_no_asset_for_this_os_is_none_never_a_foreign_binary(self) -> None:
        """Registry patterns for *other* OSes must never be used as a last resort."""
        linux = ReleaseAsset("x86_64-linux-rustscan.zip", "https://x/linux", 1)
        windows = ReleaseAsset("x86_64-windows-rustscan.zip", "https://x/windows", 1)
        release = GitHubRelease(tag="v2.4.1", assets=[linux, windows], checksums_url=None)
        spec = _spec(
            name="rustscan",
            binary="rustscan",
            asset_patterns=["*x86_64*linux*rustscan*.zip", "*x86_64*windows*rustscan*.zip"],
        )

        assert select_asset(release, spec, Mapping("darwin", "amd64")) is None

    def test_macos_spelling_counts_as_darwin(self) -> None:
        """ProjectDiscovery publishes `_macOS_` where the registry says `darwin`."""
        mac = ReleaseAsset("subfinder_2.17.0_macOS_arm64.zip", "https://x/mac", 1)
        release = GitHubRelease(tag="v2.17.0", assets=[mac], checksums_url=None)

        assert select_asset(release, _spec(), Mapping("darwin", "arm64")) is mac

    def test_gowitness_gets_the_arm64_binary_on_arm64(self) -> None:
        """Real registry.yaml entry: aarch64 must get -linux-arm64, not -linux-arm or -linux-amd64."""
        from cyberfw.manager.registry import load_registry

        spec = load_registry(Path(__file__).resolve().parents[2] / "registry.yaml").require("gowitness")
        assets = [
            ReleaseAsset(name, "https://x", 1)
            for name in ("gowitness-3.2.0-linux-amd64", "gowitness-3.2.0-linux-arm", "gowitness-3.2.0-linux-arm64")
        ]
        release = GitHubRelease(tag="v3.2.0", assets=assets, checksums_url=None)

        picked = select_asset(release, spec, Mapping("linux", "arm64"))

        assert picked is not None and picked.name == "gowitness-3.2.0-linux-arm64"

    #: RustScan 2.4.1's assets in the order GitHub lists them (arch-first names).
    _RUSTSCAN_2_4_1 = (
        "aarch64-linux-rustscan.zip",
        "aarch64-macos-rustscan.tar.gz.zip",
        "rustscan.deb.zip",
        "x86-linux-rustscan.zip",
        "x86-windows-rustscan.exe.zip",
        "x86_64-linux-rustscan.tar.gz.1.zip",
        "x86_64-linux-rustscan.tar.gz.zip",
        "x86_64-macos-rustscan.tar.gz.zip",
        "x86_64-windows-rustscan.exe.zip",
    )

    @pytest.mark.parametrize(
        ("platform", "expected"),
        [
            (Mapping("linux", "amd64"), "x86_64-linux-rustscan.tar.gz.1.zip"),
            (Mapping("linux", "arm64"), "aarch64-linux-rustscan.zip"),
            (Mapping("darwin", "amd64"), "x86_64-macos-rustscan.tar.gz.zip"),
            (Mapping("darwin", "arm64"), "aarch64-macos-rustscan.tar.gz.zip"),
            (Mapping("windows", "amd64"), "x86_64-windows-rustscan.exe.zip"),
            (Mapping("windows", "arm64"), "x86_64-windows-rustscan.exe.zip"),
        ],
        ids=["linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64", "windows-amd64", "windows-arm64"],
    )
    def test_rustscan_gets_its_own_architecture(self, platform: Mapping, expected: str) -> None:
        """Real registry.yaml entry and release: RustScan names assets arch-first and lists the
        aarch64 build first, so an x86_64 Linux host (WSL) must not be handed the aarch64 binary.
        Windows on ARM, with no native build, gets the x64 one it runs under emulation."""
        from cyberfw.manager.registry import load_registry

        spec = load_registry(Path(__file__).resolve().parents[2] / "registry.yaml").require("rustscan")
        assets = [ReleaseAsset(name, f"https://x/{name}", 1) for name in self._RUSTSCAN_2_4_1]
        release = GitHubRelease(tag="2.4.1", assets=assets, checksums_url=None)

        picked = select_asset(release, spec, platform)

        assert picked is not None and picked.name == expected

    def test_windows_on_arm_without_a_native_build_gets_the_x64_one(self) -> None:
        """Windows 11 on ARM emulates x64: prefer that build over the bare `*windows*` catch-all,
        which would take the 32-bit one listed first."""
        assets = [
            ReleaseAsset(name, f"https://x/{name}", 1)
            for name in ("nuclei_3.11.1_windows_386.zip", "nuclei_3.11.1_windows_amd64.zip")
        ]
        release = GitHubRelease(tag="v3.11.1", assets=assets, checksums_url=None)

        picked = select_asset(release, _spec(name="nuclei", asset_patterns=["nuclei_*"]), Mapping("windows", "arm64"))

        assert picked is not None and picked.name == "nuclei_3.11.1_windows_amd64.zip"

    def test_apple_silicon_without_a_native_build_gets_the_x86_64_one(self) -> None:
        """Apple silicon runs x86_64 builds under Rosetta 2."""
        mac = ReleaseAsset("tool_1.0.0_darwin_amd64.zip", "https://x/mac", 1)
        release = GitHubRelease(tag="v1.0.0", assets=[mac], checksums_url=None)

        assert select_asset(release, _spec(asset_patterns=[]), Mapping("darwin", "arm64")) is mac

    def test_linux_on_arm_never_falls_back_to_an_x64_build(self) -> None:
        """Linux has no such emulation: an aarch64 host cannot run an x86_64 binary."""
        linux = ReleaseAsset("tool_1.0.0_linux_amd64.zip", "https://x/linux", 1)
        release = GitHubRelease(tag="v1.0.0", assets=[linux], checksums_url=None)
        spec = _spec(asset_patterns=["tool_*_linux_amd64.zip"])

        assert select_asset(release, spec, Mapping("linux", "arm64")) is None


class TestInstall:
    def test_install_extracts_binary(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"subfinder_2.6.6_linux_amd64/subfinder": b"#!/bin/sh\necho hi\n"})
        installer = _installer(tmp_path, _FakeClient(archive))

        result = _install(installer, _spec(), archive, "subfinder_2.6.6_linux_amd64.zip", version="2.6.6")

        assert result.version == "2.6.6"
        assert result.binary.exists()

    def test_install_replaces_stale_binary_variant(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"naabu.exe": b"#!/bin/sh\necho new\n"})
        installer = _installer(tmp_path, _FakeClient(archive), Mapping("windows", "amd64"))
        (installer.tools_dir / "naabu").write_bytes(b"stale")
        spec = _spec(name="naabu", binary="naabu", asset_patterns=["*windows*amd64*"])

        result = _install(installer, spec, archive, "naabu_1.0.0_windows_amd64.zip")

        # The flat-layout binary is gone; ``tools_bin/naabu`` is now the tool's directory.
        assert not (installer.tools_dir / "naabu").is_file()
        assert result.binary == (installer.tools_dir / "naabu" / "naabu.exe").resolve()

    def test_locked_stale_binary_is_moved_aside_not_fatal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Windows refuses to unlink a running/AV-scanned exe but allows renaming it; init must survive that."""
        archive = _zip_bytes({"naabu.exe": b"#!/bin/sh\necho new\n"})
        installer = _installer(tmp_path, _FakeClient(archive), Mapping("windows", "amd64"))
        stale = installer.tools_dir / "naabu.exe"
        stale.write_bytes(b"stale")

        real_unlink = Path.unlink

        def locked_unlink(self: Path, missing_ok: bool = False) -> None:
            if self.read_bytes() == b"stale":
                raise PermissionError(32, "The process cannot access the file because it is being used")
            real_unlink(self, missing_ok=missing_ok)

        monkeypatch.setattr(Path, "unlink", locked_unlink)
        spec = _spec(name="naabu", binary="naabu", asset_patterns=["*windows*amd64*"])

        result = _install(installer, spec, archive, "naabu_1.0.0_windows_amd64.zip")

        assert result.binary == (installer.tools_dir / "naabu" / "naabu.exe").resolve()
        assert result.binary.read_bytes() == b"#!/bin/sh\necho new\n"
        # The locked file was renamed aside, so its old name no longer shadows anything.
        assert not stale.exists()

    def test_install_copies_raw_binary(self, tmp_path: Path) -> None:
        payload = b"#!/bin/sh\nraw executable"
        installer = _installer(tmp_path, _FakeClient(payload))
        spec = _spec(name="gowitness", binary="gowitness", archive="raw")

        result = _install(installer, spec, payload, "gowitness-2.5.2-linux-amd64", version="2.5.2")

        assert result.version == "2.5.2"
        assert result.binary.read_bytes() == payload


class TestInstallLocked:
    def test_the_locked_url_is_what_gets_downloaded(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n"})
        client = _FakeClient(archive)

        _install(_installer(tmp_path, client), _spec(), archive, _SUBFINDER_ZIP)

        assert client.urls == [f"https://example.test/{_SUBFINDER_ZIP}"]

    def test_a_mismatch_keeps_the_previous_install_and_leaves_no_archive(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho new\n"})
        installer = _installer(tmp_path, _FakeClient(archive))
        previous = installer.tools_dir / "subfinder" / "subfinder"
        previous.parent.mkdir(parents=True)
        previous.write_bytes(b"#!/bin/sh\necho old\n")

        with pytest.raises(ChecksumError, match="tools.lock has"):
            installer.install_locked(_spec(), "1.0.0", _locked(_SUBFINDER_ZIP, archive, sha256="0" * 64))

        assert previous.read_bytes() == b"#!/bin/sh\necho old\n"
        assert not (installer.tools_dir / _SUBFINDER_ZIP).exists()


class TestChecksumFor:
    """checksums.txt lines are `<sha256>  [*][dir/]<file name>`; the name must match exactly."""

    def test_the_exact_name_wins_over_a_longer_name_ending_the_same(self) -> None:
        listing = f"{'0' * 64}  mytool_1.0.0_linux_amd64.zip\n{'a' * 64}  tool_1.0.0_linux_amd64.zip\n"

        assert checksum_for(listing, "tool_1.0.0_linux_amd64.zip") == "a" * 64

    def test_binary_mode_marker_and_directory_are_accepted(self) -> None:
        assert checksum_for(f"{'b' * 64} *dist/tool.zip\n", "tool.zip") == "b" * 64

    def test_uppercase_hex_is_normalised(self) -> None:
        assert checksum_for(f"{'C' * 64}  tool.zip\n", "tool.zip") == "c" * 64

    def test_no_entry_is_none(self) -> None:
        assert checksum_for(f"{'0' * 64}  other.zip\n", "tool.zip") is None

    def test_a_non_sha256_entry_is_none(self) -> None:
        assert checksum_for(f"{'d' * 128}  tool.zip\n", "tool.zip") is None


def test_missing_binary_message_mentions_blocked_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tools_dir = tmp_path / "tools_bin"
    tools_dir.mkdir()
    blocked = tools_dir / "naabu.exe"
    blocked.write_bytes(b"blocked")
    monkeypatch.setattr("cyberfw.manager.verify.is_executable", lambda _: False)

    from cyberfw.manager.verify import ensure_binary

    with pytest.raises(ToolNotFoundError, match="downloaded but its executable could not be read"):
        ensure_binary(tools_dir, "naabu", "naabu")


def test_ensure_binary_scans_the_tool_dir_not_a_siblings_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Resolving one tool must not walk another's tree (tools_bin/chromium/'s many files)."""
    tools = tmp_path / "tools_bin"
    nested = tools / "subfinder" / "subfinder_1.0.0_linux"
    nested.mkdir(parents=True)
    exe = nested / "subfinder"
    exe.write_text("#!/usr/bin/env bash\ntrue\n", encoding="utf-8")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    sibling = tools / "chromium"
    sibling.mkdir()
    for i in range(30):
        (sibling / f"f{i}").write_text("x", encoding="utf-8")

    scanned: list[Path] = []
    real_rglob = Path.rglob

    def spy(self: Path, pattern: str, **kwargs: object):  # type: ignore[no-untyped-def]
        scanned.append(Path(self))
        return real_rglob(self, pattern, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "rglob", spy)
    found = ensure_binary(tools, "subfinder", "subfinder")

    assert found == exe
    assert tools not in scanned, "the whole tools_bin tree was walked"
    assert tools / "subfinder" in scanned


def test_ensure_binary_still_finds_a_binary_of_the_flat_layout(tmp_path: Path) -> None:
    """No tools_bin/<name>/ of its own: the whole tree is still searched."""
    tools = tmp_path / "tools_bin"
    (tools / "legacy").mkdir(parents=True)
    exe = tools / "legacy" / "naabu"
    exe.write_text("#!/usr/bin/env bash\ntrue\n", encoding="utf-8")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)

    assert ensure_binary(tools, "naabu", "naabu") == exe


def test_ensure_binary_skips_an_install_leftover_inside_the_tool_dir(tmp_path: Path) -> None:
    """The scoped scan honours install leftovers like the whole-tree one does."""
    tools = tmp_path / "tools_bin"
    leftover = tools / "subfinder" / ".old" / "subfinder"
    leftover.parent.mkdir(parents=True)
    leftover.write_text("#!/usr/bin/env bash\ntrue\n", encoding="utf-8")
    leftover.chmod(leftover.stat().st_mode | stat.S_IEXEC)
    real = tools / "subfinder" / "bin" / "subfinder"
    real.parent.mkdir()
    real.write_text("#!/usr/bin/env bash\ntrue\n", encoding="utf-8")
    real.chmod(real.stat().st_mode | stat.S_IEXEC)

    assert ensure_binary(tools, "subfinder", "subfinder") == real


class TestArchiveSizeLimit:
    def test_limit_is_the_value_the_installer_was_given(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``Settings.max_archive_size`` must reach the installer; it used to read a private
        ``CYBERFW_MAX_ARCHIVE`` env var instead, so the documented setting was silently ignored."""
        monkeypatch.delenv("CYBERFW_MAX_ARCHIVE", raising=False)
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\n" + b"x" * 100})
        installer = _installer(tmp_path, _FakeClient(archive), max_archive_size=16)

        with pytest.raises(DownloadError, match="limit 16"):
            _install(installer, _spec(), archive, _SUBFINDER_ZIP)

    def test_archive_within_limit_installs(self, tmp_path: Path) -> None:
        payload = b"#!/bin/sh\necho ok\n"
        archive = _zip_bytes({"subfinder": payload})
        installer = _installer(tmp_path, _FakeClient(archive), max_archive_size=len(payload))

        assert _install(installer, _spec(), archive, _SUBFINDER_ZIP).binary.read_bytes() == payload


class TestToolsDirLayout:
    """Every tool lives in ``tools_bin/<tool>/``; nothing but those directories (and the
    install-state files ToolManager keeps) may accumulate at the top level."""

    def test_archive_members_land_in_a_per_tool_directory(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n", "README.md": b"docs", "LICENSE": b"mit"})
        installer = _installer(tmp_path, _FakeClient(archive))

        result = _install(installer, _spec(), archive, _SUBFINDER_ZIP)

        tool_dir = installer.tools_dir / "subfinder"
        assert result.binary == (tool_dir / "subfinder").resolve()
        assert (tool_dir / "README.md").is_file()
        assert not (installer.tools_dir / "README.md").exists(), "docs from one tool must not clobber another's"

    def test_downloaded_archive_is_removed_after_extraction(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n"})
        client = _FakeClient(archive)

        _install(_installer(tmp_path, client), _spec(), archive, _SUBFINDER_ZIP)

        assert not client.downloaded[0].exists()

    def test_corrupt_archive_is_not_left_behind_either(self, tmp_path: Path) -> None:
        archive = b"PK\x03\x04 definitely not a zip"
        client = _FakeClient(archive)

        with pytest.raises(DownloadError):
            _install(_installer(tmp_path, client), _spec(), archive, _SUBFINDER_ZIP)

        assert not client.downloaded[0].exists()

    def test_raw_asset_leaves_no_copy_under_its_release_name(self, tmp_path: Path) -> None:
        payload = b"#!/bin/sh\nraw executable"
        installer = _installer(tmp_path, _FakeClient(payload))
        spec = _spec(name="gowitness", binary="gowitness", archive="raw")

        result = _install(installer, spec, payload, "gowitness-1.0.0-linux-amd64")

        assert result.binary.parent == (installer.tools_dir / "gowitness").resolve()
        assert result.binary.stem == "gowitness"
        assert [p.name for p in installer.tools_dir.iterdir()] == ["gowitness"]

    def test_reinstall_discards_files_of_the_previous_version(self, tmp_path: Path) -> None:
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho new\n"})
        installer = _installer(tmp_path, _FakeClient(archive))
        old = installer.tools_dir / "subfinder" / "CHANGELOG-0.9.md"
        old.parent.mkdir(parents=True)
        old.write_text("old release notes", encoding="utf-8")

        _install(installer, _spec(), archive, _SUBFINDER_ZIP)

        assert not old.exists()

    def test_legacy_flat_layout_binary_gives_way_to_the_tool_directory(self, tmp_path: Path) -> None:
        """Older installs put the binary at ``tools_bin/subfinder`` — the very path that is
        now the tool's directory. Re-installing must replace the file with the directory."""
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho new\n"})
        installer = _installer(tmp_path, _FakeClient(archive))
        legacy = installer.tools_dir / "subfinder"
        legacy.write_bytes(b"#!/bin/sh\necho old\n")

        result = _install(installer, _spec(), archive, _SUBFINDER_ZIP)

        assert legacy.is_dir()
        assert result.binary == (legacy / "subfinder").resolve()
        assert result.binary.read_bytes() == b"#!/bin/sh\necho new\n"

    def test_stale_downloads_of_the_same_tool_are_removed(self, tmp_path: Path) -> None:
        """Earlier versions left the archive next to the binary; a re-install cleans up
        exactly those (they match this tool's asset patterns) and nothing else."""
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n"})
        installer = _installer(tmp_path, _FakeClient(archive))
        ours = installer.tools_dir / "subfinder_0.9.0_linux_amd64.zip"
        theirs = installer.tools_dir / "httpx_0.9.0_linux_amd64.zip"
        ours.write_bytes(b"old")
        theirs.write_bytes(b"not mine")

        _install(installer, _spec(asset_patterns=["subfinder_*_linux_amd64.zip"]), archive, _SUBFINDER_ZIP)

        assert not ours.exists()
        assert theirs.exists()


class _Offline(_FakeClient):
    """The connection drops halfway through the download."""

    def download(self, url: str, destination: Path, *, expected_size: int | None = None) -> None:
        destination.write_bytes(b"partial")
        raise DownloadError("connection reset")


class TestAFailedUpdateKeepsTheInstalledVersion:
    """The new version is unpacked and checked beside the installed one, and takes its
    place only once it holds the tool's executable: a failed download, a wrong hash, a
    damaged or oversized archive, one without the executable, or a failed swap leave
    the installed version — every file of it — as it was, and nothing behind."""

    _OLD = b"#!/bin/sh\necho old\n"

    def _installed(self, installer: ToolInstaller) -> Path:
        tool_dir = installer.tools_dir / "subfinder"
        tool_dir.mkdir(parents=True)
        (tool_dir / "subfinder").write_bytes(self._OLD)
        (tool_dir / "README.md").write_text("old docs", encoding="utf-8")
        return tool_dir

    def _assert_untouched(self, installer: ToolInstaller, tool_dir: Path) -> None:
        assert (tool_dir / "subfinder").read_bytes() == self._OLD
        assert (tool_dir / "README.md").read_text(encoding="utf-8") == "old docs"
        assert sorted(path.name for path in installer.tools_dir.iterdir()) == ["subfinder"]

    @pytest.mark.parametrize("failure", ["download", "hash", "corrupt", "no executable", "too big"])
    def test_a_failed_update_leaves_the_installed_version(self, tmp_path: Path, failure: str) -> None:
        archive = {
            "corrupt": b"PK\x03\x04 definitely not a zip",
            "no executable": _zip_bytes({"README.md": b"new docs"}),
            "too big": _zip_bytes({"subfinder": b"#!/bin/sh\n" + b"x" * 4096}),
        }.get(failure, _zip_bytes({"subfinder": b"#!/bin/sh\necho new\n"}))
        client = _Offline(archive) if failure == "download" else _FakeClient(archive)
        installer = _installer(tmp_path, client, max_archive_size=1024)
        tool_dir = self._installed(installer)
        locked = _locked(_SUBFINDER_ZIP, archive, sha256="0" * 64 if failure == "hash" else None)

        with pytest.raises((DownloadError, ChecksumError, ToolNotFoundError)):
            installer.install_locked(_spec(), "2.0.0", locked)

        self._assert_untouched(installer, tool_dir)

    def test_a_failed_swap_puts_the_installed_version_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho new\n"})
        installer = _installer(tmp_path, _FakeClient(archive))
        tool_dir = self._installed(installer)
        real_rename = Path.rename

        def refuse_the_new_version(self: Path, target: str | Path) -> Path:
            if self.name.startswith(".subfinder.staging-"):
                raise PermissionError(13, "Permission denied")
            return real_rename(self, target)

        monkeypatch.setattr(Path, "rename", refuse_the_new_version)

        with pytest.raises(DownloadError, match="could not put the new subfinder in place"):
            _install(installer, _spec(), archive, _SUBFINDER_ZIP)

        self._assert_untouched(installer, tool_dir)

    def test_an_update_while_the_old_version_runs_still_lands(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Windows will not delete a running exe, but renames it — and the directory
        around it: the old copy is parked, and it never shadows the new one."""
        archive = _zip_bytes({"naabu.exe": b"#!/bin/sh\necho new\n"})
        installer = _installer(tmp_path, _FakeClient(archive), Mapping("windows", "amd64"))
        running = installer.tools_dir / "naabu" / "naabu.exe"
        running.parent.mkdir(parents=True)
        running.write_bytes(b"running")
        real_unlink = Path.unlink

        def in_use(self: Path, missing_ok: bool = False) -> None:
            if self.is_file() and self.read_bytes() == b"running":
                raise PermissionError(32, "The process cannot access the file because it is being used")
            real_unlink(self, missing_ok=missing_ok)

        monkeypatch.setattr(Path, "unlink", in_use)
        spec = _spec(name="naabu", binary="naabu", asset_patterns=["*windows*amd64*"])

        result = _install(installer, spec, archive, "naabu_2.0.0_windows_amd64.zip")

        assert result.binary == running.resolve()
        assert result.binary.read_bytes() == b"#!/bin/sh\necho new\n"
        assert ensure_binary(installer.tools_dir, "naabu", "naabu") == running

    def test_an_interrupted_swap_puts_the_installed_version_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho new\n"})
        installer = _installer(tmp_path, _FakeClient(archive))
        tool_dir = self._installed(installer)
        real_rename = Path.rename

        def interrupted(self: Path, target: str | Path) -> Path:
            if self.name.startswith(".subfinder.staging-"):
                raise KeyboardInterrupt
            return real_rename(self, target)

        monkeypatch.setattr(Path, "rename", interrupted)

        with pytest.raises(KeyboardInterrupt):
            _install(installer, _spec(), archive, _SUBFINDER_ZIP)

        self._assert_untouched(installer, tool_dir)

    def test_a_swap_that_cannot_be_undone_reports_why_it_failed_and_keeps_the_old_copy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\necho new\n"})
        installer = _installer(tmp_path, _FakeClient(archive))
        self._installed(installer)
        real_rename = Path.rename

        def stuck(self: Path, target: str | Path) -> Path:
            if self.name.startswith((".subfinder.staging-", ".subfinder.previous-")):
                raise PermissionError(13, "Permission denied")
            return real_rename(self, target)

        monkeypatch.setattr(Path, "rename", stuck)

        with pytest.raises(DownloadError, match="could not put the new subfinder in place"):
            _install(installer, _spec(), archive, _SUBFINDER_ZIP)

        aside = list(installer.tools_dir.glob(".subfinder.previous-*"))
        assert len(aside) == 1 and (aside[0] / "subfinder").read_bytes() == self._OLD

    def test_an_installed_version_left_aside_by_a_cut_short_install_is_put_back_not_deleted(
        self, tmp_path: Path
    ) -> None:
        # An install killed between its two renames leaves the installed version in
        # ``.<tool>.previous-*`` and no ``<tool>/``: the next install puts it back first,
        # so even if that one fails too, the tool is there.
        archive = b"PK\x03\x04 definitely not a zip"
        installer = _installer(tmp_path, _FakeClient(archive))
        tool_dir = self._installed(installer)
        tool_dir.rename(installer.tools_dir / ".subfinder.previous-0badc0de")

        with pytest.raises(DownloadError):
            _install(installer, _spec(), archive, _SUBFINDER_ZIP)

        self._assert_untouched(installer, tool_dir)


class TestInstallLeftoversAreNeverTheTool:
    """A ``.<tool>.staging-*`` or ``.<tool>.previous-*`` directory holds a copy of the
    binary while an install runs, or after one was cut short: it is never the tool."""

    @staticmethod
    def _binary(directory: Path) -> Path:
        directory.mkdir(parents=True)
        path = directory / ("naabu.exe" if os.name == "nt" else "naabu")
        path.write_bytes(b"#!/bin/sh\necho hi\n")
        path.chmod(0o755)
        return path

    def test_the_installed_binary_wins_over_install_leftovers(self, tmp_path: Path) -> None:
        tools = tmp_path / "tools_bin"
        self._binary(tools / ".naabu.staging-1a2b3c4d")
        self._binary(tools / ".naabu.previous-5e6f7a8b")
        installed = self._binary(tools / "naabu")

        assert ensure_binary(tools, "naabu", "naabu") == installed

    def test_leftovers_alone_are_no_installed_tool(self, tmp_path: Path) -> None:
        tools = tmp_path / "tools_bin"
        self._binary(tools / ".naabu.staging-1a2b3c4d")

        with pytest.raises(ToolNotFoundError):
            ensure_binary(tools, "naabu", "naabu")
        assert not binary_on_disk(tools, "naabu", "naabu")
