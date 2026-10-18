"""Tests for the ToolManager facade: installs from tools.lock, install bookkeeping, settings plumbing."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

from cyberfw.config import Settings
from cyberfw.exceptions import (
    ChecksumError,
    CyberfwError,
    DownloadError,
    LockError,
    RegistryError,
    ToolNotFoundError,
)
from cyberfw.manager import ToolManager
from cyberfw.manager.github_client import GitHubRelease, ReleaseAsset
from cyberfw.manager.lock import (
    LockedAsset,
    LockedTool,
    ToolLock,
    read_lock,
    selection_fingerprint,
    write_lock,
)
from cyberfw.manager.platform_map import Mapping
from cyberfw.manager.registry import load_registry


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buffer.getvalue()


def _release(tag: str, archive: bytes) -> GitHubRelease:
    """One linux/amd64 asset of ``archive``, carrying the digest GitHub would report."""
    name = f"subfinder_{tag.lstrip('v')}_linux_amd64.zip"
    asset = ReleaseAsset(name, f"https://example.test/{name}", len(archive), hashlib.sha256(archive).hexdigest())
    return GitHubRelease(tag=tag, assets=[asset], checksums_url=None)


class _FakeClient:
    """GitHub stand-in: one current release; every download serves ``archive_bytes``."""

    def __init__(self, release: GitHubRelease, archive_bytes: bytes) -> None:
        self.current = release
        self.archive_bytes = archive_bytes
        self.release_calls = 0
        self.downloads = 0

    def release(self, owner: str, repo: str, tag: str) -> GitHubRelease:
        self.release_calls += 1
        return self.current

    def download(self, url: str, destination: Path, *, expected_size: int | None = None) -> None:
        self.downloads += 1
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.archive_bytes)

    def fetch_text(self, url: str) -> str:
        return ""

    def close(self) -> None:
        pass


class _PartlyBroken(_FakeClient):
    """Resolves every repo but ``broken``, which GitHub does not know."""

    def release(self, owner: str, repo: str, tag: str) -> GitHubRelease:
        if repo == "broken":
            raise DownloadError(f"Repository not found: {owner}/{repo}")
        return super().release(owner, repo, tag)


_LATEST = "subfinder:\n  repo: org/subfinder\n  asset_patterns: ['*linux*amd64*']\n  binary: subfinder\n"
_PINNED = _LATEST + "  version: v1.0.0\n"
_BROKEN = "broken:\n  repo: org/broken\n  asset_patterns: ['*linux*amd64*']\n  binary: broken\n"


def _manager_with(
    tmp_path: Path, registry_yaml: str = _LATEST, archive: bytes | None = None, **settings: object
) -> tuple[ToolManager, _FakeClient]:
    archive = archive if archive is not None else _zip_bytes({"subfinder": b"#!/bin/sh\necho ok\n"})
    (tmp_path / "registry.yaml").write_text(registry_yaml, encoding="utf-8")
    client = _FakeClient(_release("v1.0.0", archive), archive)
    manager = ToolManager(
        Settings(root_dir=tmp_path, **settings),  # type: ignore[arg-type]
        load_registry(tmp_path / "registry.yaml"),
        Mapping("linux", "amd64"),
    )
    manager.settings.ensure_dirs()
    manager._client = client  # type: ignore[assignment]
    return manager, client


def _use_registry(manager: ToolManager, tmp_path: Path, registry_yaml: str) -> None:
    (tmp_path / "registry.yaml").write_text(registry_yaml, encoding="utf-8")
    manager.registry = load_registry(tmp_path / "registry.yaml")


class TestInstall:
    def test_max_archive_size_setting_reaches_the_installer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("CYBERFW_MAX_ARCHIVE", raising=False)
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\n" + b"x" * 100})
        manager, _ = _manager_with(tmp_path, archive=archive, max_archive_size=16)

        with pytest.raises(DownloadError, match="limit 16"):
            manager.install("subfinder")
        assert manager.install_state("subfinder") is None

    def test_successful_install_records_state(self, tmp_path: Path) -> None:
        manager, client = _manager_with(tmp_path)

        result = manager.install("subfinder")

        state = manager.install_state("subfinder")
        assert state is not None
        assert state["version"] == "1.0.0"
        assert state["binary"] == str(result.binary.resolve())
        assert state["sha256"] == hashlib.sha256(client.archive_bytes).hexdigest()
        assert manager.is_installed("subfinder")


class TestLocalTool:
    """A `source: local` tool is resolved from PATH / an explicit path, never downloaded."""

    @staticmethod
    def _manager(tmp_path: Path, entry: str = "nmap:\n  source: local\n  binary: nmap\n") -> ToolManager:
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(entry, encoding="utf-8")
        manager = ToolManager(Settings(root_dir=tmp_path), load_registry(registry_path), Mapping("linux", "amd64"))
        manager.settings.ensure_dirs()
        return manager

    def test_on_path_is_installed_and_resolves(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        manager = self._manager(tmp_path)
        monkeypatch.setattr(
            "cyberfw.manager.find_in_path", lambda cmd: "/usr/bin/nmap" if cmd == "nmap" else None
        )

        assert manager.is_installed("nmap") is True
        assert manager.binary_path("nmap") == Path("/usr/bin/nmap")

    def test_absent_from_path_is_not_installed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        manager = self._manager(tmp_path)
        monkeypatch.setattr("cyberfw.manager.find_in_path", lambda cmd: None)

        assert manager.is_installed("nmap") is False
        with pytest.raises(ToolNotFoundError):
            manager.binary_path("nmap")

    def test_an_explicit_path_is_used_over_the_path_lookup(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        exe = tmp_path / "nmap"
        exe.write_text("#!/bin/sh\n", encoding="utf-8")
        manager = self._manager(tmp_path, f"nmap:\n  source: local\n  binary: nmap\n  path: {exe}\n")
        monkeypatch.setattr(
            "cyberfw.manager.find_in_path", lambda cmd: pytest.fail("an explicit path must not fall back to PATH")
        )

        assert manager.binary_path("nmap") == exe

    def test_install_refuses_a_local_tool(self, tmp_path: Path) -> None:
        manager = self._manager(tmp_path)

        with pytest.raises(CyberfwError, match="package manager"):
            manager.install("nmap")

    def test_install_all_skips_local_tools(self, tmp_path: Path) -> None:
        manager, _ = _manager_with(tmp_path)  # a github subfinder
        _use_registry(manager, tmp_path, _LATEST + "nmap:\n  source: local\n  binary: nmap\n")

        results = manager.install_all()  # must not try to download nmap

        assert [r.spec.name for r in results] == ["subfinder"]


class TestSkipUpToDate:
    def test_second_install_of_the_same_version_downloads_nothing(self, tmp_path: Path) -> None:
        manager, client = _manager_with(tmp_path)
        first = manager.install("subfinder")
        second = manager.install("subfinder")

        assert client.downloads == 1
        assert first.up_to_date is False
        assert second.up_to_date is True
        assert second.binary == first.binary and second.version == "1.0.0"

    def test_force_reinstalls(self, tmp_path: Path) -> None:
        manager, client = _manager_with(tmp_path)
        manager.install("subfinder")
        result = manager.install("subfinder", force=True)

        assert client.downloads == 2
        assert result.up_to_date is False

    @pytest.mark.parametrize("registry_yaml", [_LATEST, _PINNED], ids=["latest", "pinned"])
    def test_a_locked_installed_tool_needs_no_network(self, tmp_path: Path, registry_yaml: str) -> None:
        manager, client = _manager_with(tmp_path, registry_yaml)
        manager.install("subfinder")
        calls_after_first = client.release_calls

        result = manager.install("subfinder")

        assert result.up_to_date is True
        assert client.release_calls == calls_after_first

    def test_missing_binary_is_reinstalled_despite_matching_state(self, tmp_path: Path) -> None:
        manager, client = _manager_with(tmp_path, _PINNED)
        first = manager.install("subfinder")
        first.binary.unlink()

        result = manager.install("subfinder")

        assert result.up_to_date is False
        assert client.downloads == 2

    def test_a_pre_lock_install_is_reinstalled_once_and_verified(self, tmp_path: Path) -> None:
        """1.x recorded no archive hash, so such an install was never checked against the
        lock: it is downloaded and verified once, then counts as up to date."""
        manager, client = _manager_with(tmp_path)
        manager.install("subfinder")
        state_path = tmp_path / "tools_bin" / ".subfinder.install.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        del state["sha256"]
        state_path.write_text(json.dumps(state), encoding="utf-8")

        second = manager.install("subfinder")
        third = manager.install("subfinder")

        assert second.up_to_date is False and third.up_to_date is True
        assert client.downloads == 2


class TestLockedInstall:
    def test_the_lock_defaults_to_the_root_dir(self, tmp_path: Path) -> None:
        manager, _ = _manager_with(tmp_path)

        assert manager.lock_path == tmp_path / "tools.lock"

    def test_a_tool_missing_from_the_lock_is_added_and_written(self, tmp_path: Path) -> None:
        manager, client = _manager_with(tmp_path)

        manager.install("subfinder")

        lock = read_lock(tmp_path / "tools.lock")
        assert lock is not None
        entry = lock.tools["subfinder"]
        assert entry.repo == "org/subfinder" and entry.tag == "v1.0.0"
        assert entry.assets["linux/amd64"].sha256 == hashlib.sha256(client.archive_bytes).hexdigest()

    def test_an_explicit_lock_path_is_used(self, tmp_path: Path) -> None:
        manager, client = _manager_with(tmp_path)
        pins = tmp_path / "pins"
        pins.mkdir()
        other = ToolManager(manager.settings, manager.registry, manager.mapping, lock_path=pins / "tools.lock")
        other._client = client  # type: ignore[assignment]

        other.install("subfinder")

        assert (pins / "tools.lock").is_file()
        assert not (tmp_path / "tools.lock").exists()

    def test_install_never_rewrites_an_existing_entry(self, tmp_path: Path) -> None:
        manager, client = _manager_with(tmp_path)
        manager.install("subfinder")
        before = (tmp_path / "tools.lock").read_bytes()
        client.current = _release("v2.0.0", client.archive_bytes)  # upstream moved on
        (tmp_path / "tools_bin" / ".subfinder.install.json").unlink()

        result = manager.install("subfinder")

        assert result.version == "1.0.0"
        assert (tmp_path / "tools.lock").read_bytes() == before
        assert client.release_calls == 1

    def test_a_newer_release_waits_for_lock_upgrade(self, tmp_path: Path) -> None:
        manager, client = _manager_with(tmp_path)
        manager.install("subfinder")
        newer = _zip_bytes({"subfinder": b"#!/bin/sh\necho v2\n"})
        client.current, client.archive_bytes = _release("v2.0.0", newer), newer

        assert manager.install("subfinder").up_to_date is True  # still the locked 1.0.0
        update = manager.update_lock(["subfinder"], upgrade=True)
        result = manager.install("subfinder")

        assert [(c.before, c.after, c.change) for c in update.changes] == [("v1.0.0", "v2.0.0", "upgraded")]
        assert result.version == "2.0.0" and result.up_to_date is False

    def test_a_stale_entry_is_an_error_not_a_silent_reinstall(self, tmp_path: Path) -> None:
        manager, _ = _manager_with(tmp_path)
        manager.install("subfinder")
        _use_registry(manager, tmp_path, _LATEST + "  version: v2.0.0\n")

        with pytest.raises(LockError, match="run `cyberfw lock`"):
            manager.install("subfinder")

    def test_no_locked_asset_for_this_platform(self, tmp_path: Path) -> None:
        manager, _ = _manager_with(tmp_path)
        windows = LockedAsset(
            name="subfinder_1.0.0_windows_amd64.zip",
            url="https://example.test/subfinder_1.0.0_windows_amd64.zip",
            sha256="a" * 64,
            source="digest",
        )
        entry = LockedTool(
            repo="org/subfinder",
            tag="v1.0.0",
            selection=selection_fingerprint(manager.spec("subfinder")),
            assets={"windows/amd64": windows},
        )
        write_lock(tmp_path / "tools.lock", ToolLock(tools={"subfinder": entry}))

        with pytest.raises(DownloadError, match="no locked asset for linux/amd64"):
            manager.install("subfinder")

    def test_a_registry_edit_to_asset_patterns_makes_install_ask_for_cyberfw_lock(self, tmp_path: Path) -> None:
        manager, _ = _manager_with(tmp_path)
        manager.install("subfinder")
        _use_registry(manager, tmp_path, _LATEST.replace("['*linux*amd64*']", "['subfinder_*_linux_amd64.zip']"))

        with pytest.raises(LockError, match="run `cyberfw lock`"):
            manager.install("subfinder")

    def test_a_hash_mismatch_fails_and_records_no_state(self, tmp_path: Path) -> None:
        manager, client = _manager_with(tmp_path)
        manager.update_lock()
        client.archive_bytes = _zip_bytes({"subfinder": b"#!/bin/sh\necho tampered\n"})

        with pytest.raises(ChecksumError, match="tools.lock has"):
            manager.install("subfinder")
        assert manager.install_state("subfinder") is None


class TestUpdateLock:
    def test_creates_the_lock_with_every_downloadable_tool(self, tmp_path: Path) -> None:
        manager, _ = _manager_with(tmp_path)

        update = manager.update_lock()

        assert update.written and update.path == tmp_path / "tools.lock"
        assert [(c.tool, c.before, c.after, c.change, c.sources) for c in update.changes] == [
            ("subfinder", None, "v1.0.0", "added", "digest")
        ]

    def test_a_second_run_changes_nothing_and_asks_github_nothing(self, tmp_path: Path) -> None:
        manager, client = _manager_with(tmp_path)
        manager.update_lock()
        before, calls = (tmp_path / "tools.lock").read_bytes(), client.release_calls

        update = manager.update_lock()

        assert not update.written
        assert [c.change for c in update.changes] == ["unchanged"]
        assert (tmp_path / "tools.lock").read_bytes() == before
        assert client.release_calls == calls

    def test_a_tool_gone_from_the_registry_is_dropped_only_without_names(self, tmp_path: Path) -> None:
        manager, _ = _manager_with(tmp_path)
        manager.update_lock()
        _use_registry(manager, tmp_path, "nmap:\n  source: local\n  binary: nmap\n")

        assert manager.update_lock(["nmap"]).changes == []  # named: no pruning; a local tool is skipped
        update = manager.update_lock()

        assert [(c.tool, c.change) for c in update.changes] == [("subfinder", "removed")]
        lock = read_lock(tmp_path / "tools.lock")
        assert lock is not None and lock.tools == {}

    def test_plain_lock_re_resolves_a_stale_entry(self, tmp_path: Path) -> None:
        manager, client = _manager_with(tmp_path)
        manager.update_lock()
        _use_registry(manager, tmp_path, _LATEST + "  version: v2.0.0\n")
        client.current = _release("v2.0.0", client.archive_bytes)

        update = manager.update_lock()

        assert [(c.before, c.after, c.change) for c in update.changes] == [("v1.0.0", "v2.0.0", "re-resolved")]

    def test_upgrade_refuses_a_changed_file_under_the_same_tag(self, tmp_path: Path) -> None:
        """Same tag, different bytes: upstream replaced a published asset — what the lock exists to catch."""
        manager, client = _manager_with(tmp_path)
        manager.update_lock()
        before = (tmp_path / "tools.lock").read_bytes()
        client.current = _release("v1.0.0", _zip_bytes({"subfinder": b"#!/bin/sh\necho replaced\n"}))

        update = manager.update_lock(upgrade=True)

        [change] = update.changes
        assert change.change == "failed" and "changed upstream" in change.error
        assert update.failed and not update.written
        assert (tmp_path / "tools.lock").read_bytes() == before

    @staticmethod
    def _x64_release(*builds: tuple[str, bytes]) -> GitHubRelease:
        """gitleaks-style `x64` names: the platform patterns miss them, so the registry decides."""
        return GitHubRelease(
            tag="v1.0.0",
            assets=[
                ReleaseAsset(name, f"https://example.test/{name}", len(data), hashlib.sha256(data).hexdigest())
                for name, data in builds
            ],
            checksums_url=None,
        )

    _X64 = "subfinder:\n  repo: org/subfinder\n  asset_patterns: ['subfinder_*_linux_x64.tar.gz']\n  binary: subfinder\n"

    @pytest.mark.parametrize("upgrade", [False, True], ids=["lock", "lock-upgrade"])
    def test_a_registry_edit_that_picks_another_file_re_resolves(self, tmp_path: Path, upgrade: bool) -> None:
        """The user's own asset_patterns edit changes which file a platform gets under the same
        tag: that is a re-resolve, never a "changed upstream" alarm."""
        manager, client = _manager_with(tmp_path, self._X64)
        client.current = self._x64_release(
            ("subfinder_1.0.0_linux_x64.tar.gz", b"tar build"), ("subfinder_1.0.0_linux_x64.zip", b"zip build")
        )
        manager.update_lock()
        _use_registry(manager, tmp_path, self._X64.replace(".tar.gz", ".zip"))

        update = manager.update_lock(upgrade=upgrade)

        [change] = update.changes
        assert (change.change, change.error) == ("re-resolved", "")
        lock = read_lock(tmp_path / "tools.lock")
        assert lock is not None
        assert lock.tools["subfinder"].assets["linux/amd64"].name == "subfinder_1.0.0_linux_x64.zip"

    def test_a_new_file_under_the_same_tag_is_refused_when_nothing_of_ours_changed(self, tmp_path: Path) -> None:
        """Same tag, same registry, same rules — yet a platform now gets another file: the release's
        asset list changed upstream."""
        registry = self._X64.replace("linux_x64.tar.gz", "linux_x64*")
        manager, client = _manager_with(tmp_path, registry)
        client.current = self._x64_release(("subfinder_1.0.0_linux_x64.tar.gz", b"tar build"))
        manager.update_lock()
        client.current = self._x64_release(
            ("subfinder_1.0.0_linux_x64.bin", b"planted"), ("subfinder_1.0.0_linux_x64.tar.gz", b"tar build")
        )

        update = manager.update_lock(upgrade=True)

        [change] = update.changes
        assert change.change == "failed" and "changed upstream" in change.error

    def test_a_replaced_file_is_refused_even_while_re_resolving(self, tmp_path: Path) -> None:
        """An edit that makes the entry stale must not open a window for a replaced same-name file."""
        manager, client = _manager_with(tmp_path, self._X64)
        client.current = self._x64_release(("subfinder_1.0.0_linux_x64.tar.gz", b"tar build"))
        manager.update_lock()
        _use_registry(manager, tmp_path, self._X64.replace("linux_x64.tar.gz", "linux_x64*"))
        client.current = self._x64_release(("subfinder_1.0.0_linux_x64.tar.gz", b"replaced upstream"))

        update = manager.update_lock()

        [change] = update.changes
        assert change.change == "failed" and "changed upstream" in change.error

    def test_a_tool_that_fails_to_resolve_is_reported_and_the_rest_written(self, tmp_path: Path) -> None:
        manager, client = _manager_with(tmp_path, _LATEST + _BROKEN)
        manager._client = _PartlyBroken(client.current, client.archive_bytes)  # type: ignore[assignment]

        update = manager.update_lock()

        assert {c.tool: c.change for c in update.changes} == {"broken": "failed", "subfinder": "added"}
        assert update.failed and update.written
        lock = read_lock(tmp_path / "tools.lock")
        assert lock is not None and set(lock.tools) == {"subfinder"}

    def test_a_lock_that_cannot_be_written_still_reports_the_changes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        manager, _ = _manager_with(tmp_path)

        def refuse(src: object, dst: object) -> None:
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr("cyberfw.manager.lock.os.replace", refuse)

        update = manager.update_lock()

        assert [c.change for c in update.changes] == ["added"]
        assert not update.written and update.failed
        assert "workspace" in update.error

    def test_tools_added_to_the_lock_by_installing_are_remembered(self, tmp_path: Path) -> None:
        """init and the launcher tell the user what they pinned; installing again adds nothing."""
        manager, _ = _manager_with(tmp_path)

        manager.install("subfinder")
        manager.install("subfinder")

        assert manager.added_to_lock == ["subfinder"]

    def test_an_unknown_name_is_a_registry_error(self, tmp_path: Path) -> None:
        manager, _ = _manager_with(tmp_path)

        with pytest.raises(RegistryError):
            manager.update_lock(["nope"])
