"""cyberfw.core.workspace: the registry in use, the manager over it and the lock next to it."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberfw.config import Settings, load_settings
from cyberfw.core.workspace import is_packaged, open_manager, registry_path


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "registry.yaml").write_text(
        "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: subfinder\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_the_registry_in_the_current_directory_comes_first(workspace: Path) -> None:
    assert registry_path() == workspace / "registry.yaml"


def test_the_manager_keeps_the_lock_next_to_the_registry_in_use(workspace: Path) -> None:
    manager = open_manager(Settings(root_dir=workspace))
    try:
        assert manager.registry.names() == ["subfinder"]
        assert manager.lock_path == workspace / "tools.lock"
    finally:
        manager.close()


def test_a_checkout_file_is_not_a_packaged_copy(workspace: Path) -> None:
    assert not is_packaged(workspace / "tools.lock")


class TestTheWorkspaceTheSettingsName:
    """``Settings(root_dir=...)`` and ``CYBERFW_ROOT_DIR`` name a workspace: its registry
    and its lock are the ones in use, whichever directory cyberfw is started from."""

    @staticmethod
    def _workspace(path: Path, tool: str | None) -> Path:
        path.mkdir()
        if tool is not None:
            (path / "registry.yaml").write_text(f"{tool}:\n  repo: org/{tool}\n  asset_patterns: []\n", encoding="utf-8")
        return path

    @staticmethod
    def _opened(settings: Settings) -> tuple[list[str], Path]:
        manager = open_manager(settings)
        try:
            return manager.registry.names(), manager.lock_path
        finally:
            manager.close()

    def test_settings_naming_another_workspace_use_its_registry_and_lock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        here = self._workspace(tmp_path / "a", "only-in-a")
        there = self._workspace(tmp_path / "b", "only-in-b")
        monkeypatch.chdir(here)

        assert self._opened(Settings(root_dir=there)) == (["only-in-b"], there / "tools.lock")

    def test_the_environment_naming_another_workspace_does_the_same(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        here = self._workspace(tmp_path / "a", "only-in-a")
        there = self._workspace(tmp_path / "b", "only-in-b")
        monkeypatch.chdir(here)
        monkeypatch.setenv("CYBERFW_ROOT_DIR", str(there))

        assert self._opened(load_settings()) == (["only-in-b"], there / "tools.lock")

    def test_a_workspace_with_no_registry_never_borrows_the_current_directory_s(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # It runs on the registry cyberfw ships (the checkout's here, the wheel's
        # when installed), with the lock that belongs to that one.
        here = self._workspace(tmp_path / "a", "only-in-a")
        there = self._workspace(tmp_path / "b", None)
        monkeypatch.chdir(here)

        names, lock = self._opened(Settings(root_dir=there))

        assert "only-in-a" not in names and "subfinder" in names
        assert lock.parent not in (here, there)
