"""cyberfw.core.workspace: the registry in use, the manager over it and the lock next to it."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberfw.config import Settings
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
