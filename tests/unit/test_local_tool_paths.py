"""Configured local tool paths belong to the workspace, not the caller's CWD."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from cyberfw.config import Settings
from cyberfw.core.workspace import tool_state
from cyberfw.exceptions import ToolNotFoundError
from cyberfw.manager import ToolManager
from cyberfw.manager.registry import ToolRegistry, ToolSpec


@pytest.fixture
def local_tool(tmp_path: Path) -> tuple[ToolManager, Path]:
    workspace = tmp_path / "workspace with spaces"
    binary = workspace / "local" / "probe.py"
    binary.parent.mkdir(parents=True)
    binary.write_text("print('workspace tool')\n", encoding="utf-8")
    spec = ToolSpec(name="probe", source="local", path="local/probe.py")
    manager = ToolManager(Settings(root_dir=workspace), ToolRegistry({"probe": spec}))
    return manager, binary


@pytest.mark.parametrize("in_workspace", [True, False], ids=["workspace-cwd", "other-cwd"])
def test_relative_binary_resolves_and_runs_from_either_directory(
    local_tool: tuple[ToolManager, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    in_workspace: bool,
) -> None:
    manager, binary = local_tool
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.chdir(manager.settings.root_dir if in_workspace else other)

    resolved = manager.binary_path("probe")

    assert resolved.is_absolute()
    assert resolved == binary.resolve()
    # The harmless Python fixture runs by its resolved filename, with the same
    # CWD a scheduled invocation or a caller outside the workspace would have.
    done = subprocess.run([sys.executable, str(resolved)], capture_output=True, text=True, check=True)
    assert done.stdout.strip() == "workspace tool"


def test_same_named_binary_in_cwd_cannot_shadow_the_workspace_binary(
    local_tool: tuple[ToolManager, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager, binary = local_tool
    other = tmp_path / "other"
    shadow = other / "local" / "probe.py"
    shadow.parent.mkdir(parents=True)
    shadow.write_text("print('wrong tool')\n", encoding="utf-8")
    monkeypatch.chdir(other)

    assert manager.binary_path("probe") == binary.resolve()


def test_relative_local_tool_is_ready_outside_the_workspace(
    local_tool: tuple[ToolManager, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager, _ = local_tool
    monkeypatch.chdir(tmp_path)

    assert manager.is_installed("probe")
    assert tool_state(manager, "probe", manager.settings.tools_dir) == "ready"


def test_missing_workspace_binary_does_not_fall_back_to_a_cwd_copy_or_path(
    local_tool: tuple[ToolManager, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager, binary = local_tool
    binary.unlink()
    shadow = tmp_path / "local" / "probe.py"
    shadow.parent.mkdir()
    shadow.write_text("pass\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("cyberfw.manager.find_in_path", lambda _: pytest.fail("explicit path must not fall back to PATH"))

    with pytest.raises(ToolNotFoundError, match="configured path does not exist"):
        manager.binary_path("probe")
    assert not manager.is_installed("probe")


def test_absolute_configured_path_keeps_its_meaning_outside_the_workspace(
    local_tool: tuple[ToolManager, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager, _ = local_tool
    external = tmp_path / "external.py"
    external.write_text("pass\n", encoding="utf-8")
    manager.registry.require("probe").path = str(external)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("cyberfw.manager.find_in_path", lambda _: pytest.fail("explicit path must not fall back to PATH"))

    assert manager.binary_path("probe") == external


def test_an_unconfigured_local_tool_still_uses_path_lookup(
    local_tool: tuple[ToolManager, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    manager, binary = local_tool
    spec = manager.registry.require("probe")
    spec.path = None
    monkeypatch.setattr("cyberfw.manager.find_in_path", lambda command: str(binary) if command == "probe" else None)

    assert manager.binary_path("probe") == binary
