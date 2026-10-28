"""Gitleaks must never silently discard a requested directory list."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cyberfw import api
from cyberfw.cli import app
from cyberfw.config import Settings
from cyberfw.manager import ToolManager
from cyberfw.manager.registry import ToolRegistry, ToolSpec
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.plugin import ToolContext
from cyberfw.tools.gitleaks import GitleaksTool


@pytest.fixture
def manager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ToolManager:
    spec = ToolSpec(name="gitleaks", source="local", path=sys.executable)
    settings = Settings(root_dir=tmp_path, animations=False, log_to_file=False)
    result = ToolManager(settings, ToolRegistry({"gitleaks": spec}))
    monkeypatch.setattr(api, "open_manager", lambda _settings: result)
    return result


@pytest.fixture
def commands(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []

    async def run(cmd: list[str], **_kwargs: object) -> list[ToolRecord]:
        calls.append(cmd)
        return []

    monkeypatch.setattr("cyberfw.pipeline.engine.run_stage", run)
    return calls


@pytest.mark.parametrize("with_target", [False, True], ids=["list-only", "target-and-list"])
def test_adapter_rejects_a_nonempty_directory_list(manager: ToolManager, with_target: bool) -> None:
    adapter = GitleaksTool(manager.spec("gitleaks"), Path(sys.executable))
    ctx = ToolContext(target=str(manager.settings.root_dir) if with_target else None, inputs=["repo-one", "repo-two"])

    with pytest.raises(ValueError, match="--list"):
        adapter.build_cmd(ctx)


@pytest.mark.parametrize("with_target", [False, True], ids=["list-only", "target-and-list"])
def test_api_reports_the_unsupported_list_without_starting_a_process(
    manager: ToolManager, commands: list[list[str]], with_target: bool
) -> None:
    outcome = api.run_tool(
        "gitleaks", inputs=[str(manager.settings.root_dir)], settings=manager.settings,
        target=str(manager.settings.root_dir) if with_target else None,
    )

    assert not outcome.succeeded
    assert outcome.exit_code() == 1
    assert "--list" in (outcome.result.nodes[0].error or "")
    assert outcome.result.records == []
    assert commands == []


def test_cli_reports_the_unsupported_list_without_starting_a_process(
    manager: ToolManager, commands: list[list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("cyberfw.cli.scan._setup", lambda **_kwargs: manager.settings)
    list_file = manager.settings.root_dir / "directories.txt"
    list_file.write_text(str(manager.settings.root_dir) + "\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["run", "gitleaks", "--list", str(list_file), "--no-save"])

    assert result.exit_code == 1
    assert "--list" in result.output
    assert "--target" in result.output
    assert commands == []


def test_a_single_explicit_directory_still_runs(manager: ToolManager, commands: list[list[str]]) -> None:
    target = str(manager.settings.root_dir)

    outcome = api.run_tool("gitleaks", target=target, settings=manager.settings)

    assert outcome.succeeded
    assert len(commands) == 1
    assert commands[0][1:3] == ["dir", target]


def test_an_empty_list_still_runs_nothing(manager: ToolManager, commands: list[list[str]]) -> None:
    outcome = api.run_tool("gitleaks", inputs=[], settings=manager.settings)

    assert outcome.succeeded
    assert outcome.result.records == []
    assert commands == []
