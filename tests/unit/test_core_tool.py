"""One tool on its own in cyberfw.core: checked, run, kept — against the CLI tests' fake tools."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from cyberfw.config import Settings
from cyberfw.core.events import RunObserver, StepEvent
from cyberfw.core.sessions import open_session
from cyberfw.core.tool_run import check_tool, keep_tool_run, run_tool_once
from cyberfw.core.workspace import open_manager
from cyberfw.exceptions import RegistryError, ToolNotFoundError
from cyberfw.manager import ToolManager
from cyberfw.pipeline.schemas import ToolRecord

from .test_cli import _write_fake_binaries, _write_registry

pytestmark = pytest.mark.usefixtures("prints_nothing")


class Recorder(RunObserver):
    def __init__(self) -> None:
        self.steps: list[str] = []
        self.records: list[ToolRecord] = []

    def on_step(self, event: StepEvent) -> None:
        self.steps.append(f"{event.step}:{event.kind}")

    def on_record(self, record: ToolRecord) -> None:
        self.records.append(record)


@pytest.fixture
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    _write_fake_binaries(tmp_path / "tools_bin")
    _write_registry(tmp_path)
    monkeypatch.chdir(tmp_path)
    return Settings(root_dir=tmp_path)


@pytest.fixture
def manager(settings: Settings) -> Iterator[ToolManager]:
    manager = open_manager(settings)
    yield manager
    manager.close()


def test_a_target_the_tool_cannot_take_is_a_value_error(manager: ToolManager) -> None:
    with pytest.raises(ValueError, match="local repository directory"):
        check_tool(manager, "gitleaks", "https://utm.md/")


def test_an_unknown_tool_is_a_registry_error(manager: ToolManager) -> None:
    with pytest.raises(RegistryError):
        check_tool(manager, "bogus", "example.com")


def test_a_tool_without_its_binary_is_not_found(settings: Settings, manager: ToolManager) -> None:
    (settings.tools_dir / "subfinder").unlink()

    with pytest.raises(ToolNotFoundError):
        check_tool(manager, "subfinder", "example.com")


def test_a_run_returns_its_records_between_scan_events(settings: Settings, manager: ToolManager) -> None:
    session = open_session(settings.reports_dir, kind="run", name="subfinder", session=None, stream=False)
    seen = Recorder()

    ran = run_tool_once("subfinder", settings=settings, manager=manager, target="example.com",
                        session=session, observer=seen)

    assert ran.node.ok and [record.target for record in ran.records] == ["sub.example.com"]
    assert seen.steps == ["scan:start", "scan:done"] and seen.records == ran.records
    assert ran.started_at <= ran.finished_at
    assert not session.dir.exists()  # undecided: nothing written yet


def test_without_parsing_every_line_is_a_raw_record(settings: Settings, manager: ToolManager) -> None:
    session = open_session(settings.reports_dir, kind="run", name="subfinder", session=None, stream=False)

    ran = run_tool_once("subfinder", settings=settings, manager=manager, target="example.com",
                        parse=False, session=session, observer=RunObserver())

    assert [record.raw for record in ran.records] == ['{"host": "sub.example.com", "source": "stub"}']


def test_keeping_an_undecided_run_archives_its_records_and_writes_reports(
    settings: Settings, manager: ToolManager
) -> None:
    session = open_session(settings.reports_dir, kind="run", name="subfinder", session="later", stream=False)
    ran = run_tool_once("subfinder", settings=settings, manager=manager, target="example.com",
                        session=session, observer=RunObserver())

    reports = keep_tool_run(ran, settings=settings, manager=manager)

    assert sorted(reports) == ["html", "json"] and all(path.is_file() for path in reports.values())
    archived = list(session.dir.glob("*.jsonl"))
    assert len(archived) == 1 and len(archived[0].read_text(encoding="utf-8").splitlines()) == 1


def test_a_streamed_run_is_not_archived_twice(settings: Settings, manager: ToolManager) -> None:
    session = open_session(settings.reports_dir, kind="run", name="subfinder", session="now", stream=True)
    ran = run_tool_once("subfinder", settings=settings, manager=manager, target="example.com",
                        session=session, observer=RunObserver())

    keep_tool_run(ran, settings=settings, manager=manager)

    archived = list(session.dir.glob("*.jsonl"))
    assert len(archived) == 1 and len(archived[0].read_text(encoding="utf-8").splitlines()) == 1
