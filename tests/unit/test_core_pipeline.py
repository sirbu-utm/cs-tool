"""Preparing and running a pipeline in cyberfw.core, against the fake tools the CLI tests use."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from cyberfw.config import Settings
from cyberfw.core import scan
from cyberfw.core.events import Note, RunObserver, StepEvent
from cyberfw.core.scan import choose_wordlist, execute_pipeline, prepare_pipeline
from cyberfw.core.sessions import open_session
from cyberfw.core.workspace import open_manager
from cyberfw.exceptions import CyberfwError, RegistryError
from cyberfw.manager import ToolManager
from cyberfw.pipeline.engine import PipelineEngine, PipelineResult, StageEvent
from cyberfw.pipeline.schemas import ToolRecord

from .test_cli import _break_tool, _write_fake_binaries, _write_registry

pytestmark = pytest.mark.usefixtures("prints_nothing")


class Recorder(RunObserver):
    """Everything the run sends, in order, as short labels."""

    def __init__(self) -> None:
        self.log: list[str] = []
        self.records: list[ToolRecord] = []
        self.notes: list[Note] = []

    def on_stage(self, event: StageEvent) -> None:
        self.log.append(f"stage:{event.stage}:{event.kind}")

    def on_record(self, record: ToolRecord) -> None:
        self.records.append(record)

    def on_output(self, line: str, stream: str) -> None:
        self.log.append(f"output:{stream}")

    def on_step(self, event: StepEvent) -> None:
        self.log.append(f"{event.step}:{event.kind}")

    def on_note(self, note: Note) -> None:
        self.log.append(f"note:{note.level}")
        self.notes.append(note)


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


def test_an_unknown_pipeline_is_a_registry_error(settings: Settings, manager: ToolManager) -> None:
    with pytest.raises(RegistryError):
        prepare_pipeline("no-such-pipeline", "example.com", settings=settings, manager=manager)


def test_a_ready_pipeline_lists_its_stages_and_their_tools(settings: Settings, manager: ToolManager) -> None:
    prepared = prepare_pipeline("recon-to-vuln", "example.com", settings=settings, manager=manager)

    assert [node.tool for node in prepared.nodes] == ["subfinder", "httpx", "nuclei"]
    assert prepared.states == {"subfinder": "ready", "httpx": "ready", "nuclei": "ready"}
    assert prepared.ready and prepared.blocking == [] and prepared.warnings == []


def test_a_missing_binary_blocks_its_stage(settings: Settings, manager: ToolManager) -> None:
    (settings.tools_dir / "nuclei").unlink()

    prepared = prepare_pipeline("recon-to-vuln", "example.com", settings=settings, manager=manager)

    assert prepared.blocking == [("vulns", "nuclei", "not installed")]
    assert prepared.states["nuclei"] == "not installed" and not prepared.ready


def test_a_missing_optional_dependency_is_only_a_warning(
    settings: Settings, manager: ToolManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(manager.spec("subfinder"), "check_deps", ["nmap"])
    monkeypatch.setattr(scan.shutil, "which", lambda _name: None)

    prepared = prepare_pipeline("recon-to-vuln", "example.com", settings=settings, manager=manager)

    assert prepared.ready
    assert len(prepared.warnings) == 1 and prepared.warnings[0].startswith("subfinder works best with `nmap`")


def test_the_scan_is_a_step_around_every_stage_event(settings: Settings, manager: ToolManager) -> None:
    prepared = prepare_pipeline("recon-to-vuln", "example.com", settings=settings, manager=manager)
    session = open_session(settings.reports_dir, kind="pipeline", name="recon-to-vuln", session="s", stream=True)
    seen = Recorder()

    result = execute_pipeline(prepared, session=session, wordlist=None, observer=seen)

    assert seen.log[0] == "scan:start" and seen.log[-1] == "scan:done"
    assert "stage:vulns:done" in seen.log and "output:stdout" in seen.log
    assert [record.tool for record in seen.records] == [record.tool for record in result.records]
    assert result.succeeded() and len(result.records) == 3


def test_hosts_kept_out_of_scope_are_noted_after_the_scan(
    settings: Settings, manager: ToolManager
) -> None:
    scoped = settings.model_copy(update={"exclude": ["sub.example.com"]})
    prepared = prepare_pipeline("recon-to-vuln", "example.com", settings=scoped, manager=manager)
    session = open_session(scoped.reports_dir, kind="pipeline", name="recon-to-vuln", session=None, stream=True)
    seen = Recorder()

    execute_pipeline(prepared, session=session, wordlist=None, observer=seen)

    assert seen.log[-2:] == ["scan:done", "note:info"]
    assert seen.notes == [Note("info", "scope: 1 host(s) excluded")]


def test_a_failing_engine_still_ends_the_scan_and_closes_the_manager(
    settings: Settings, manager: ToolManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(self: PipelineEngine, *_a: object, **_k: object) -> object:
        raise CyberfwError("the engine broke")

    closed: list[bool] = []
    monkeypatch.setattr(PipelineEngine, "run", broken)
    monkeypatch.setattr(manager, "close", lambda: closed.append(True))
    prepared = prepare_pipeline("recon-to-vuln", "example.com", settings=settings, manager=manager)
    session = open_session(settings.reports_dir, kind="pipeline", name="recon-to-vuln", session=None, stream=True)
    seen = Recorder()

    with pytest.raises(CyberfwError, match="the engine broke"):
        execute_pipeline(prepared, session=session, wordlist=None, observer=seen)

    assert seen.log == ["scan:start", "scan:done"] and closed == [True]


def test_a_given_wordlist_is_used_as_is(settings: Settings) -> None:
    seen = Recorder()

    assert choose_wordlist(settings, "mine.txt", ffuf=True, observer=seen) == "mine.txt"
    assert seen.notes == []


def test_ffuf_without_a_wordlist_says_which_list_it_falls_back_to(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    (settings.root_dir / "wordlists").mkdir()
    (settings.root_dir / "wordlists" / "common.txt").write_text("admin\n", encoding="utf-8")
    seen = Recorder()

    assert choose_wordlist(settings, None, ffuf=True, observer=seen) is None
    assert seen.notes[0] == Note(
        "info", "--ffuf: no wordlist given, using the bundled common.txt (pass --wordlist <path> to override)"
    )

    monkeypatch.setattr(scan, "default_wordlist", lambda: None)
    choose_wordlist(settings, None, ffuf=True, observer=seen)
    assert seen.notes[1].level == "warn" and "the fuzz stage will be skipped" in seen.notes[1].text


def test_a_script_driving_the_core_writes_nothing_to_either_stream(settings: Settings) -> None:
    # A plain script sets up no logging: the engine's warning about a failed
    # stage must not fall through to Python's last-resort handler on stderr.
    _break_tool(settings.root_dir, "httpx")
    script = (
        "from pathlib import Path\n"
        "from cyberfw.config import Settings\n"
        "from cyberfw.core.events import RunObserver\n"
        "from cyberfw.core.scan import execute_pipeline, prepare_pipeline\n"
        "from cyberfw.core.sessions import open_session\n"
        "from cyberfw.core.workspace import open_manager\n"
        "settings = Settings(root_dir=Path.cwd())\n"
        "prepared = prepare_pipeline('recon-to-vuln', 'example.com', settings=settings,\n"
        "                            manager=open_manager(settings))\n"
        "session = open_session(settings.reports_dir, kind='pipeline', name='recon-to-vuln',\n"
        "                       session=None, stream=True)\n"
        "result = execute_pipeline(prepared, session=session, wordlist=None, observer=RunObserver())\n"
        "assert not result.succeeded()\n"
    )

    run = subprocess.run(
        [sys.executable, "-c", script],
        cwd=settings.root_dir,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONUTF8": "1"},
        timeout=120,
    )

    assert run.returncode == 0, run.stderr
    assert (run.stdout, run.stderr) == ("", "")


class _Ends(RunObserver):
    """Keeps the done events."""

    def __init__(self) -> None:
        self.ends: list[StepEvent] = []

    def on_step(self, event: StepEvent) -> None:
        if event.kind == "done":
            self.ends.append(event)


def test_the_scan_ends_with_its_result(settings: Settings, manager: ToolManager) -> None:
    prepared = prepare_pipeline("recon-to-vuln", "example.com", settings=settings, manager=manager)
    session = open_session(settings.reports_dir, kind="pipeline", name="recon-to-vuln", session=None, stream=True)
    seen = _Ends()

    result = execute_pipeline(prepared, session=session, wordlist=None, observer=seen)

    assert [event.step for event in seen.ends] == ["scan"] and seen.ends[0].summary is result


def test_the_scan_still_ends_when_closing_the_manager_fails(settings: Settings, manager: ToolManager) -> None:
    def stuck() -> None:
        raise OSError("connection pool [stuck]")

    prepared = prepare_pipeline("recon-to-vuln", "example.com", settings=settings, manager=manager)
    session = open_session(settings.reports_dir, kind="pipeline", name="recon-to-vuln", session=None, stream=True)
    seen = _Ends()

    with pytest.MonkeyPatch.context() as patch:  # the fixture closes the real manager afterwards
        patch.setattr(manager, "close", stuck)
        with pytest.raises(OSError, match="stuck"):
            execute_pipeline(prepared, session=session, wordlist=None, observer=seen)

    assert [event.step for event in seen.ends] == ["scan"]
    assert isinstance(seen.ends[0].summary, PipelineResult) and seen.ends[0].summary.succeeded()
