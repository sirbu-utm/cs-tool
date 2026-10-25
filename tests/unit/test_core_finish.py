"""Sessions and finishing a run in cyberfw.core: triage, the comparison, keeping or discarding the reports."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cyberfw.config import Settings
from cyberfw.core.events import Note, RunObserver, StepEvent
from cyberfw.core.finish import Finished, finalize
from cyberfw.core.sessions import checked_session, discard_session, open_session, session_tag
from cyberfw.core.workspace import open_manager
from cyberfw.manager import ToolManager
from cyberfw.pipeline.engine import Node, NodeResult, PipelineResult
from cyberfw.pipeline.schemas import validate_record
from cyberfw.report.diff import RunDiff


class Recorder(RunObserver):
    """Keeps every step event and note, and the moment the save question came."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.notes: list[Note] = []
        self.changes: list[RunDiff] = []

    def on_step(self, event: StepEvent) -> None:
        self.events.append(f"{event.step}:{event.kind}")
        if isinstance(event.summary, RunDiff):
            self.changes.append(event.summary)

    def on_note(self, note: Note) -> None:
        self.events.append(f"note:{note.level}")
        self.notes.append(note)


@pytest.fixture
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    (tmp_path / "registry.yaml").write_text(
        "nuclei:\n  repo: org/nuclei\n  asset_patterns: []\n  binary: nuclei\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    return Settings(root_dir=tmp_path)


@pytest.fixture
def manager(settings: Settings) -> Iterator[ToolManager]:
    manager = open_manager(settings)
    yield manager
    manager.close()


pytestmark = pytest.mark.usefixtures("prints_nothing")


def _scan(minutes_ago: int, *findings: tuple[str, str]) -> PipelineResult:
    """A finished one-stage nuclei run with the given (template id, severity) findings."""
    started = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    records = [
        validate_record("nuclei", json.dumps({"template-id": template, "matched-at": "https://sub.example.com/",
                                              "info": {"name": template, "severity": severity}}), index)
        for index, (template, severity) in enumerate(findings, 1)
    ]
    node = Node(tool="nuclei", stage="vulns")
    return PipelineResult(nodes=[NodeResult(node=node, count=len(records))], records=records,
                          started_at=started, finished_at=started + timedelta(seconds=5))


def _finish(result: PipelineResult, settings: Settings, manager: ToolManager, seen: RunObserver, *,
            session: str | None = None, save: object = True, compare: bool = True) -> Finished:
    run_session = open_session(settings.reports_dir, kind="pipeline", name="scan", session=session, stream=True)
    return finalize(
        result, manager=manager, settings=settings, name="scan", seed="example.com", tools={"nuclei"},
        session=run_session, compare=compare, baseline=None, save=save, observer=seen,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize("name", ["scan-1", "nightly_run", "a.b"])
def test_a_plain_session_name_is_accepted(name: str) -> None:
    assert checked_session(name) == name


@pytest.mark.parametrize("name", [".", "..", "../x", "a/b", "a\\b", "C:x"])
def test_a_session_that_is_not_a_plain_name_is_refused(name: str) -> None:
    with pytest.raises(ValueError, match="plain directory name"):
        checked_session(name)


def test_a_fresh_session_is_named_after_its_run() -> None:
    assert session_tag("pipeline", "recon").startswith("pipeline-recon-20")


def test_an_existing_session_directory_is_never_removed(tmp_path: Path) -> None:
    (tmp_path / "earlier").mkdir()
    session = open_session(tmp_path, kind="run", name="x", session="earlier", stream=False)

    assert session.created is False and session.context is None
    assert discard_session(session.dir, created=session.created) is False
    assert (tmp_path / "earlier").is_dir()


def test_a_saved_run_writes_both_reports(settings: Settings, manager: ToolManager) -> None:
    seen = Recorder()

    finished = _finish(_scan(1, ("xss", "medium")), settings, manager, seen, session="kept")

    assert sorted(finished.reports) == ["html", "json"]
    assert all(path.is_file() for path in finished.reports.values())
    assert finished.run.session_id == "kept" and finished.run.seed == "example.com"
    assert seen.notes == []


def test_declining_removes_the_session_this_run_made(settings: Settings, manager: ToolManager) -> None:
    seen = Recorder()

    finished = _finish(_scan(1), settings, manager, seen, session="mine", save=False)

    assert finished.reports == {}
    assert not (settings.reports_dir / "mine").exists()
    assert seen.notes == [Note("info", "report not saved")]


def test_declining_leaves_an_earlier_session_alone(settings: Settings, manager: ToolManager) -> None:
    (settings.reports_dir / "earlier").mkdir(parents=True)
    seen = Recorder()

    _finish(_scan(1), settings, manager, seen, session="earlier", save=False)

    assert (settings.reports_dir / "earlier").is_dir()
    assert seen.notes == [Note("info", f"report not saved; {settings.reports_dir / 'earlier'} was left as it was")]


def test_the_save_question_comes_after_the_comparison(settings: Settings, manager: ToolManager) -> None:
    _finish(_scan(10, ("xss", "medium")), settings, manager, Recorder(), session="first")
    seen = Recorder()

    def ask() -> bool:
        seen.events.append("asked")
        return True

    finished = _finish(_scan(1, ("xss", "medium"), ("sqli", "high")), settings, manager, seen, save=ask)

    assert seen.events == ["compare:start", "compare:done", "asked"]
    assert seen.changes == [finished.changes]
    assert finished.changes is not None and finished.changes.new_findings_at_least("high") == 1


def test_a_first_scan_or_no_comparison_sends_no_compare_events(settings: Settings, manager: ToolManager) -> None:
    first, unasked = Recorder(), Recorder()

    _finish(_scan(10, ("xss", "medium")), settings, manager, first)
    finished = _finish(_scan(1, ("xss", "medium")), settings, manager, unasked, compare=False)

    assert first.events == [] and unasked.events == []
    assert finished.changes is None


def test_muted_findings_are_noted(settings: Settings, manager: ToolManager) -> None:
    settings.triage_file.parent.mkdir(parents=True, exist_ok=True)
    settings.triage_file.write_text("mutes:\n  - {id: m1, template: xss, reason: false_positive}\n", encoding="utf-8")
    seen = Recorder()

    _finish(_scan(1, ("xss", "medium")), settings, manager, seen, save=False)

    assert seen.notes[0].level == "info" and seen.notes[0].text.startswith("Triage: 1 finding(s) muted")
