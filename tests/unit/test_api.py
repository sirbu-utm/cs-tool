"""cyberfw.api: runs, plans and saved runs as data — offline, against the CLI tests' fake tools."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberfw import api
from cyberfw.exceptions import CyberfwError, RegistryError, ToolNotFoundError
from cyberfw.pipeline.context import SessionContext
from cyberfw.pipeline.engine import Node, NodeResult, PipelineEngine

from . import test_cli as base

pytestmark = pytest.mark.usefixtures("prints_nothing")

PIPELINE = ("recon-to-vuln", "example.com")


class Recorder(api.RunObserver):
    """Everything a run sends, as short labels, plus the notes."""

    def __init__(self) -> None:
        self.log: list[str] = []
        self.notes: list[api.Note] = []

    def on_plan(self, plan: api.Plan) -> None:
        self.log.append("plan")

    def on_stage(self, event: api.StageEvent) -> None:
        self.log.append("stage")

    def on_record(self, record: api.ToolRecord) -> None:
        self.log.append("record")

    def on_step(self, event: api.StepEvent) -> None:
        self.log.append(f"{event.step}:{event.kind}")

    def on_note(self, note: api.Note) -> None:
        self.log.append(f"note:{note.level}")
        self.notes.append(note)


@pytest.fixture(autouse=True)
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base._write_fake_binaries(tmp_path / "tools_bin")
    base._write_registry(tmp_path)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _two_saved_runs(workspace: Path) -> tuple[api.RunOutcome, api.RunOutcome]:
    """A first run, then one where nuclei adds a new high finding."""
    first = api.run_pipeline(*PIPELINE, session="one", mail=False)
    base.TestBaselineComparison._tool_prints(
        workspace, "nuclei",
        {"template-id": "xss", "matched-at": "https://sub.example.com/", "info": {"name": "XSS", "severity": "medium"}},
        {"template-id": "sqli", "matched-at": "https://sub.example.com/login", "info": {"name": "SQLi", "severity": "high"}},
    )
    return first, api.run_pipeline(*PIPELINE, session="two", mail=False)


def test_a_pipeline_run_returns_its_stages_records_and_reports(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    seen = Recorder()

    outcome = api.run_pipeline(*PIPELINE, session="first", observer=seen)

    assert outcome.succeeded and outcome.exit_code() == 0
    assert [stage.node.tool for stage in outcome.result.nodes] == ["subfinder", "httpx", "nuclei"]
    assert len(outcome.result.records) >= 3
    assert outcome.reports == {
        "json": workspace / "reports" / "first" / "report.json",
        "html": workspace / "reports" / "first" / "report.html",
    }
    assert (outcome.session_id, outcome.session_dir) == ("first", workspace / "reports" / "first")
    assert seen.log[0] == "plan" and {"stage", "record", "scan:start", "scan:done", "mail:done"} <= set(seen.log)
    assert capsys.readouterr() == ("", "")


def test_the_notes_of_a_run_are_kept_in_its_outcome() -> None:
    seen = Recorder()

    outcome = api.run_pipeline(*PIPELINE, save=False, observer=seen)

    assert outcome.notes == seen.notes
    assert any(note.text.startswith("Email check skipped") for note in outcome.notes)  # live DNS is off in tests


def test_a_failed_stage_exits_1(workspace: Path) -> None:
    base._break_tool(workspace, "httpx")

    outcome = api.run_pipeline(*PIPELINE, save=False, mail=False)

    assert not outcome.succeeded and outcome.exit_code() == 1 and outcome.exit_code("low") == 1


def test_new_findings_exit_3_only_when_an_alert_severity_is_given(workspace: Path) -> None:
    _, second = _two_saved_runs(workspace)

    assert second.changes is not None and second.alert_hits("high") == 1
    assert (second.exit_code(), second.exit_code("high"), second.exit_code("critical")) == (0, 3, 0)


def test_a_failed_run_outranks_its_new_findings(workspace: Path) -> None:
    # Even with new findings to alert on, a broken scan is reported as broken.
    _two_saved_runs(workspace)
    changes = api.compare_runs(api.load_run("one"), api.load_run("two"))
    failed = api.PipelineResult(nodes=[NodeResult(node=Node(tool="httpx", stage="live_http"), ok=False)])

    outcome = api.RunOutcome(
        result=failed, run=api.RunInfo(), session_id="x", session_dir=workspace, reports={}, changes=changes
    )

    assert outcome.alert_hits("high") == 1 and outcome.exit_code("high") == 1


def test_an_unknown_alert_severity_is_a_value_error() -> None:
    outcome = api.run_pipeline(*PIPELINE, save=False, mail=False)

    with pytest.raises(ValueError, match="severity must be one of"):
        outcome.exit_code("urgent")


def test_a_run_that_is_not_saved_leaves_no_session_behind(workspace: Path) -> None:
    asked: list[bool] = []

    api.run_pipeline(*PIPELINE, session="dropped", save=False, mail=False)
    api.run_pipeline(*PIPELINE, session="declined", save=lambda: asked.append(True) or False, mail=False)

    assert asked == [True]
    assert not (workspace / "reports" / "dropped").exists() and not (workspace / "reports" / "declined").exists()


def test_stages_that_cannot_run_stop_the_run_before_it_starts(workspace: Path) -> None:
    (workspace / "tools_bin" / "nuclei").unlink()
    seen = Recorder()

    with pytest.raises(api.PreflightError) as caught:
        api.run_pipeline(*PIPELINE, observer=seen)

    assert caught.value.blocking == [("vulns", "nuclei", "not installed")]
    assert seen.log == ["plan"]
    assert list((workspace / "reports").iterdir()) == []


def test_force_start_runs_the_stages_that_can(workspace: Path) -> None:
    (workspace / "tools_bin" / "nuclei").unlink()

    outcome = api.run_pipeline(*PIPELINE, force_start=True, save=False, mail=False)

    assert [stage.ok for stage in outcome.result.nodes] == [True, True, False] and outcome.exit_code() == 1


def test_a_session_that_is_not_a_plain_name_is_a_value_error() -> None:
    with pytest.raises(ValueError, match="plain directory name"):
        api.run_pipeline(*PIPELINE, session="../outside")


def test_an_unknown_pipeline_is_a_registry_error() -> None:
    with pytest.raises(RegistryError):
        api.run_pipeline("no-such-pipeline", "example.com")


def test_an_engine_failure_releases_the_records_store(monkeypatch: pytest.MonkeyPatch) -> None:
    async def broken(self: PipelineEngine, *_a: object, **_k: object) -> object:
        raise CyberfwError("the engine broke")

    real_close = SessionContext.close
    closed: list[bool] = []

    def counting_close(self: SessionContext) -> None:
        closed.append(True)
        real_close(self)

    monkeypatch.setattr(PipelineEngine, "run", broken)
    monkeypatch.setattr(SessionContext, "close", counting_close)

    with pytest.raises(CyberfwError, match="the engine broke"):
        api.run_pipeline(*PIPELINE)

    assert closed == [True]


def test_a_plan_lists_the_stages_what_blocks_and_whether_it_is_ready(workspace: Path) -> None:
    plan = api.plan_pipeline(*PIPELINE)

    assert plan.ready and [stage.tool for stage in plan.stages] == ["subfinder", "httpx", "nuclei"]

    (workspace / "tools_bin" / "nuclei").unlink()
    blocked = api.plan_pipeline("recon-to-vuln")

    assert not blocked.ready and blocked.target is None
    assert blocked.blocking == (api.Blocker("vulns", "nuclei", "not installed"),)


def test_a_tool_run_returns_its_records_and_writes_nothing_unless_saved() -> None:
    outcome = api.run_tool("subfinder", target="example.com")

    assert [record.target for record in outcome.result.records] == ["sub.example.com"]
    assert outcome.succeeded and outcome.reports == {} and not outcome.session_dir.exists()


def test_a_saved_tool_run_writes_its_reports(workspace: Path) -> None:
    outcome = api.run_tool("subfinder", target="example.com", session="once", save=True)

    assert sorted(outcome.reports) == ["html", "json"]
    assert outcome.reports["json"] == workspace / "reports" / "once" / "report.json"


def test_a_tool_run_asks_to_save_only_when_it_found_something(workspace: Path) -> None:
    base._silence_tool(workspace, "subfinder")
    asked: list[bool] = []

    outcome = api.run_tool("subfinder", target="example.com", save=lambda: asked.append(True) or True)

    assert asked == [] and outcome.reports == {}


def test_a_tool_run_with_nothing_to_work_on_finds_nothing() -> None:
    outcome = api.run_tool("subfinder")

    assert outcome.succeeded and outcome.result.records == []


def test_a_target_the_tool_cannot_take_is_a_value_error() -> None:
    with pytest.raises(ValueError, match="local repository directory"):
        api.run_tool("gitleaks", target="https://utm.md/")


def test_a_tool_that_is_not_installed_is_not_found(workspace: Path) -> None:
    (workspace / "tools_bin" / "subfinder").unlink()

    with pytest.raises(ToolNotFoundError):
        api.run_tool("subfinder", target="example.com")


def test_saved_runs_load_compare_and_export(workspace: Path) -> None:
    first, _ = _two_saved_runs(workspace)

    one, two = api.load_run("one"), api.load_run(workspace / "reports" / "two")
    changes = api.compare_runs(one, two)
    sarif = api.export_sarif(two)

    assert one.path == first.reports["json"]
    assert changes.new_findings_at_least("high") == 1
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    assert "nuclei,vuln,high,https://sub.example.com/login,SQLi,false" in api.export_csv(two).splitlines()


def test_a_run_that_was_never_saved_is_not_found() -> None:
    with pytest.raises(FileNotFoundError):
        api.load_run("never-saved")


def test_scan_controls_override_only_what_the_caller_set() -> None:
    overrides = api._scan_control_overrides

    assert overrides(severity="", tags="", rate_limit=None, exclude=[]) == {}
    assert overrides(severity="high", tags="", rate_limit=None, exclude=[]) == {"severity": "high"}
    assert overrides(severity="high", tags="cve", rate_limit=20, exclude=["*.dev"]) == {
        "severity": "high", "tags": "cve", "rate_limit": 20, "exclude": ["*.dev"],
    }
