"""Finishing a run without printing: triage, its facts, the comparison with an
earlier run, and keeping its reports — or removing the session it made."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cyberfw import triage
from cyberfw.config import Settings
from cyberfw.core.events import Note, RunObserver, StepEvent
from cyberfw.core.sessions import Session, discard_session
from cyberfw.manager import ToolManager
from cyberfw.pipeline.engine import PipelineResult
from cyberfw.report import diff as rundiff
from cyberfw.report.diff import RunDiff
from cyberfw.report.html_report import generate_html_report
from cyberfw.report.json_report import generate_json_report, report_payload
from cyberfw.report.run_info import RunInfo


def apply_triage(result: PipelineResult, triage_file: Path, observer: RunObserver) -> None:
    """Silence findings the triage file has muted, and say how many."""
    try:
        rules = triage.load_rules(triage_file)
    except triage.TriageError as exc:
        observer.on_note(Note("warn", f"Triage skipped — {exc}"))
        return
    if not rules:
        return
    summary = triage.apply(result.records, rules)
    if summary.muted:
        observer.on_note(Note("info", f"Triage: {summary.line()}"))
    if summary.expired:
        observer.on_note(Note("warn", f"Triage: {len(summary.expired)} rule(s) expired — {', '.join(summary.expired)}"))


def run_info(manager: ToolManager, *, name: str, seed: str | None, session_id: str, tools: set[str]) -> RunInfo:
    """The facts a report records about its run: what ran, against what, where, with which versions."""
    return RunInfo(
        pipeline=name,
        seed=seed,
        session_id=session_id,
        platform=manager.mapping.label,
        tool_versions={tool: (manager.install_state(tool) or {}).get("version") for tool in sorted(tools)},
    )


def compare_with_earlier(
    result: PipelineResult, run: RunInfo, reports_dir: Path, explicit: str | None, observer: RunObserver
) -> RunDiff | None:
    """Compare this run with an earlier one — the one named, else the newest
    earlier run of the same pipeline and seed. A first scan has nothing to compare
    with and sends no events; the changes go out with the ``compare`` step's ``done``."""
    try:
        if explicit:
            path: Path | None = rundiff.resolve_report(explicit, reports_dir)
        else:
            path = rundiff.find_baseline(reports_dir, seed=run.seed, pipeline=run.pipeline, before=result.started_at)
    except (FileNotFoundError, ValueError) as exc:
        observer.on_note(Note("warn", f"Not compared with an earlier run: {exc}"))
        return None
    if path is None:
        return None
    changes: RunDiff | None = None
    observer.on_step(StepEvent("start", "compare"))
    try:
        changes = rundiff.compare(rundiff.load_report(path), report_payload(result, run))
    except (FileNotFoundError, ValueError) as exc:
        observer.on_note(Note("warn", f"Not compared with an earlier run: {exc}"))
    finally:
        observer.on_step(StepEvent("done", "compare", summary=changes))
    return changes


def write_reports(
    result: PipelineResult, *, session_id: str, settings: Settings, run: RunInfo, changes: RunDiff | None = None
) -> dict[str, Path]:
    """Render both reports into the session directory: ``{"json": path, "html": path}``."""
    json_path = generate_json_report(
        result, session_id=session_id, reports_dir=settings.reports_dir, run=run, changes=changes
    )
    html_path = generate_html_report(
        result, session_id=session_id, reports_dir=settings.reports_dir, run=run, changes=changes
    )
    return {"json": json_path, "html": html_path}


@dataclass
class Finished:
    """What finishing a run left: its facts, what changed since the earlier run, the reports."""

    run: RunInfo
    changes: RunDiff | None
    #: The reports written, by format (``json``, ``html``); empty when the run was not saved.
    reports: dict[str, Path]


def finalize(
    result: PipelineResult,
    *,
    manager: ToolManager,
    settings: Settings,
    name: str,
    seed: str | None,
    tools: set[str],
    session: Session,
    compare: bool,
    baseline: str | None,
    save: bool | Callable[[], bool],
    observer: RunObserver,
) -> Finished:
    """Finish a pipeline run: triage, the run's facts, the comparison with an
    earlier run — then keep the reports, or remove the session if this run made it.

    A callable ``save`` is asked after the comparison and before anything is
    written. A report that cannot be written raises :class:`CyberfwError`.
    """
    apply_triage(result, settings.triage_file, observer)
    run = run_info(manager, name=name, seed=seed, session_id=session.id, tools=tools)
    changes = compare_with_earlier(result, run, settings.reports_dir, baseline, observer) if compare else None
    if session.context is not None:
        session.context.close()
    if not (save() if callable(save) else save):
        if discard_session(session.dir, created=session.created):
            observer.on_note(Note("info", "report not saved"))
        else:
            observer.on_note(Note("info", f"report not saved; {session.dir} was left as it was"))
        return Finished(run=run, changes=changes, reports={})
    reports = write_reports(result, session_id=session.id, settings=settings, run=run, changes=changes)
    return Finished(run=run, changes=changes, reports=reports)
