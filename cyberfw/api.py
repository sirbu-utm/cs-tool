"""cyberfw's Python API: run a pipeline or one tool, plan a pipeline, read and compare saved runs.

Stable within a major version: the functions and types in ``__all__``.
``cyberfw.core`` and ``cyberfw.cli`` are internal. Nothing here prints, prompts
or calls ``sys.exit``: results come back as data, progress goes to an optional
:class:`RunObserver`, and logging is the caller's to set up. The calls are
synchronous and run their own event loop — call them from plain code, not from
inside a running asyncio loop.

Example::

    from cyberfw import api

    outcome = api.run_pipeline("recon-to-vuln", "example.com", save=False)
    print(outcome.succeeded, len(outcome.result.records), outcome.exit_code())
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cyberfw.config import Settings, load_settings
from cyberfw.core.events import (
    MailSummary,
    Note,
    RunObserver,
    StepEvent,
    StepName,
    StepSummary,
    Stream,
    TakeoverSummary,
    TlsSummary,
    VtSummary,
)
from cyberfw.core.finish import finalize, run_info
from cyberfw.core.scan import (
    Blocker,
    Plan,
    PlanStage,
    choose_wordlist,
    execute_pipeline,
    plan_of,
    prepare_pipeline,
)
from cyberfw.core.sessions import checked_session, open_session
from cyberfw.core.steps import post_scan
from cyberfw.core.tool_run import check_tool, keep_tool_run, run_tool_once
from cyberfw.core.workspace import open_manager
from cyberfw.exceptions import PreflightError
from cyberfw.pipeline.engine import PipelineResult, StageEvent
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.report import diff as rundiff
from cyberfw.report.csv_report import to_csv
from cyberfw.report.diff import RunDiff
from cyberfw.report.run_info import RunInfo
from cyberfw.report.sarif import to_sarif
from cyberfw.threatintel import IntelSummary

__all__ = [
    "Blocker",
    "IntelSummary",
    "MailSummary",
    "Note",
    "PipelineResult",
    "Plan",
    "PlanStage",
    "PreflightError",
    "RunDiff",
    "RunInfo",
    "RunObserver",
    "RunOutcome",
    "SavedRun",
    "StageEvent",
    "StepEvent",
    "StepName",
    "StepSummary",
    "Stream",
    "TakeoverSummary",
    "TlsSummary",
    "ToolRecord",
    "VtSummary",
    "compare_runs",
    "export_csv",
    "export_sarif",
    "load_run",
    "plan_pipeline",
    "run_pipeline",
    "run_tool",
]


@dataclass
class RunOutcome:
    """What a run produced: its result, its facts, where it was kept, what changed."""

    #: The stages, their records and timing; hosts kept out of scope in ``excluded``.
    result: PipelineResult
    run: RunInfo
    session_id: str
    session_dir: Path
    #: The reports written, by format (``json``, ``html``); empty when the run was not saved.
    reports: dict[str, Path]
    #: What changed since the earlier run it was compared with, if it was.
    changes: RunDiff | None
    #: Every note the run sent, in order.
    notes: list[Note] = field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        """Every stage ran and finished cleanly."""
        return self.result.succeeded()

    def alert_hits(self, severity: str = "low") -> int:
        """New findings at ``severity`` or worse since the earlier run; 0 without a comparison."""
        _check_severity(severity)
        return self.changes.new_findings_at_least(severity) if self.changes is not None else 0

    def exit_code(self, alert_severity: str | None = None) -> int:
        """The CLI's exit code for this run: 1 when it failed — a broken scan is
        reported as broken, never as "nothing new" — 3 when ``alert_severity`` is
        given and there are new findings at it or worse, else 0."""
        if not self.succeeded:
            return 1
        if alert_severity is not None and self.alert_hits(alert_severity):
            return 3
        return 0


@dataclass(frozen=True)
class SavedRun:
    """A saved run: its ``report.json`` and what it holds."""

    path: Path
    payload: dict[str, Any]


def _check_severity(severity: str) -> None:
    if severity not in rundiff.REAL:
        raise ValueError(f"severity must be one of {', '.join(rundiff.REAL)}, got {severity!r}")


def _scan_control_overrides(
    *, severity: str, tags: str, rate_limit: int | None, exclude: list[str]
) -> dict[str, object]:
    """The ``Settings`` fields to override for this run — only the controls the
    caller actually set, so an unset flag leaves the env/YAML/default in place."""
    overrides: dict[str, object] = {}
    if severity:
        overrides["severity"] = severity
    if tags:
        overrides["tags"] = tags
    if rate_limit is not None:
        overrides["rate_limit"] = rate_limit
    if exclude:
        overrides["exclude"] = exclude
    return overrides


def _settings(
    settings: Settings | None,
    *,
    severity: str = "",
    tags: str = "",
    rate_limit: int | None = None,
    exclude: Sequence[str] = (),
) -> Settings:
    """The settings for one call: as given, else loaded the way the CLI loads them;
    the scan controls the caller set override them for this call only."""
    settings = settings if settings is not None else load_settings()
    settings.ensure_dirs()
    overrides = _scan_control_overrides(severity=severity, tags=tags, rate_limit=rate_limit, exclude=list(exclude))
    return settings.model_copy(update=overrides) if overrides else settings


class _Relay(RunObserver):
    """Passes every event on to the caller's observer and keeps the notes for the outcome."""

    def __init__(self, observer: RunObserver | None) -> None:
        self._observer = observer if observer is not None else RunObserver()
        self.notes: list[Note] = []

    def on_plan(self, plan: Plan) -> None:
        self._observer.on_plan(plan)

    def on_stage(self, event: StageEvent) -> None:
        self._observer.on_stage(event)

    def on_record(self, record: ToolRecord) -> None:
        self._observer.on_record(record)

    def on_output(self, line: str, stream: Stream) -> None:
        self._observer.on_output(line, stream)

    def on_step(self, event: StepEvent) -> None:
        self._observer.on_step(event)

    def on_note(self, note: Note) -> None:
        self.notes.append(note)
        self._observer.on_note(note)


def run_pipeline(
    name: str,
    target: str,
    *,
    settings: Settings | None = None,
    ffuf: bool = False,
    wordlist: str | None = None,
    gowitness: bool | None = None,
    max_httpx: int = 0,
    severity: str = "",
    tags: str = "",
    rate_limit: int | None = None,
    exclude: Sequence[str] = (),
    mail: bool = True,
    takeover: bool = True,
    intel: bool = True,
    vt_key: str | None = None,
    vt_limit: int = 20,
    baseline: str | None = None,
    compare: bool = True,
    session: str | None = None,
    save: bool | Callable[[], bool] = True,
    force_start: bool = False,
    observer: RunObserver | None = None,
) -> RunOutcome:
    """Run a pipeline against ``target`` and finish it: the checks after the scan,
    triage, the comparison with an earlier run, and the reports.

    ``settings`` default to the CLI's (env, ``config.local.yaml``); ``severity``,
    ``tags``, ``rate_limit`` and ``exclude`` override them for this call only.
    VirusTotal runs only with ``vt_key`` — the API never looks for a key or asks.
    ``baseline`` names the earlier run to compare with (else the newest of the same
    pipeline and seed); ``compare=False`` skips the comparison. ``save`` keeps the
    reports; a callable is asked after the comparison, before anything is written.
    A session this call made is removed when the run is not saved.

    Raises :class:`ValueError` (no target; a session that is not a plain name),
    :class:`RegistryError` (an unknown pipeline, or a tool it names),
    :class:`PreflightError` (stages cannot run and ``force_start`` is not set),
    :class:`ReportError` (the reports cannot be written) and
    :class:`CyberfwError` (the engine itself failed).
    """
    if not target:
        raise ValueError("a pipeline needs a target")
    if session:
        checked_session(session)
    settings = _settings(settings, severity=severity, tags=tags, rate_limit=rate_limit, exclude=exclude)
    relay = _Relay(observer)
    manager = open_manager(settings)
    try:
        prepared = prepare_pipeline(
            name, target, settings=settings, manager=manager, ffuf=ffuf, gowitness=gowitness, max_httpx=max_httpx
        )
        relay.on_plan(plan_of(prepared))
        for warning in prepared.warnings:
            relay.on_note(Note("warn", warning))
        if prepared.blocking and not force_start:
            raise PreflightError(prepared.blocking)
        chosen = choose_wordlist(settings, wordlist, ffuf=ffuf, observer=relay)
        run_session = open_session(settings.reports_dir, kind="pipeline", name=name, session=session, stream=True)
    except BaseException:
        manager.close()
        raise
    try:
        result = execute_pipeline(prepared, session=run_session, wordlist=chosen, observer=relay)
        post_scan(
            result, seed=target, settings=settings, mail=mail, takeover=takeover, intel=intel,
            vt_key=vt_key, vt_limit=vt_limit, observer=relay,
        )
        finished = finalize(
            result, manager=manager, settings=settings, name=name, seed=target,
            tools={node.tool for node in prepared.nodes}, session=run_session, compare=compare,
            baseline=baseline, save=save, observer=relay,
        )
    except BaseException:
        # The run never finished: release the records store (what streamed stays on disk).
        if run_session.context is not None:
            run_session.context.close()
        raise
    return RunOutcome(
        result=result, run=finished.run, session_id=run_session.id, session_dir=run_session.dir,
        reports=finished.reports, changes=finished.changes, notes=relay.notes,
    )


def plan_pipeline(
    name: str,
    target: str | None = None,
    *,
    settings: Settings | None = None,
    ffuf: bool = False,
    gowitness: bool | None = None,
    max_httpx: int = 0,
) -> Plan:
    """What :func:`run_pipeline` would run, without running it: each stage, the
    stage it reads, its tool's state, what blocks and what only weakens the run.
    Raises :class:`RegistryError` for an unknown pipeline or a tool it names."""
    settings = _settings(settings)
    manager = open_manager(settings)
    try:
        return plan_of(prepare_pipeline(
            name, target, settings=settings, manager=manager, ffuf=ffuf, gowitness=gowitness, max_httpx=max_httpx
        ))
    finally:
        manager.close()


def run_tool(
    tool: str,
    *,
    target: str | None = None,
    inputs: Sequence[str] = (),
    wordlist: str | None = None,
    settings: Settings | None = None,
    severity: str = "",
    tags: str = "",
    rate_limit: int | None = None,
    parse: bool = True,
    session: str | None = None,
    save: bool | Callable[[], bool] = False,
    observer: RunObserver | None = None,
) -> RunOutcome:
    """Run one registered tool on its own against ``target`` and/or ``inputs``.

    With neither, the tool has nothing to work on and finds nothing. Without
    ``parse`` every stdout line is a raw record. ``save=True`` streams the records
    into ``reports/<session>/`` as they arrive and writes both reports; a callable
    is asked after the run — only when it produced records — before anything is
    written; ``False`` writes nothing.

    Raises :class:`ValueError` (a target the tool cannot take; a session that is
    not a plain name), :class:`RegistryError` (an unknown tool) and
    :class:`ToolNotFoundError` (a tool that is not installed).
    """
    if session:
        checked_session(session)
    settings = _settings(settings, severity=severity, tags=tags, rate_limit=rate_limit)
    relay = _Relay(observer)
    manager = open_manager(settings)
    try:
        check_tool(manager, tool, target)
    except BaseException:
        manager.close()
        raise
    run_session = open_session(settings.reports_dir, kind="run", name=tool, session=session, stream=save is True)
    ran = run_tool_once(
        tool, settings=settings, manager=manager, target=target, inputs=inputs, wordlist=wordlist,
        parse=parse, session=run_session, observer=relay,
    )
    keep = save if isinstance(save, bool) else bool(ran.records) and save()
    reports = keep_tool_run(ran, settings=settings, manager=manager) if keep else {}
    return RunOutcome(
        result=ran.result,
        run=run_info(manager, name=tool, seed=target, session_id=run_session.id, tools={tool}),
        session_id=run_session.id, session_dir=run_session.dir, reports=reports, changes=None, notes=relay.notes,
    )


def load_run(ref: str | Path, *, settings: Settings | None = None) -> SavedRun:
    """A saved run, by session id, its directory or its ``report.json`` (looked up
    under ``reports/``). Raises :class:`FileNotFoundError` when there is none and
    :class:`ValueError` when the file is not a cyberfw report."""
    settings = settings if settings is not None else load_settings()
    path = rundiff.resolve_report(str(ref), settings.reports_dir)
    return SavedRun(path=path, payload=rundiff.load_report(path))


def compare_runs(old: SavedRun, new: SavedRun) -> RunDiff:
    """What changed from ``old`` to ``new``: findings, ports, subdomains, certificates, exploitation."""
    return rundiff.compare(old.payload, new.payload)


def export_sarif(run: SavedRun) -> dict[str, Any]:
    """The run's findings as a SARIF 2.1.0 document (for CI / code scanning)."""
    return to_sarif(run.payload)


def export_csv(run: SavedRun) -> str:
    """Every record of the run as CSV (for triage in a spreadsheet)."""
    return to_csv(run.payload)
