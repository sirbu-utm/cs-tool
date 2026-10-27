"""Preparing and running a pipeline scan without printing.

:func:`prepare_pipeline` builds the stages and checks them before anything
runs — what blocks a stage, what only weakens it; :func:`execute_pipeline` runs
them, sending every stage, record and output line to the observer, with the scan
itself as a ``scan`` step around them.
"""

from __future__ import annotations

import functools
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

import anyio

from cyberfw.config import Settings
from cyberfw.core.events import Note, RunObserver, StepEvent
from cyberfw.core.sessions import Session
from cyberfw.core.workspace import tool_state
from cyberfw.manager import ToolManager
from cyberfw.pipeline.engine import (
    Node,
    PipelineEngine,
    PipelineResult,
    StageEvent,
    dependency_hint,
)
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.pipelines import build
from cyberfw.resources import default_wordlist


class Blocker(NamedTuple):
    """A stage that cannot run as things stand, and why."""

    stage: str
    tool: str
    reason: str


@dataclass(frozen=True)
class PlanStage:
    """One stage of a planned pipeline."""

    #: Its place in the pipeline, counted from 1.
    index: int
    tool: str
    stage: str
    #: ``seed``, or the stage whose targets it reads.
    consumes: str
    #: ``ready`` / ``blocked`` / ``not installed``.
    state: str
    #: The stage's own scan controls, when set, as ``(name, value)`` pairs:
    #: ``severity``, ``tags``, ``rate``, ``max``.
    options: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Plan:
    """A pipeline as it would run: its stages, what blocks them, what only weakens them."""

    name: str
    target: str | None
    stages: tuple[PlanStage, ...]
    blocking: tuple[Blocker, ...]
    warnings: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return not self.blocking


@dataclass
class PreparedPipeline:
    """A pipeline ready to run — or to show as a plan: its stages and what stands in their way."""

    name: str
    target: str | None
    nodes: list[Node]
    #: Each stage that cannot run as things stand, and why.
    blocking: list[Blocker]
    #: Missing optional dependencies: they cost capability, not the run.
    warnings: list[str]
    #: ``ready`` / ``blocked`` / ``not installed`` for each tool the stages use.
    states: dict[str, str]
    settings: Settings
    manager: ToolManager

    @property
    def ready(self) -> bool:
        return not self.blocking


def resolve_gowitness(flag: bool | None, manager: ToolManager, tools_dir: Path) -> bool:
    """Whether recon-to-vuln should run gowitness.

    An explicit ``--gowitness`` / ``--no-gowitness`` is taken as given. The
    vanilla default (``None``) includes it only when it can actually run —
    registered, installed, and a Chrome/Chromium present — so a plain run gains
    screenshots where possible and never fails for the lack of a browser."""
    if flag is not None:
        return flag
    from cyberfw.tools.gowitness import _find_chrome

    return (
        "gowitness" in manager.registry.names()
        and manager.is_installed("gowitness")
        and _find_chrome(tools_dir) is not None
    )


def _preflight(
    manager: ToolManager, nodes: list[Node], tools_dir: Path
) -> tuple[list[Blocker], list[str], dict[str, str]]:
    """What stands between this plan and a useful run, in plan order.

    Returns ``(blocking, warnings, states)``. Blocking: a binary that cannot run,
    or a hard external requirement the adapter reports missing (gowitness without
    Chrome) — the stage could only fail. Warnings: a ``check_deps`` entry that is
    not on PATH (RustScan's Nmap), which costs capability, not the run.
    """
    blocking: list[Blocker] = []
    warnings: list[str] = []
    states: dict[str, str] = {}
    for node in nodes:
        if node.tool in states:
            continue
        state = states[node.tool] = tool_state(manager, node.tool, tools_dir)
        if state != "ready":
            blocking.append(Blocker(node.stage, node.tool, state))
            continue
        requirement = manager.adapter_class(node.tool).missing_requirement(tools_dir)
        if requirement is not None:
            blocking.append(Blocker(node.stage, node.tool, requirement))
        for dep in manager.spec(node.tool).check_deps:
            if shutil.which(dep) is None:
                warnings.append(
                    f"{node.tool} works best with `{dep}`, which is not on PATH — {dependency_hint(dep)}"
                )
    return blocking, warnings, states


def prepare_pipeline(
    name: str,
    target: str | None,
    *,
    settings: Settings,
    manager: ToolManager,
    ffuf: bool = False,
    gowitness: bool | None = None,
    max_httpx: int = 0,
) -> PreparedPipeline:
    """Build the pipeline's stages and check them before anything runs.

    Every tool must be registered and have an adapter — a YAML pipeline may name
    one the registry (or the code) lacks — else :class:`RegistryError`. Then each
    tool's state, what blocks a stage and what only weakens it.
    """
    nodes = build(
        name,
        pipelines_dir=settings.pipelines_dir,
        include_ffuf=ffuf,
        include_gowitness=resolve_gowitness(gowitness, manager, settings.tools_dir),
        max_httpx=max_httpx,
    )
    for node in nodes:
        manager.spec(node.tool)
        manager.adapter_class(node.tool)
    blocking, warnings, states = _preflight(manager, nodes, settings.tools_dir)
    return PreparedPipeline(
        name=name, target=target, nodes=nodes, blocking=blocking, warnings=warnings, states=states,
        settings=settings, manager=manager,
    )


def plan_of(prepared: PreparedPipeline) -> Plan:
    """The plan a prepared pipeline would run: each stage, the stage it reads, its
    tool's state and its own scan controls, then what blocks and what weakens it."""
    stages: list[PlanStage] = []
    previous: str | None = None
    for index, node in enumerate(prepared.nodes, start=1):
        controls = (("severity", node.severity), ("tags", node.tags), ("rate", node.rate_limit), ("max", node.max_records))
        stages.append(PlanStage(
            index=index,
            tool=node.tool,
            stage=node.stage,
            consumes=node.input_from or ("seed" if previous is None else previous),
            state=prepared.states[node.tool],
            options=tuple((key, str(value)) for key, value in controls if value),
        ))
        previous = node.stage
    return Plan(
        name=prepared.name, target=prepared.target, stages=tuple(stages),
        blocking=tuple(prepared.blocking), warnings=tuple(prepared.warnings),
    )


def choose_wordlist(settings: Settings, wordlist: str | None, *, ffuf: bool, observer: RunObserver) -> str | None:
    """The wordlist every stage is offered: the one given, else the configured one.

    With ``ffuf`` and neither, the fuzz stage falls back to the bundled list — the
    note says which, or that there is none and the stage will be skipped."""
    chosen = wordlist or settings.wordlist
    if ffuf and not chosen:
        bundled = default_wordlist()
        if bundled is not None:
            observer.on_note(Note(
                "info", f"--ffuf: no wordlist given, using the bundled {bundled.name} (pass --wordlist <path> to override)"
            ))
        else:
            observer.on_note(Note(
                "warn",
                "--ffuf needs a wordlist and the bundled default was not found; "
                "the fuzz stage will be skipped. Re-run with --wordlist <path>.",
            ))
    return chosen


def wire_observer(engine: PipelineEngine, observer: RunObserver) -> None:
    """Send the engine's stage, record and raw-output callbacks to ``observer``."""

    async def on_stage(event: StageEvent) -> None:
        observer.on_stage(event)

    async def on_record(record: ToolRecord) -> None:
        observer.on_record(record)

    async def on_stdout(line: str) -> None:
        observer.on_output(line, "stdout")

    async def on_stderr(line: str) -> None:
        observer.on_output(line, "stderr")

    engine.set_stage_callback(on_stage)
    engine.set_record_callback(on_record)
    engine.set_stdout_raw_callback(on_stdout)
    engine.set_stderr_callback(on_stderr)


def end_scan(manager: ToolManager, observer: RunObserver, result: PipelineResult | None) -> None:
    """Close the tool manager, then end the ``scan`` step with its result (``None``
    when it raised) — the ``done`` goes out even if closing fails."""
    try:
        manager.close()
    finally:
        observer.on_step(StepEvent("done", "scan", summary=result))


def execute_pipeline(
    prepared: PreparedPipeline, *, session: Session, wordlist: str | None, observer: RunObserver
) -> PipelineResult:
    """Run the prepared stages, streaming every stage, record and output line to the observer.

    The scan is a step of its own: ``start`` before the engine runs and ``done``,
    carrying the result, after it — also when it raises — then a note for any
    hosts kept out of scope.
    The tool manager is closed once the stages have run.
    """
    # The pre-flight already reported any missing optional dependency.
    engine = PipelineEngine(prepared.settings, prepared.manager, context=session.context, report_missing_deps=False)
    wire_observer(engine, observer)
    observer.on_step(StepEvent("start", "scan"))
    try:
        result = anyio.run(functools.partial(engine.run, extra_input=wordlist), prepared.nodes, prepared.target)
    except BaseException:
        end_scan(prepared.manager, observer, None)
        raise
    end_scan(prepared.manager, observer, result)
    if result.excluded:
        observer.on_note(Note("info", f"scope: {len(result.excluded)} host(s) excluded"))
    return result
