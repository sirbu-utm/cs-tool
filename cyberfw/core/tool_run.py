"""One registered tool run on its own (``cyberfw run``), without printing: checked, run, kept."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import anyio

from cyberfw.config import Settings
from cyberfw.core.events import RunObserver, StepEvent
from cyberfw.core.finish import run_info, write_reports
from cyberfw.core.scan import end_scan, wire_observer
from cyberfw.core.sessions import Session
from cyberfw.manager import ToolManager
from cyberfw.pipeline.context import SessionContext
from cyberfw.pipeline.engine import Node, NodeResult, PipelineEngine, PipelineResult
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.tools import adapter_class
from cyberfw.tools.base import ToolContext


def check_tool(manager: ToolManager, tool: str, target: str | None) -> None:
    """What must hold before ``tool`` runs on its own, checked in this order: a
    target of the kind it takes (else :class:`ValueError` — a usage error), a
    registered tool with an adapter (else :class:`RegistryError`), and its binary
    (else :class:`ToolNotFoundError`)."""
    if target is not None:
        adapter_class(tool).validate_target(target)
    manager.binary_path(tool)


@dataclass
class ToolRun:
    """One tool run on its own: its outcome, records and timing."""

    tool: str
    target: str | None
    node: NodeResult
    records: list[ToolRecord]
    started_at: datetime
    finished_at: datetime
    session: Session

    @property
    def result(self) -> PipelineResult:
        """The run as a one-stage pipeline result."""
        return PipelineResult(
            nodes=[self.node], records=self.records, started_at=self.started_at, finished_at=self.finished_at
        )


async def _run_single(
    engine: PipelineEngine, ctx: ToolContext, tool: str, parse: bool
) -> tuple[NodeResult, list[ToolRecord]]:
    """Run one tool stage through the engine (handles fan-out and crashes)."""
    return await engine.run_single(Node(tool=tool, stage=tool), ctx, parse=parse)


def run_tool_once(
    tool: str,
    *,
    settings: Settings,
    manager: ToolManager,
    target: str | None,
    inputs: Sequence[str] = (),
    wordlist: str | None = None,
    parse: bool = True,
    session: Session,
    observer: RunObserver,
) -> ToolRun:
    """Run one registered tool on its own, streaming its events to the observer.

    Like a pipeline stage — same fan-out, timeout and failure handling — with
    ``inputs`` in place of a previous stage. Without ``parse`` every stdout line
    is a raw record. The run is a ``scan`` step, timed around the process; the
    manager is closed afterwards, and the session's store if records streamed.
    """
    engine = PipelineEngine(settings, manager, context=session.context)
    wire_observer(engine, observer)
    ctx = ToolContext(
        target=target, inputs=list(inputs), extra_input=wordlist or settings.wordlist, controls=engine._controls()
    )
    started_at = datetime.now(timezone.utc)
    observer.on_step(StepEvent("start", "scan"))
    try:
        node, records = anyio.run(_run_single, engine, ctx, tool, parse)
    except BaseException:
        end_scan(manager, observer, None)
        raise
    ran = ToolRun(
        tool=tool, target=target, node=node, records=records, started_at=started_at,
        finished_at=datetime.now(timezone.utc), session=session,
    )
    end_scan(manager, observer, ran.result)
    if session.context is not None:
        session.context.close()
    return ran


def keep_tool_run(run: ToolRun, *, settings: Settings, manager: ToolManager) -> dict[str, Path]:
    """Save a tool run: its records — archived now, unless they streamed as they
    came — and both reports. Returns the reports by format, as :func:`write_reports`."""
    if run.session.context is None:
        with SessionContext(settings.reports_dir, run.session.id) as store:
            for record in run.records:
                store.append(run.tool, record)
    info = run_info(manager, name=run.tool, seed=run.target, session_id=run.session.id, tools={run.tool})
    return write_reports(run.result, session_id=run.session.id, settings=settings, run=info)
