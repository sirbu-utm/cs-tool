"""Live progress view for a running pipeline.

A scan is mostly waiting: stages that print nothing for minutes, fan-outs over
hundreds of hosts. This view turns the engine's :class:`StageEvent` stream and
its validated records into a picture that is always current — which stage is
running and for how long, how far a fan-out has got, what each stage produced
or why it failed, and the findings as they arrive.

Pure state plus :meth:`PipelineLiveView.render`: the caller drives a Rich
``Live`` with it, and tests render it to a string. ``clock`` is injectable so
elapsed times are deterministic under test.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from rich import box
from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text

from cyberfw.pipeline.engine import Node, StageEvent
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.ui import record_detail, record_style

__all__ = ["PipelineLiveView"]

#: How many of the most recent findings to keep on screen.
DEFAULT_TAIL = 8

_STATUS_STYLES = {"pending": "muted", "running": "info", "ok": "ok", "failed": "err"}


@dataclass
class _Stage:
    """Everything the table shows for one stage."""

    tool: str
    stage: str
    status: str = "pending"
    count: int = 0
    done: int = 0
    total: int = 0
    note: str = ""
    started: float | None = None
    finished: float | None = None

    def elapsed(self, now: float) -> float | None:
        if self.started is None:
            return None
        return (self.finished if self.finished is not None else now) - self.started


class PipelineLiveView:
    """Renderable state of a pipeline run.

    ``nodes`` is the plan, so every stage is listed as ``pending`` before it
    starts; a stage the view was not constructed with (``cyberfw run``) is
    added when its first event arrives.
    """

    def __init__(
        self,
        nodes: Iterable[Node],
        *,
        tail: int = DEFAULT_TAIL,
        clock: Callable[[], float] = time.monotonic,
        title: str | None = None,
    ) -> None:
        self._clock = clock
        self._title = title
        self._stages: dict[str, _Stage] = {
            node.stage: _Stage(tool=node.tool, stage=node.stage) for node in nodes
        }
        self._tail: deque[ToolRecord] = deque(maxlen=tail)

    # -- engine hooks ---------------------------------------------------------
    def on_stage(self, event: StageEvent) -> None:
        """Apply one stage lifecycle event."""
        stage = self._stages.get(event.stage)
        if stage is None:
            stage = self._stages[event.stage] = _Stage(tool=event.tool, stage=event.stage)
        if event.kind == "start":
            stage.status = "running"
            stage.total = event.total
            stage.started = self._clock()
        elif event.kind == "progress":
            stage.done, stage.total = event.done, event.total
        elif event.kind == "done":
            stage.finished = self._clock()
            result = event.result
            stage.status = "ok" if result is None or result.ok else "failed"
            if result is not None:
                stage.count = result.count
                stage.note = result.error or ""
            if stage.total:
                stage.done = stage.total

    def on_record(self, record: ToolRecord) -> None:
        """Count a validated record against its stage and keep it in the tail."""
        self._tail.append(record)
        for stage in self._stages.values():
            if stage.status == "running" and stage.tool == record.tool:
                stage.count += 1
                break

    # -- async adapters for PipelineEngine ------------------------------------
    async def stage_callback(self, event: StageEvent) -> None:
        self.on_stage(event)

    async def record_callback(self, record: ToolRecord) -> None:
        self.on_record(record)

    # -- rendering ------------------------------------------------------------
    def render(self) -> RenderableType:
        return Group(self._stage_table(), Text(""), self._tail_table())

    def _stage_table(self) -> Table:
        now = self._clock()
        # Not expanded: the stage table is narrow, and stretching it to the
        # terminal width scatters "records/targets/time" across the screen.
        table = Table(
            title=self._title or "Pipeline",
            title_style="accent",
            box=box.SIMPLE_HEAD,
            pad_edge=False,
        )
        table.add_column("#", style="muted", justify="right", width=2)
        table.add_column("tool", style="tool", no_wrap=True)
        table.add_column("stage", no_wrap=True)
        table.add_column("status", no_wrap=True)
        table.add_column("records", justify="right", no_wrap=True)
        table.add_column("targets", justify="right", no_wrap=True)
        table.add_column("time", justify="right", no_wrap=True)
        table.add_column("note", style="err", overflow="ellipsis", no_wrap=True)
        for index, stage in enumerate(self._stages.values(), start=1):
            elapsed = stage.elapsed(now)
            table.add_row(
                str(index),
                stage.tool,
                stage.stage,
                Text(stage.status, style=_STATUS_STYLES[stage.status]),
                str(stage.count) if stage.count or stage.status != "pending" else "",
                f"{stage.done}/{stage.total}" if stage.total > 1 else "",
                "" if elapsed is None else f"{elapsed:.1f}s",
                stage.note,
            )
        return table

    def _tail_table(self) -> Table:
        table = Table(
            title="Latest findings",
            title_style="accent",
            box=box.SIMPLE_HEAD,
            expand=True,
            pad_edge=False,
        )
        table.add_column("tool", style="tool", no_wrap=True)
        table.add_column("kind", no_wrap=True)
        table.add_column("target", overflow="ellipsis", no_wrap=True, ratio=3)
        table.add_column("detail", overflow="ellipsis", no_wrap=True, ratio=2)
        if not self._tail:
            table.add_row(Text("no records yet", style="muted"), "", "", "")
            return table
        for record in self._tail:
            style = record_style(record)
            table.add_row(
                record.tool,
                Text(record.kind, style="muted"),
                Text(record.target, style=style),
                Text(record_detail(record), style=style),
            )
        return table
