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
from rich.tree import Tree

from cyberfw.pipeline.engine import Node, StageEvent
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.tools.targets import hostname_of
from cyberfw.ui import NEUTRAL_STYLE, SEVERITY_STYLES, STATUS_STYLES, record_detail, record_style

__all__ = ["PipelineLiveView", "TopologyView"]

#: How many of the most recent findings to keep on screen.
DEFAULT_TAIL = 8

_STATUS_STYLES = {
    "pending": "muted",
    "running": "info",
    "ok": "ok",
    "failed": "err",
    # Not a fault of this tool: its source stage failed, so it never ran.
    "skipped": "warn",
}


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
            if result is None or result.ok:
                stage.status = "ok"
            else:
                stage.status = "skipped" if result.skipped else "failed"
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
        stages = list(self._stages.values())
        # Only the columns that carry something: eight columns do not fit an
        # 80-100 column terminal, and the first to be squeezed are the ones that
        # identify the row ("nucl…"). "targets" is meaningful only for a fan-out
        # stage, and "note" only once something went wrong.
        with_targets = any(stage.total > 1 for stage in stages)
        with_note = any(stage.note for stage in stages)
        # Not expanded: the stage table is narrow, and stretching it to the
        # terminal width scatters "records/targets/time" across the screen.
        table = Table(
            title=self._title or "Pipeline",
            title_style="accent",
            box=box.SIMPLE_HEAD,
            pad_edge=False,
        )
        # min_width on the identifying columns and a cap on the free-text note:
        # without both, a one-sentence note claims the width and Rich shrinks
        # the tool and stage names to "nucl…" / "vul…".
        table.add_column("tool", style="tool", no_wrap=True, min_width=10)
        table.add_column("stage", no_wrap=True, min_width=10)
        table.add_column("status", no_wrap=True, min_width=7)
        table.add_column("records", justify="right", no_wrap=True, min_width=7)
        if with_targets:
            table.add_column("targets", justify="right", no_wrap=True, min_width=7)
        table.add_column("time", justify="right", no_wrap=True, min_width=5)
        if with_note:
            table.add_column("note", style="err", overflow="ellipsis", no_wrap=True, max_width=40)
        for stage in stages:
            elapsed = stage.elapsed(now)
            row: list[str | Text] = [
                stage.tool,
                stage.stage,
                Text(stage.status, style=_STATUS_STYLES[stage.status]),
                str(stage.count) if stage.count or stage.status != "pending" else "",
            ]
            if with_targets:
                row.append(f"{stage.done}/{stage.total}" if stage.total > 1 else "")
            row.append("" if elapsed is None else f"{elapsed:.1f}s")
            if with_note:
                row.append(stage.note)
            table.add_row(*row)
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


#: Braille spinner frames for the running-stage indicator.
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
#: Seconds a freshly-touched node stays highlighted — the growth "pulse".
_PULSE = 0.8
#: Cap on hosts drawn, so a huge fan-out does not build a thousand-line tree.
_MAX_HOSTS = 40
#: Cap on vulnerabilities listed per host before they collapse to a count.
_MAX_VULNS_PER_HOST = 6


@dataclass
class _HostNode:
    """One host in the topology and everything discovered hanging off it."""

    host: str
    source: str = ""
    live: bool = False
    status_code: int = 0
    title: str = ""
    ports: set[str] = None  # type: ignore[assignment]
    vulns: list[tuple[str, str]] = None  # type: ignore[assignment]
    fuzz: int = 0
    shots: int = 0
    touched: float = 0.0

    def __post_init__(self) -> None:
        if self.ports is None:
            self.ports = set()
        if self.vulns is None:
            self.vulns = []


class TopologyView:
    """A live, growing topology of a scan, rendered as a Rich tree.

    The seed is the root; each discovered host is a branch, with its live HTTP
    status, open ports, and vulnerabilities (severity-coloured) as leaves. Hosts
    are keyed by hostname, so a nuclei finding on ``https://a.example.com/x``
    attaches under the same node subfinder first discovered as ``a.example.com``.

    Animation comes from :meth:`__rich__`: driven by a Rich ``Live`` with
    auto-refresh, the running stage shows a spinner and nodes touched in the last
    moment are highlighted, so the map visibly grows and pulses as results land.
    ``clock`` is injectable for deterministic tests.
    """

    def __init__(
        self,
        nodes: Iterable[Node],
        *,
        seed: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        title: str | None = None,
    ) -> None:
        self._clock = clock
        self._seed = seed
        self._title = title
        self._tools = [node.tool for node in nodes]
        self._hosts: dict[str, _HostNode] = {}
        self._order: list[str] = []
        self._active: str | None = None  # "tool" of the running stage
        self._running = False

    # -- engine hooks ---------------------------------------------------------
    def on_stage(self, event: StageEvent) -> None:
        if event.kind == "start":
            self._active = event.tool
            self._running = True
        elif event.kind == "done":
            if self._active == event.tool:
                self._running = False

    def on_record(self, record: ToolRecord) -> None:
        """Fold one validated record into the topology, keyed by hostname."""
        node = self._node_for(record)
        if node is None:
            return
        kind = record.kind
        if kind == "host":
            node.source = str(getattr(record, "source", "") or node.source)
        elif kind == "http":
            node.live = True
            node.status_code = int(getattr(record, "status_code", 0) or 0)
            node.title = str(getattr(record, "title", "") or node.title)
        elif kind == "vuln":
            node.vulns.append(
                (str(getattr(record, "severity", "") or "unknown"), str(getattr(record, "name", "") or ""))
            )
        elif kind == "port":
            _, _, port = record.target.rpartition(":")
            if port:
                node.ports.add(port)
        elif kind == "scan":
            for port in str(getattr(record, "ports_list", "") or "").split(","):
                if port.strip():
                    node.ports.add(port.strip())
        elif kind == "fuzz":
            node.fuzz += 1
        elif kind == "screenshot":
            node.shots += 1
        node.touched = self._clock()

    def _node_for(self, record: ToolRecord) -> _HostNode | None:
        host = hostname_of(record.target).strip() if record.target else ""
        if not host:
            return None
        node = self._hosts.get(host)
        if node is None:
            node = self._hosts[host] = _HostNode(host=host)
            self._order.append(host)
        return node

    # -- async adapters -------------------------------------------------------
    async def stage_callback(self, event: StageEvent) -> None:
        self.on_stage(event)

    async def record_callback(self, record: ToolRecord) -> None:
        self.on_record(record)

    # -- rendering ------------------------------------------------------------
    def __rich__(self) -> RenderableType:
        return self.render()

    def render(self) -> RenderableType:
        now = self._clock()
        vuln_total = sum(len(h.vulns) for h in self._hosts.values())
        live_total = sum(1 for h in self._hosts.values() if h.live)
        spin = _SPINNER[int(now * 10) % len(_SPINNER)] if self._running else "•"
        header = Text.assemble(
            (f"{spin} ", "info" if self._running else "muted"),
            (self._title or "scan", "accent"),
            ("   ", ""),
            (f"{len(self._hosts)} hosts", "muted"),
            ("  ·  ", "muted"),
            (f"{live_total} live", "ok" if live_total else "muted"),
            ("  ·  ", "muted"),
            (f"{vuln_total} vulns", "err" if vuln_total else "muted"),
        )
        root = Tree(Text.assemble((str(self._seed or "scan"), "bold")), guide_style="muted")
        for host in self._order[:_MAX_HOSTS]:
            self._attach_host(root, self._hosts[host], now)
        hidden = len(self._order) - _MAX_HOSTS
        if hidden > 0:
            root.add(Text(f"… +{hidden} more host(s)", style="muted"))
        return Group(header, Text(""), root)

    def _attach_host(self, root: Tree, node: _HostNode, now: float) -> None:
        pulsing = (now - node.touched) < _PULSE
        label = Text()
        label.append("● " if node.live else "○ ", style="ok" if node.live else "muted")
        label.append(node.host, style="bold" if pulsing else ("white" if node.live else "muted"))
        if node.status_code:
            label.append(f"  {node.status_code}", style=STATUS_STYLES.get(node.status_code // 100, NEUTRAL_STYLE))
        if node.title:
            label.append(f"  {node.title}", style="muted")
        if node.source and not node.live:
            label.append(f"  ({node.source})", style="muted")
        branch = root.add(label)
        if node.ports:
            ports = ",".join(sorted(node.ports, key=lambda p: int(p) if p.isdigit() else 0))
            branch.add(Text.assemble(("ports ", "muted"), (ports, "info")))
        for severity, name in node.vulns[:_MAX_VULNS_PER_HOST]:
            style = SEVERITY_STYLES.get(severity.lower(), "white")
            branch.add(Text.assemble(("▲ ", style), (severity, style), ("  " + name if name else "", style)))
        extra = len(node.vulns) - _MAX_VULNS_PER_HOST
        if extra > 0:
            branch.add(Text(f"▲ +{extra} more finding(s)", style="err"))
        if node.fuzz:
            branch.add(Text.assemble(("fuzz ", "muted"), (str(node.fuzz), "info")))
        if node.shots:
            branch.add(Text.assemble(("screenshots ", "muted"), (str(node.shots), "info")))
