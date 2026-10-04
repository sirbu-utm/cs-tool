"""Live progress view for a running pipeline.

A scan is mostly waiting: stages that print nothing for minutes, fan-outs over
hundreds of hosts. This view turns the engine's :class:`StageEvent` stream and
its validated records into a picture that is always current — which stage is
running and for how long, how far a fan-out has got, what each stage produced
or why it failed, and the findings as they arrive.

Pure state plus :meth:`PipelineLiveView.render`: the caller drives a Rich
``Live`` with the view itself (``__rich__``) on auto-refresh, so spinners turn,
bars shimmer and timers tick between events; tests render it to a string.
``clock`` is injectable so elapsed times and animation frames are
deterministic under test. ``animate=False`` (the ``animations`` setting) draws
the same information without motion, and :meth:`finish` settles the transient
effects so the frame left on screen is clean.

``Live`` renders from its refresh thread while the engine's callbacks change
the state on the event loop, so each view guards both with one lock: a deque
or dict that grows mid-iteration would otherwise kill the refresh thread.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from rich import box
from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from cyberfw.motion import bar, fade_mark, scanner, spinner
from cyberfw.pipeline.engine import Node, NodeResult, StageEvent
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.tools.targets import hostname_of
from cyberfw.ui import (
    NEUTRAL_STYLE,
    PIP,
    SEVERITY_STYLES,
    STATUS_STYLES,
    record_detail,
    record_style,
)

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

#: Cells in a stage's progress bar.
_BAR = 10
#: Seconds a changed record count stays bright.
_FLASH = 0.35


def _outcome(result: NodeResult | None) -> str:
    """``ok`` / ``failed`` / ``skipped`` for a finished stage."""
    if result is None or result.ok:
        return "ok"
    return "skipped" if result.skipped else "failed"


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
    #: When ``count`` last went up, for the flash.
    changed: float | None = None

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
        animate: bool = True,
    ) -> None:
        self._clock = clock
        self._title = title
        self._animate = animate
        self._settled = False
        self._lock = threading.Lock()
        self._stages: dict[str, _Stage] = {
            node.stage: _Stage(tool=node.tool, stage=node.stage) for node in nodes
        }
        #: Recent records with the moment each arrived (for its fading mark).
        self._tail: deque[tuple[ToolRecord, float]] = deque(maxlen=tail)

    # -- engine hooks ---------------------------------------------------------
    def on_stage(self, event: StageEvent) -> None:
        """Apply one stage lifecycle event."""
        with self._lock:
            self._apply(event)

    def _apply(self, event: StageEvent) -> None:
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
            stage.status = _outcome(result)
            if result is not None:
                stage.count = result.count
                stage.note = result.error or ""
            if stage.total:
                stage.done = stage.total

    def on_record(self, record: ToolRecord) -> None:
        """Count a validated record against its stage and keep it in the tail."""
        with self._lock:
            now = self._clock()
            self._tail.append((record, now))
            for stage in self._stages.values():
                if stage.status == "running" and stage.tool == record.tool:
                    stage.count += 1
                    stage.changed = now
                    break

    def finish(self) -> None:
        """Settle spinners, flashes and fading marks: the run is over and this
        frame stays on screen."""
        self._settled = True

    @property
    def _moving(self) -> bool:
        return self._animate and not self._settled

    # -- async adapters for PipelineEngine ------------------------------------
    async def stage_callback(self, event: StageEvent) -> None:
        self.on_stage(event)

    async def record_callback(self, record: ToolRecord) -> None:
        self.on_record(record)

    # -- rendering ------------------------------------------------------------
    def __rich__(self) -> RenderableType:
        return self.render()

    def render(self) -> RenderableType:
        with self._lock:
            now = self._clock()
            return Group(self._stage_table(now), Text(""), self._tail_table(now))

    def _stage_table(self, now: float) -> Table:
        stages = list(self._stages.values())
        # Only the columns that carry something: eight columns do not fit an
        # 80-100 column terminal, and the first to be squeezed are the ones that
        # identify the row ("nucl…"). "note" is shown only once something went wrong.
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
        table.add_column("status", no_wrap=True, min_width=9)
        table.add_column("records", justify="right", no_wrap=True, min_width=7)
        table.add_column("progress", no_wrap=True, min_width=_BAR)
        table.add_column("time", justify="right", no_wrap=True, min_width=5)
        if with_note:
            table.add_column("note", style="err", overflow="ellipsis", no_wrap=True, max_width=40)
        for stage in stages:
            elapsed = stage.elapsed(now)
            row: list[str | Text] = [
                stage.tool,
                stage.stage,
                self._status_cell(stage, now),
                self._count_cell(stage, now),
                self._progress_cell(stage, now),
                "" if elapsed is None else f"{elapsed:.1f}s",
            ]
            if with_note:
                row.append(stage.note)
            table.add_row(*row)
        return table

    def _status_cell(self, stage: _Stage, now: float) -> Text:
        """``■ ok`` — the banner's pip in the state's colour; a spinner while running."""
        style = _STATUS_STYLES[stage.status]
        if stage.status == "pending":
            mark = " "
        elif stage.status == "running" and self._moving:
            mark = spinner(now)
        else:
            mark = PIP
        return Text.assemble((f"{mark} ", style), (stage.status, style))

    def _count_cell(self, stage: _Stage, now: float) -> Text:
        if not stage.count and stage.status == "pending":
            return Text("")
        fresh = self._moving and stage.changed is not None and now - stage.changed < _FLASH
        return Text(str(stage.count), style="bold bright_white" if fresh else "")

    def _progress_cell(self, stage: _Stage, now: float) -> Text:
        """A bar per stage: filled by targets done for a fan-out, a sweeping glow
        for a single process still running, full and coloured once it is over."""
        fan_out = stage.total > 1
        fraction = stage.done / stage.total if fan_out else 0.0
        if stage.status == "running":
            if fan_out:
                cell = bar(fraction, _BAR, style="info", shine=(now % 1.2) / 1.2 if self._moving else None)
            elif self._moving:
                cell = scanner(now, _BAR, style="info")
            else:
                cell = bar(0.0, _BAR, style="info", track="info")
        elif stage.status == "ok":
            cell = bar(1.0, _BAR, style="ok")
        elif stage.status == "failed":
            cell = bar(fraction if fan_out else 1.0, _BAR, style="err")
        elif stage.status == "skipped":
            cell = bar(0.0, _BAR, style="warn", track="warn")
        else:
            cell = bar(0.0, _BAR, style="muted")
        if fan_out:
            cell.append(f" {stage.done}/{stage.total}", style="muted")
        return cell

    def _tail_table(self, now: float) -> Table:
        table = Table(
            title="Latest findings",
            title_style="accent",
            box=box.SIMPLE_HEAD,
            expand=True,
            pad_edge=False,
        )
        # A one-cell gutter where each new finding's mark fades: █ ▓ ▒ ░.
        table.add_column("", no_wrap=True, width=1)
        table.add_column("tool", style="tool", no_wrap=True)
        table.add_column("kind", no_wrap=True)
        table.add_column("target", overflow="ellipsis", no_wrap=True, ratio=3)
        table.add_column("detail", overflow="ellipsis", no_wrap=True, ratio=2)
        if not self._tail:
            table.add_row("", Text("no records yet", style="muted"), "", "", "")
            return table
        for record, arrived in self._tail:
            style = record_style(record)
            table.add_row(
                Text(fade_mark(now - arrived) if self._moving else " ", style=style),
                record.tool,
                Text(record.kind, style="muted"),
                Text(record.target, style=style),
                Text(record_detail(record), style=style),
            )
        return table


#: Seconds a freshly-touched node stays highlighted — the growth "pulse" —
#: and how much of that it spends lit up as a full block.
_PULSE = 0.8
_GLOW = 0.3
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
    auto-refresh, the running stage shows a spinner, the header carries a pip per
    stage (the running one blinks), and a node touched a moment ago glows and
    then cools down, so the map visibly grows and pulses as results land.
    ``clock`` is injectable for deterministic tests.
    """

    def __init__(
        self,
        nodes: Iterable[Node],
        *,
        seed: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        title: str | None = None,
        animate: bool = True,
    ) -> None:
        self._clock = clock
        self._seed = seed
        self._title = title
        self._animate = animate
        self._settled = False
        self._lock = threading.Lock()
        nodes = list(nodes)
        self._tools = [node.tool for node in nodes]
        #: pending / running / ok / failed / skipped per stage, in plan order.
        self._stage_states: dict[str, str] = {node.stage: "pending" for node in nodes}
        self._hosts: dict[str, _HostNode] = {}
        self._order: list[str] = []
        self._active: str | None = None  # "tool" of the running stage
        self._running = False

    # -- engine hooks ---------------------------------------------------------
    def on_stage(self, event: StageEvent) -> None:
        with self._lock:
            self._apply(event)

    def _apply(self, event: StageEvent) -> None:
        if event.kind == "start":
            self._active = event.tool
            self._running = True
            self._stage_states[event.stage] = "running"
        elif event.kind == "done":
            if self._active == event.tool:
                self._running = False
            self._stage_states[event.stage] = _outcome(event.result)

    def finish(self) -> None:
        """Settle the spinner and the glow: the run is over and this frame stays."""
        self._settled = True

    @property
    def _moving(self) -> bool:
        return self._animate and not self._settled

    def on_record(self, record: ToolRecord) -> None:
        """Fold one validated record into the topology, keyed by hostname."""
        with self._lock:
            self._fold(record)

    def _fold(self, record: ToolRecord) -> None:
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
        with self._lock:
            return self._render()

    def _render(self) -> RenderableType:
        now = self._clock()
        vuln_total = sum(len(h.vulns) for h in self._hosts.values())
        live_total = sum(1 for h in self._hosts.values() if h.live)
        spin = spinner(now) if self._running and self._moving else "•"
        header = Text.assemble(
            (f"{spin} ", "info" if self._running else "muted"),
            (self._title or "scan", "accent"),
            ("   ", ""),
            self._stage_pips(now),
            ("   " if self._stage_states else "", ""),
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

    def _stage_pips(self, now: float) -> Text:
        """One pip per stage, coloured by outcome; the running one blinks."""
        pips = Text()
        for state in self._stage_states.values():
            if state == "running":
                style = "bold bright_white" if self._moving and int(now * 4) % 2 else "info"
            else:
                style = _STATUS_STYLES[state]
            pips.append(PIP, style=style)
        return pips

    def _attach_host(self, root: Tree, node: _HostNode, now: float) -> None:
        age = now - node.touched
        if self._moving and age < _GLOW:
            name_style = "bold black on green"
        elif self._moving and age < _PULSE:
            name_style = "bold bright_green"
        else:
            name_style = "white" if node.live else "muted"
        label = Text()
        label.append("● " if node.live else "○ ", style="ok" if node.live else "muted")
        label.append(node.host, style=name_style)
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
