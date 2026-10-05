"""HTML report generation from a pipeline result.

Writes ``report.html`` under ``reports/<session>/``: an animated dashboard of
the run — KPI tiles, a severity donut, records per tool, the pipeline drawn as
a graph, a per-host inventory, finding cards, a screenshot gallery and a
filterable, sortable record table. CSS, JS and SVG are inline, so the page
opens offline and can be emailed; only the gowitness screenshots are linked,
from the session's ``screenshots/`` directory next to the report.

Everything taken from a scan (page titles, URLs, template names, the seed) is
attacker-influenced and HTML-escaped; on top of that a Content-Security-Policy
admits only this module's own two scripts, by hash. The page is complete
without JavaScript and without motion (``prefers-reduced-motion``): the script
only replays the numbers, reveals sections and adds filtering.
"""

from __future__ import annotations

import base64
import hashlib
import html
import math
import re
import zlib
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from cyberfw.exceptions import ReportError
from cyberfw.logging import get_logger
from cyberfw.pipeline.engine import NodeResult, PipelineResult
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.report.run_info import RunInfo
from cyberfw.tools.targets import hostname_of

LOG = get_logger("report.html")

__all__ = ["generate_html_report"]

#: Ordered human-facing headers for a record row; ``num`` columns sort numerically.
_HEADERS = [
    ("#", "num"),
    ("tool", "text"),
    ("kind", "text"),
    ("target", "text"),
    ("detail", "text"),
]

#: Severity order, worst first. Anything else nuclei says counts as ``unknown``.
_SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")

#: Compact severity labels for the host table.
_SEVERITY_SHORT = {
    "critical": "crit",
    "high": "high",
    "medium": "med",
    "low": "low",
    "info": "info",
    "unknown": "unk",
}

#: Severities that get a card of their own; the rest fold into a ``<details>``.
_MAJOR = frozenset({"critical", "high", "medium"})

#: Record kinds whose target names a host. A gitleaks ``secret`` names a file,
#: and ``hostname_of("src/app.py")`` would invent a host called ``src``.
_HOST_KINDS = frozenset({"host", "port", "http", "fuzz", "vuln", "screenshot", "scan"})

#: Fixed colour per registered tool, so a tool looks the same in every report.
_TOOL_COLORS = {
    "subfinder": "#2ec5d5",
    "naabu": "#9b7bff",
    "rustscan": "#c084fc",
    "httpx": "#2ed573",
    "nuclei": "#ff6bcb",
    "ffuf": "#ffb547",
    "gowitness": "#4d9bff",
    "gitleaks": "#a3e635",
}
#: Picked by name hash for a tool the map does not know.
_FALLBACK_COLORS = ("#38bdf8", "#f472b6", "#facc15", "#34d399", "#fb923c", "#818cf8")

#: Caps that keep a huge scan from building a page the browser chokes on;
#: the record table always lists everything.
_MAX_HOSTS = 500
_MAX_CARDS = 240
_MAX_SHOTS = 300
#: Rows past this index share its entry delay, so long tables do not crawl in.
_MAX_STAGGER = 30


#: Pipeline graph geometry, in SVG user units.
_NODE_W, _NODE_H, _GAP_X, _GAP_Y, _PAD = 184, 68, 64, 20, 14


def generate_html_report(
    result: PipelineResult,
    output_path: Path | None = None,
    *,
    session_id: str | None = None,
    reports_dir: Path | None = None,
    run: RunInfo | None = None,
) -> Path:
    """Write the HTML report and return its path.

    ``output_path`` takes priority; otherwise ``reports_dir / session_id /
    report.html`` is used (creating directories as needed). ``run`` supplies
    the provenance (pipeline, seed, timing, tool versions).
    """
    path = _resolve_path(output_path, session_id, reports_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(_render_page(result, run or RunInfo()), encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"cannot write {path}: {exc}") from exc
    LOG.info("HTML report written to %s", path)
    return path


# -- page ---------------------------------------------------------------------
def _render_page(result: PipelineResult, run: RunInfo) -> str:
    info = run.as_dict(result)
    records = result.records
    hosts = _hosts(records)
    vulns = [r for r in records if r.kind == "vuln"]
    secrets = [r for r in records if r.kind == "secret"]
    shots = [r for r in records if r.kind == "screenshot" and getattr(r, "filename", None)]
    # Tools whose stage completed: only those can vouch for "nothing found".
    ran = {nr.node.tool for nr in result.nodes if nr.ok}

    sections: list[tuple[str, str, str]] = [
        ("overview", "Overview", _overview(result, hosts, vulns, ran))
    ]
    sections.append(("pipeline", "Pipeline", _pipeline_section(result, run.seed)))
    if hosts:
        sections.append(("hosts", "Hosts", _hosts_section(hosts)))
    if vulns or secrets:
        sections.append(("findings", "Findings", _findings_section(vulns, secrets)))
    if shots:
        sections.append(("screenshots", "Screenshots", _shots_section(shots)))
    sections.append(("records", "Records", _records_section(records)))
    sections.append(("run", "Run", _run_section(result, run)))

    nav = "".join(f'<a href="#{sid}">{_e(label)}</a>' for sid, label, _ in sections)
    body = "\n".join(
        f'<section id="{sid}" class="reveal">{content}</section>'
        for sid, _label, content in sections
    )
    seed = run.seed or ""
    status = "success" if result.succeeded() else "failed"
    return _PAGE_TEMPLATE.format(
        csp=_CSP,
        title=_e("cyberfw report" + (f" · {seed}" if seed else "")),
        css=_CSS,
        head_js=_HEAD_JS,
        nav=nav,
        hero=_hero(result, info, hosts, status, seed or run.pipeline or "scan report"),
        sections=body,
        lightbox=_LIGHTBOX if shots else "",
        generated=_e(str(info["generated_at"])),
        version=_e(str(info["cyberfw_version"])),
        js=_JS,
    )


def _hero(
    result: PipelineResult, info: dict[str, Any], hosts: list[_Host], status: str, headline: str
) -> str:
    chips = [f'<span class="pill {status}"><i></i>{status}</span>']
    if info["pipeline"]:
        chips.append(f'<span class="chip">pipeline <b>{_e(str(info["pipeline"]))}</b></span>')
    if result.started_at is not None:
        chips.append(f'<span class="chip">started <b>{_e(_when(result.started_at))}</b></span>')
    if result.duration_s is not None:
        chips.append(
            f'<span class="chip">took <b>{_e(_human_duration(result.duration_s))}</b></span>'
        )
    return (
        '<header class="hero reveal" id="top">'
        '<div class="hero-main">'
        '<div class="eyebrow">cyberfw · security report</div>'
        f'<h1{" class=long" if len(headline) > 32 else ""}><span class="grad">{_e(headline)}</span></h1>'
        f'<div class="meta">{"".join(chips)}</div>'
        f"{_totals_line(result)}"
        "</div>"
        "</header>"
    )


# -- overview -------------------------------------------------------------------
def _overview(
    result: PipelineResult, hosts: list[_Host], vulns: list[ToolRecord], ran: set[str]
) -> str:
    panels = [
        p
        for p in (
            _severity_panel(vulns, "nuclei" in ran),
            _tools_panel(result),
            _http_panel(result.records),
        )
        if p
    ]
    grid = f'<div class="grid2">{"".join(panels)}</div>' if panels else ""
    return _heading("Overview") + _tiles(result, hosts, vulns, ran) + grid


def _tiles(
    result: PipelineResult, hosts: list[_Host], vulns: list[ToolRecord], ran: set[str]
) -> str:
    nodes = result.nodes
    failed = sum(1 for n in nodes if not n.ok and not n.skipped)
    skipped = sum(1 for n in nodes if n.skipped)
    passed = len(nodes) - failed - skipped
    producers = sum(1 for count in result.totals_by_tool.values() if count)
    if not nodes:
        stage_note = "nothing ran"
    elif failed or skipped:
        stage_note = " · ".join(
            p
            for p in (f"{failed} failed" if failed else "", f"{skipped} skipped" if skipped else "")
            if p
        )
    else:
        stage_note = "all passed"
    tiles: list[dict[str, Any]] = [
        {
            "label": "records",
            "value": len(result.records),
            "icon": "list",
            "sub": f"from {producers} tool(s)" if producers else "nothing found",
        },
        {
            "label": "stages",
            "value": passed,
            "of": len(nodes),
            "icon": "layers",
            "sub": stage_note,
            "tone": "t-err" if failed else ("t-warn" if skipped or not nodes else "t-ok"),
        },
        {
            "label": "duration",
            "value": _human_duration(result.duration_s),
            "icon": "clock",
            "sub": f"from {result.started_at.astimezone(timezone.utc):%H:%M:%S} UTC"
            if result.started_at
            else "",
            "tone": "t-info",
        },
    ]
    if hosts:
        live = sum(1 for h in hosts if h.live)
        tiles.append(
            {
                "label": "hosts",
                "value": len(hosts),
                "icon": "globe",
                "sub": f"{live} live",
                "tone": "t-info",
            }
        )
    if any(r.kind == "http" for r in result.records):
        live = sum(1 for h in hosts if h.live)
        share = f"{live * 100 // len(hosts)}% of hosts" if hosts else ""
        tiles.append(
            {"label": "live web", "value": live, "icon": "pulse", "sub": share, "tone": "t-ok"}
        )
    ports = sum(len(h.ports) for h in hosts)
    if ports:
        on = sum(1 for h in hosts if h.ports)
        tiles.append(
            {
                "label": "open ports",
                "value": ports,
                "icon": "server",
                "sub": f"on {on} host(s)",
                "tone": "t-violet",
            }
        )
    if vulns or "nuclei" in ran:
        counts = Counter(_severity(r) for r in vulns)
        worst = next((s for s in _SEVERITIES if counts[s]), "")
        top = " · ".join([f"{counts[s]} {s}" for s in _SEVERITIES if counts[s]][:2])
        tiles.append(
            {
                "label": "findings",
                "value": len(vulns),
                "icon": "shield",
                "sub": top or "none matched",
                "tone": f"sev-{worst}" if worst else "t-ok",
            }
        )
    secrets = sum(1 for r in result.records if r.kind == "secret")
    if secrets or "gitleaks" in ran:
        tiles.append(
            {
                "label": "secrets",
                "value": secrets,
                "icon": "key",
                "sub": "leaked" if secrets else "none found",
                "tone": "t-err" if secrets else "t-ok",
            }
        )
    shots = sum(1 for r in result.records if r.kind == "screenshot")
    if shots:
        tiles.append({"label": "screenshots", "value": shots, "icon": "camera", "tone": "t-info"})
    rows = -(-len(tiles) // 6)
    columns = -(-len(tiles) // rows)
    cells = "".join(_tile(index=index, **spec) for index, spec in enumerate(tiles))
    return f'<div class="tiles" style="--cols:{columns}">{cells}</div>'


def _tile(
    label: str,
    value: int | str,
    *,
    icon: str,
    index: int,
    sub: str = "",
    tone: str = "",
    of: int | None = None,
) -> str:
    if isinstance(value, int):
        number = f'<span data-count="{value}">{value:,}</span>'
        if of is not None:
            number += f'<span class="of">/{of:,}</span>'
    else:
        number = _e(value)
    small = f"<small>{_e(sub)}</small>" if sub else ""
    return (
        f'<div class="tile {tone}" style="--i:{index}"><span class="ico">{_ICONS[icon]}</span>'
        f'<span class="lbl">{_e(label)}</span><b class="num">{number}</b>{small}</div>'
    )


def _severity_panel(vulns: list[ToolRecord], nuclei_ran: bool) -> str:
    if not vulns:
        if not nuclei_ran:
            return ""
        return (
            '<div class="panel"><h3>Severity</h3><div class="clean">'
            '<svg viewBox="0 0 48 48" aria-hidden="true"><path class="shield" d="M24 4l16 6v12c0 10-7 17.5-16 21-9-3.5-16-11-16-21V10z"/>'
            '<path class="chk" pathLength="1" d="M16 24.5l5.5 5.5L33 18.5"/></svg>'
            "<div><b>No vulnerabilities found</b><p>nuclei matched no templates against the targets.</p></div>"
            "</div></div>"
        )
    counts = Counter(_severity(r) for r in vulns)
    total = len(vulns)
    present = [s for s in _SEVERITIES if counts[s]]
    radius = 52
    circumference = 2 * math.pi * radius
    gap = 2.0 if len(present) > 1 else 0.0
    segments: list[str] = []
    legend: list[str] = []
    offset = 0.0
    for index, severity in enumerate(present):
        length = circumference * counts[severity] / total
        segments.append(
            f'<circle class="seg sev-{severity}" cx="60" cy="60" r="{radius}" '
            f'style="--len:{max(length - gap, 0.6):.2f};--off:{-offset:.2f};--i:{index}"/>'
        )
        offset += length
        legend.append(
            f'<li class="sev-{severity}" style="--i:{index}"><i></i>{severity}'
            f'<b>{counts[severity]:,}</b><span class="pct">{counts[severity] * 100 / total:.0f}%</span></li>'
        )
    return (
        '<div class="panel"><h3>Severity</h3><div class="sev-wrap">'
        f'<div class="donut-box"><svg class="donut" viewBox="0 0 120 120" style="--c:{circumference:.2f}" '
        f'role="img" aria-label="{total} findings by severity">'
        f'<circle class="track" cx="60" cy="60" r="{radius}"/>{"".join(segments)}</svg>'
        f'<div class="donut-c"><b data-count="{total}">{total:,}</b><span>findings</span></div></div>'
        f'<ul class="legend">{"".join(legend)}</ul>'
        "</div></div>"
    )


def _tools_panel(result: PipelineResult) -> str:
    totals = sorted(result.totals_by_tool.items(), key=lambda item: -item[1])
    if not any(count for _, count in totals):
        return ""
    peak = max(count for _, count in totals) or 1
    rows = "".join(
        f'<li style="--w:{count * 100 / peak:.1f}%;--c:{_tool_color(tool)};--i:{index}">'
        f'<span class="name">{_e(tool)}</span><span class="track"><i></i></span>'
        f'<b data-count="{count}">{count:,}</b></li>'
        for index, (tool, count) in enumerate(totals)
    )
    return f'<div class="panel"><h3>Records by tool</h3><ul class="bars">{rows}</ul></div>'


def _http_panel(records: list[ToolRecord]) -> str:
    """Stacked bar of HTTP status classes across httpx results."""
    classes = Counter(
        int(getattr(r, "status_code", 0) or 0) // 100 for r in records if r.kind == "http"
    )
    classes = Counter({k: v for k, v in classes.items() if 1 <= k <= 5})
    total = sum(classes.values())
    if not total:
        return ""
    labels = {1: "1xx", 2: "2xx ok", 3: "3xx redirect", 4: "4xx client", 5: "5xx server"}
    order = sorted(classes)
    stack = "".join(
        f'<i class="http-{k}xx" style="--w:{classes[k] * 100 / total:.2f}%;--i:{i}" title="{labels[k]}: {classes[k]}"></i>'
        for i, k in enumerate(order)
    )
    legend = "".join(
        f'<li class="http-{k}xx"><i></i>{labels[k]}<b>{classes[k]:,}</b></li>' for k in order
    )
    return (
        '<div class="panel"><h3>HTTP responses</h3>'
        f'<div class="stack">{stack}</div><ul class="legend inline">{legend}</ul></div>'
    )


# -- pipeline ---------------------------------------------------------------------
def _pipeline_section(result: PipelineResult, seed: str | None) -> str:
    return (
        _heading("Pipeline", f"{len(result.nodes)} stage(s)")
        + f'<div class="panel flow">{_flow(result.nodes, seed)}</div>'
        + '<h3 class="sub">Stages</h3>'
        + '<div class="tbl"><table><thead><tr><th>tool</th><th>stage</th><th>records</th>'
        + "<th>status</th><th>error</th></tr></thead><tbody>"
        + _render_stages(result)
        + "</tbody></table></div>"
    )


def _flow(nodes: list[NodeResult], seed: str | None) -> str:
    """The pipeline as an SVG graph: seed → stages, laid out in columns by depth.

    A node reads ``input_from`` when set, else the previous node; its column is
    one past its source's. Live edges carry animated "packets" of data.
    """
    if not nodes:
        return '<p class="empty">no stages ran</p>'
    by_stage = {nr.node.stage: index for index, nr in enumerate(nodes)}
    parents: list[int] = []
    for index, nr in enumerate(nodes):
        source = nr.node.input_from
        parent = by_stage.get(source, index - 1) if source else index - 1
        parents.append(parent if 0 <= parent < index else -1)  # -1: the seed
    shift = 1 if seed else 0
    columns: list[int] = []
    for parent in parents:
        columns.append(shift if parent < 0 else columns[parent] + 1)
    per_column = Counter(columns)
    rows_max = max(per_column.values())
    step_x, step_y = _NODE_W + _GAP_X, _NODE_H + _GAP_Y

    def top(column: int) -> float:
        return _PAD + (rows_max - per_column[column]) * step_y / 2

    placed: Counter[int] = Counter()
    boxes: list[tuple[float, float]] = []
    for column in columns:
        boxes.append((_PAD + column * step_x, top(column) + placed[column] * step_y))
        placed[column] += 1
    seed_box: tuple[float, float] = (_PAD, _PAD + (rows_max - 1) * step_y / 2)
    width = 2 * _PAD + (max(columns) + 1) * step_x - _GAP_X
    height = 2 * _PAD + rows_max * step_y - _GAP_Y

    edges: list[str] = []
    for index, (nr, parent) in enumerate(zip(nodes, parents, strict=True)):
        if parent < 0 and not seed:
            continue
        sx, sy = seed_box if parent < 0 else boxes[parent]
        x1, y1 = sx + _NODE_W, sy + _NODE_H / 2
        x2, y2 = boxes[index][0], boxes[index][1] + _NODE_H / 2
        mid = (x1 + x2) / 2
        d = f"M{x1:.1f},{y1:.1f} C{mid:.1f},{y1:.1f} {mid:.1f},{y2:.1f} {x2:.1f},{y2:.1f}"
        state = _node_state(nr)
        kind = {"ok": "live", "failed": "fail", "skipped": "skip"}[state]
        edges.append(
            f'<path class="edge {kind}" pathLength="1" d="{d}" style="--i:{columns[index]}"/>'
        )
        feeds = parent < 0 or nodes[parent].count > 0
        if kind == "live" and feeds:
            color = "var(--accent)" if parent < 0 else _tool_color(nodes[parent].node.tool)
            for k in range(2):
                edges.append(
                    f'<circle class="pkt" r="3.2" style="--c:{color}">'
                    f'<animateMotion dur="2.4s" begin="{k * 1.2 + index * 0.15:.2f}s" repeatCount="indefinite" path="{d}"/>'
                    "</circle>"
                )

    shapes: list[str] = []
    if seed:
        x, y = seed_box
        shapes.append(
            f'<g transform="translate({x:.1f} {y:.1f})"><g class="fn seed" style="--i:0;--c:var(--accent)">'
            f"<title>seed: {_e(seed)}</title>"
            f'<rect class="fbox" width="{_NODE_W}" height="{_NODE_H}" rx="{_NODE_H / 2:.0f}"/>'
            f'<circle class="ping" cx="26" cy="{_NODE_H / 2:.0f}" r="6"/><circle class="fdot" cx="26" cy="{_NODE_H / 2:.0f}" r="5"/>'
            f'<text class="fstage" x="44" y="28">seed</text>'
            f'<text class="ftool" x="44" y="48">{_e(_clip(seed, 16))}</text></g></g>'
        )
    for index, nr in enumerate(nodes):
        x, y = boxes[index]
        state = _node_state(nr)
        tool, stage = nr.node.tool, nr.node.stage
        tip = f"{tool} · {stage}: {nr.count} record(s), {state}" + (
            f" — {nr.error}" if nr.error else ""
        )
        shapes.append(
            f'<g transform="translate({x:.1f} {y:.1f})">'
            f'<g class="fn st-{state}" style="--i:{columns[index]};--c:{_tool_color(tool)}">'
            f"<title>{_e(tip)}</title>"
            f'<rect class="fbox" width="{_NODE_W}" height="{_NODE_H}" rx="14"/>'
            f'<rect class="fstripe" x="0" y="14" width="3" height="{_NODE_H - 28}" rx="1.5"/>'
            f'<circle class="fdot" cx="20" cy="24" r="5"/>'
            f'<text class="ftool" x="33" y="29">{_e(_clip(tool, 13))}</text>'
            f'<text class="fstage" x="20" y="52">{_e(_clip(stage, 15))}</text>'
            f'<text class="fcount" x="{_NODE_W - 16}" y="53" text-anchor="end">{nr.count:,}</text>'
            f'<g class="fstat" transform="translate({_NODE_W - 22} 24)"><circle r="8"/>'
            f'<path d="{_STATE_GLYPH[state]}"/></g>'
            "</g></g>"
        )
    return (
        f'<svg viewBox="0 0 {width:.0f} {height:.0f}" style="min-width:{width * 0.62:.0f}px" '
        f'role="img" aria-label="pipeline graph">{"".join(edges)}{"".join(shapes)}</svg>'
    )


#: Check, cross and dash drawn inside a node's status disc.
_STATE_GLYPH = {
    "ok": "M-3.5 0.2l2.4 2.4 4.6-4.8",
    "failed": "M-3-3l6 6M3-3l-6 6",
    "skipped": "M-3.5 0h7",
}


def _node_state(nr: NodeResult) -> str:
    if nr.ok:
        return "ok"
    return "skipped" if nr.skipped else "failed"


def _render_stages(result: PipelineResult) -> str:
    """Rows for the per-stage summary table."""
    rows: list[str] = []
    for index, node_result in enumerate(result.nodes):
        node = node_result.node
        state = _node_state(node_result)
        error = (
            f'<td class="dim">{_e(node_result.error)}</td>'
            if node_result.error
            else '<td class="dim">—</td>'
        )
        rows.append(
            f'<tr style="--i:{min(index, _MAX_STAGGER)}">'
            f'<td>{_tool_label(node.tool)}</td><td class="mono">{_e(node.stage)}</td>'
            f'<td class="mono">{node_result.count:,}</td>'
            f'<td><span class="badge st-{state}">{state}</span></td>{error}</tr>'
        )
    return "\n".join(rows) if rows else '<tr><td colspan="5" class="dim">no stages ran</td></tr>'


# -- hosts ------------------------------------------------------------------------
@dataclass
class _Host:
    """One host and everything the run found on it."""

    name: str
    order: int
    live: bool = False
    status_code: int = 0
    title: str = ""
    ports: set[str] = field(default_factory=set)
    severities: Counter[str] = field(default_factory=Counter)
    fuzz: int = 0
    shots: int = 0

    def worst(self) -> str:
        return next((s for s in _SEVERITIES if self.severities[s]), "")

    def risk(self) -> tuple[Any, ...]:
        """Sort key: most criticals first, then highs, ...; live before dead; then discovery order."""
        return (*(-self.severities[s] for s in _SEVERITIES), not self.live, self.order)


def _hosts(records: Iterable[ToolRecord]) -> list[_Host]:
    """Fold records into hosts keyed by hostname, riskiest first.

    The same keying as the live topology map: a nuclei match on
    ``https://a.example.com/x`` lands on the host subfinder found as ``a.example.com``.
    """
    hosts: dict[str, _Host] = {}
    for record in records:
        if record.kind not in _HOST_KINDS or not record.target:
            continue
        name = hostname_of(record.target).strip()
        if not name:
            continue
        host = hosts.get(name)
        if host is None:
            host = hosts[name] = _Host(name=name, order=len(hosts))
        kind = record.kind
        if kind == "http":
            host.live = True
            host.status_code = int(getattr(record, "status_code", 0) or 0) or host.status_code
            host.title = str(getattr(record, "title", "") or "") or host.title
        elif kind == "vuln":
            host.severities[_severity(record)] += 1
        elif kind == "port":
            port = getattr(record, "port", 0)
            if port:
                host.ports.add(str(port))
        elif kind == "scan":
            ports = str(getattr(record, "ports_list", "") or "")
            host.ports.update(p.strip() for p in ports.split(",") if p.strip())
        elif kind == "fuzz":
            host.fuzz += 1
        elif kind == "screenshot":
            host.shots += 1
    return sorted(hosts.values(), key=_Host.risk)


def _hosts_section(hosts: list[_Host]) -> str:
    rows: list[str] = []
    for index, host in enumerate(hosts[:_MAX_HOSTS]):
        code = (
            f'<span class="badge http-{host.status_code // 100}xx">{host.status_code}</span>'
            if host.status_code
            else '<span class="dim">—</span>'
        )
        ports = sorted(host.ports, key=lambda p: (not p.isdigit(), int(p) if p.isdigit() else 0, p))
        port_chips = "".join(f'<span class="port">{_e(p)}</span>' for p in ports[:12])
        if len(ports) > 12:
            port_chips += f'<span class="port more">+{len(ports) - 12}</span>'
        findings = "".join(
            f'<span class="sevn sev-{s}" title="{s}">{host.severities[s]} {_SEVERITY_SHORT[s]}</span>'
            for s in _SEVERITIES
            if host.severities[s]
        )
        extras = " · ".join(
            part
            for part in (
                f"{host.fuzz} fuzz" if host.fuzz else "",
                f"{host.shots} shot(s)" if host.shots else "",
            )
            if part
        )
        rows.append(
            f'<tr style="--i:{min(index, _MAX_STAGGER)}">'
            f'<td class="host"><i class="ld{" on" if host.live else ""}"></i>{_e(host.name)}</td>'
            f"<td>{code}</td>"
            f'<td class="ttl" title="{_e(host.title)}">{_e(_clip(host.title, 70)) or _DASH}</td>'
            f'<td><div class="ports">{port_chips or _DASH}</div></td>'
            f'<td><div class="ports">{findings or _DASH}</div></td>'
            f'<td class="dim">{_e(extras) or "—"}</td></tr>'
        )
    hidden = len(hosts) - _MAX_HOSTS
    note = (
        f'<p class="note">… and {hidden:,} more host(s) — every record is in the table below.</p>'
        if hidden > 0
        else ""
    )
    live = sum(1 for h in hosts if h.live)
    return (
        _heading("Hosts", f"{len(hosts):,} discovered · {live:,} live")
        + '<div class="tbl"><table class="hosts"><thead><tr><th>host</th><th>http</th><th>title</th>'
        + "<th>ports</th><th>findings</th><th>other</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table></div>"
        + note
    )


# -- findings ---------------------------------------------------------------------
def _findings_section(vulns: list[ToolRecord], secrets: list[ToolRecord]) -> str:
    ordered = sorted(
        vulns, key=lambda r: _SEVERITIES.index(_severity(r))
    )  # stable: keeps arrival order
    major = [r for r in ordered if _severity(r) in _MAJOR]
    minor = [r for r in ordered if _severity(r) not in _MAJOR]
    parts = [_heading("Findings", f"{len(vulns):,} vulnerabilities · {len(secrets):,} secrets")]
    if major:
        parts.append(_cards(_vuln_card(r, i) for i, r in enumerate(major[:_MAX_CARDS])))
        parts.append(_more_note(len(major)))
    if minor:
        cards = _cards(_vuln_card(r, i) for i, r in enumerate(minor[:_MAX_CARDS]))
        summary = f"{len(minor):,} low / info finding(s)"
        parts.append(
            f'<details class="more"{"" if major else " open"}><summary>{summary}</summary>{cards}{_more_note(len(minor))}</details>'
        )
    if secrets:
        parts.append('<h3 class="sub">Secrets</h3>')
        parts.append(_cards(_secret_card(r, i) for i, r in enumerate(secrets[:_MAX_CARDS])))
        parts.append(_more_note(len(secrets)))
    return "".join(parts)


def _cards(cards: Iterable[str]) -> str:
    return f'<div class="cards">{"".join(cards)}</div>'


def _more_note(count: int) -> str:
    hidden = count - _MAX_CARDS
    return (
        f'<p class="note">… and {hidden:,} more — see the record table.</p>' if hidden > 0 else ""
    )


def _vuln_card(record: ToolRecord, index: int) -> str:
    severity = _severity(record)
    info = getattr(record, "info", {}) or {}
    classification = info.get("classification")
    if not isinstance(classification, dict):
        classification = {}
    name = str(getattr(record, "name", "") or getattr(record, "template_id", "") or "finding")
    template_id = str(getattr(record, "template_id", "") or "")
    tags = [f'<span class="tag id">{_e(template_id)}</span>'] if template_id else []
    cves = [c for c in _as_list(classification.get("cve-id")) if c.lower() != template_id.lower()]
    tags += [f'<span class="tag cve">{_e(cve)}</span>' for cve in cves[:3]]
    score = classification.get("cvss-score")
    if score not in (None, "", 0):
        tags.append(f'<span class="tag cvss">CVSS {_e(str(score))}</span>')
    tags += [f'<span class="tag">{_e(tag)}</span>' for tag in _as_list(info.get("tags"))[:5]]
    description = str(info.get("description") or "").strip()
    desc = f'<p class="desc">{_e(_clip(description, 260))}</p>' if description else ""
    return (
        f'<article class="card sev-{severity}" style="--i:{min(index, 12)}">'
        f'<header><span class="badge sev-{severity}">{severity}</span><h4>{_e(name)}</h4></header>'
        f'<p class="where">{_link(record.target)}</p>{desc}'
        f"<footer>{''.join(tags)}</footer></article>"
    )


def _secret_card(record: ToolRecord, index: int) -> str:
    rule = str(getattr(record, "rule_id", "") or "secret")
    description = str(getattr(record, "description", "") or "")
    commit = str(getattr(record, "commit", "") or "")
    footer = (
        f'<footer><span class="tag id">commit {_e(commit[:10])}</span></footer>' if commit else ""
    )
    desc = f'<p class="desc">{_e(description)}</p>' if description else ""
    return (
        f'<article class="card t-err" style="--i:{min(index, 12)}">'
        f'<header><span class="badge t-err">secret</span><h4>{_e(rule)}</h4></header>'
        f'<p class="where">{_e(record.target)}</p>{desc}{footer}</article>'
    )


# -- screenshots --------------------------------------------------------------------
def _shots_section(shots: list[ToolRecord]) -> str:
    figures: list[str] = []
    for index, record in enumerate(shots[:_MAX_SHOTS]):
        name = re.split(r"[\\/]", str(getattr(record, "filename", "")))[-1]
        src = _e("screenshots/" + quote(name))
        url = str(getattr(record, "url", "") or record.target)
        title = str(getattr(record, "title", "") or "")
        status = int(getattr(record, "status_code", 0) or 0)
        code = f'<span class="badge http-{status // 100}xx">{status}</span>' if status else ""
        figures.append(
            f'<figure class="shot" style="--i:{min(index, 12)}">'
            f'<a href="{src}" data-caption="{_e(url)}"><img src="{src}" loading="lazy" alt="screenshot of {_e(url)}"></a>'
            f'<figcaption><span class="u">{code}<span class="mono">{_e(_clip(url, 60))}</span></span>'
            f"{f'<span class=ttl>{_e(_clip(title, 80))}</span>' if title else ''}</figcaption></figure>"
        )
    hidden = len(shots) - _MAX_SHOTS
    note = f'<p class="note">… and {hidden:,} more in screenshots/.</p>' if hidden > 0 else ""
    return (
        _heading("Screenshots", f"{len(shots):,} page(s)")
        + f'<div class="shots">{"".join(figures)}</div>{note}'
    )


# -- records ----------------------------------------------------------------------
def _records_section(records: list[ToolRecord]) -> str:
    by_tool = Counter(r.tool for r in records)
    filters = "".join(
        f'<button type="button" data-tool="{_e(tool)}" aria-pressed="false" style="--c:{_tool_color(tool)}">'
        f"{_e(tool)} <b>{count:,}</b></button>"
        for tool, count in by_tool.most_common()
    )
    toolbar = (
        '<div class="toolbar">'
        f'<label class="search">{_ICONS["search"]}<input id="q" type="search" placeholder="filter records…" '
        'autocomplete="off" spellcheck="false" aria-label="filter records"></label>'
        f'<div class="filters"><button type="button" data-tool="" aria-pressed="true">all <b>{len(records):,}</b></button>{filters}</div>'
        f'<span class="shown"><span id="shown">{len(records):,}</span> / {len(records):,} records</span>'
        "</div>"
        if records
        else ""
    )
    headers = "".join(
        f'<th data-sort="{kind}"{" aria-sort=ascending" if label == "#" else ""}><button type="button">{label}</button></th>'
        for label, kind in _HEADERS
    )
    return (
        _heading("Records", f"{len(records):,} total")
        + toolbar
        + f'<div class="tbl"><table id="record-table"><thead><tr>{headers}</tr></thead><tbody>'
        + _render_records(records)
        + '</tbody></table></div><p id="none" class="empty" hidden>no matching records</p>'
        + '<button id="more" class="more-btn" type="button" hidden>show more</button>'
    )


def _render_records(records: list[ToolRecord]) -> str:
    """Rows for the full record listing."""
    rows = [_render_record(index, record) for index, record in enumerate(records, start=1)]
    return "\n".join(rows) if rows else '<tr><td colspan="5" class="dim">no records</td></tr>'


def _render_record(index: int, record: ToolRecord) -> str:
    detail = _e(_format_detail(record.as_dict()))
    tone = f' class="{_tone(record)}"' if _tone(record) else ""
    return (
        f'<tr data-tool="{_e(record.tool)}"{tone} style="--i:{min(index - 1, _MAX_STAGGER)}">'
        f'<td class="mono dim">{index}</td><td>{_tool_label(record.tool)}</td>'
        f'<td><span class="tag">{_e(record.kind)}</span></td><td class="target">{_link(record.target)}</td>'
        f'<td class="detail">{detail}</td></tr>'
    )


def _format_detail(as_dict: dict[str, object]) -> str:
    """Flatten a record dict into a short, readable substring (first field wins)."""
    skip = {"tool", "line_number", "raw", "target", "kind", "stage"}
    seen: list[str] = []
    for key, value in as_dict.items():
        if key in skip or value in ("", None):
            continue
        seen.append(f"{key}={value if not isinstance(value, list) else ','.join(map(str, value))}")
    return " ".join(seen)


# -- run ----------------------------------------------------------------------------
def _run_section(result: PipelineResult, run: RunInfo) -> str:
    """The provenance grid; every value is escaped (the seed is user input,
    tool versions come from install records)."""
    info = run.as_dict(result)
    versions = "".join(
        '<span class="tag">' + _e(f"{tool} {version or _EM_DASH}") + "</span>"
        for tool, version in sorted(run.tool_versions.items())
    )
    duration = info["duration_s"]
    # (label, value, columns spanned of 4): three full rows on a wide screen.
    rows = [
        ("pipeline", _cell(info["pipeline"]), 1),
        ("seed", _cell(info["seed"]), 2),
        ("platform", _cell(info["platform"]), 1),
        ("session", _cell(info["session_id"]), 2),
        ("started (UTC)", _cell(info["started_at"]), 1),
        ("duration", _cell(None if duration is None else f"{duration:.1f} s"), 1),
        ("cyberfw", _cell(info["cyberfw_version"]), 1),
        ("tools", f'<div class="ports">{versions}</div>' if versions else _DASH, 3),
    ]
    cells = "".join(
        f'<div style="--span:{span}"><dt>{_e(label)}</dt><dd>{value}</dd></div>'
        for label, value, span in rows
    )
    return _heading("Run", "provenance") + f'<dl class="run">{cells}</dl>'


# -- helpers --------------------------------------------------------------------------
_EM_DASH = "—"
_DASH = f'<span class="dim">{_EM_DASH}</span>'


def _e(value: str) -> str:
    return html.escape(value, quote=True)


def _cell(value: object) -> str:
    return _DASH if value is None else _e(str(value))


def _heading(title: str, note: str = "") -> str:
    count = f'<span class="count">{_e(note)}</span>' if note else ""
    return f'<div class="sec-h"><h2>{_e(title)}</h2>{count}</div>'


def _tool_label(tool: str) -> str:
    return f'<span class="tool" style="--c:{_tool_color(tool)}">{_e(tool)}</span>'


def _tool_color(tool: str) -> str:
    return (
        _TOOL_COLORS.get(tool)
        or _FALLBACK_COLORS[zlib.crc32(tool.encode("utf-8")) % len(_FALLBACK_COLORS)]
    )


def _link(target: str) -> str:
    """A target as a link when it is a web URL; anything else (``javascript:``,
    a file path, a bare host) stays plain text."""
    if target.lower().startswith(("http://", "https://")):
        safe = _e(target)
        return f'<a href="{safe}" target="_blank" rel="noopener noreferrer">{safe}</a>'
    return _e(target)


def _severity(record: ToolRecord) -> str:
    severity = str(getattr(record, "severity", "") or "").lower()
    return severity if severity in _SEVERITIES else "unknown"


def _tone(record: ToolRecord) -> str:
    """Row tone: severity first, then HTTP status class — the precedence of
    :func:`cyberfw.ui.record_style`, so the page reads like the live view."""
    severity = str(getattr(record, "severity", "") or "").lower()
    if severity in _SEVERITIES[:-1]:
        return f"sev-{severity}"
    status = getattr(record, "status_code", 0) or getattr(record, "status", 0)
    try:
        leading = int(status) // 100
    except (TypeError, ValueError):
        return ""
    return f"http-{leading}xx" if 2 <= leading <= 5 else ""


def _as_list(value: object) -> list[str]:
    """nuclei writes tags / CVE ids as a list or a comma-joined string."""
    if value in (None, ""):
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple)):
        return [str(part) for part in value if part not in (None, "")]
    return [str(value)]


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _totals_line(result: PipelineResult) -> str:
    """``59 records · ● subfinder 12 · ● naabu 18 …`` under the headline."""
    parts = "".join(
        f'<span class="tool" style="--c:{_tool_color(tool)}">{_e(tool)} <b>{count:,}</b></span>'
        for tool, count in result.totals_by_tool.items()
    )
    return f'<p class="sum"><b>{len(result.records):,}</b> records{parts or " · no records"}</p>'


def _when(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _human_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, secs = divmod(int(round(seconds)), 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


def _resolve_path(
    output_path: Path | None, session_id: str | None, reports_dir: Path | None
) -> Path:
    if output_path is not None:
        return output_path
    base = reports_dir or Path.cwd() / "reports"
    session = session_id or "default"
    return base / session / "report.html"


# -- assets -----------------------------------------------------------------------------
def _icon(body: str) -> str:
    return (
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" '
        f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{body}</svg>'
    )


_ICONS = {
    "list": _icon(
        '<path d="M9 6h11M9 12h11M9 18h11"/><circle cx="4.5" cy="6" r="1"/><circle cx="4.5" cy="12" r="1"/><circle cx="4.5" cy="18" r="1"/>'
    ),
    "layers": _icon('<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>'),
    "clock": _icon('<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>'),
    "globe": _icon(
        '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/>'
    ),
    "pulse": _icon('<path d="M3 12h4l3-8 4 16 3-8h4"/>'),
    "server": _icon(
        '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>'
    ),
    "shield": _icon(
        '<path d="M12 3l8 3v6c0 5-3.5 8.5-8 9.5-4.5-1-8-4.5-8-9.5V6z"/><path d="M12 8v5M12 16.5h.01"/>'
    ),
    "key": _icon('<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3M14.5 8.5l2 2"/>'),
    "camera": _icon('<path d="M4 8h3l2-3h6l2 3h3v11H4z"/><circle cx="12" cy="13" r="3.5"/>'),
    "search": _icon('<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>'),
}

_LIGHTBOX = '<div id="lightbox" class="lightbox" hidden><figure><img alt=""><figcaption></figcaption></figure></div>'

#: Runs in ``<head>`` before first paint: marks JS as available (sections may
#: start hidden for their reveal) and applies a remembered theme without a flash.
_HEAD_JS = (
    "document.documentElement.classList.add('js');"
    "try{var t=localStorage.getItem('cyberfw-theme');"
    "if(t==='light'||t==='dark')document.documentElement.setAttribute('data-theme',t)}catch(e){}"
)

_JS = r"""
(() => {
  const doc = document.documentElement;
  const still = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const fmt = new Intl.NumberFormat('en-US');

  // Theme toggle; the head script already applied a remembered choice.
  const toggle = document.getElementById('theme');
  toggle.addEventListener('click', () => {
    const light = doc.dataset.theme ? doc.dataset.theme === 'light'
      : matchMedia('(prefers-color-scheme: light)').matches;
    doc.dataset.theme = light ? 'dark' : 'light';
    try { localStorage.setItem('cyberfw-theme', doc.dataset.theme); } catch (e) {}
  });

  // Numbers count up to the value the page already carries.
  const countUp = (el) => {
    const end = Number(el.dataset.count);
    if (!end || still) return;
    const t0 = performance.now(), dur = 1100;
    const step = (now) => {
      const p = Math.min(1, (now - t0) / dur);
      el.textContent = fmt.format(Math.round(end * (1 - Math.pow(1 - p, 3))));
      if (p < 1) requestAnimationFrame(step);
    };
    el.textContent = '0';
    requestAnimationFrame(step);
  };

  // The headline decodes itself from noise, left to right.
  const glyphs = '01<>/\\[]{}#$%&*+=?';
  const scramble = (el) => {
    const final = el.textContent;
    if (still || !final) return;
    const t0 = performance.now(), dur = Math.min(1600, 600 + final.length * 30);
    const step = (now) => {
      const p = Math.min(1, (now - t0) / dur), fixed = Math.floor(final.length * p);
      let out = final.slice(0, fixed);
      for (let i = fixed; i < final.length; i++) {
        out += final[i] === ' ' ? ' ' : glyphs[(Math.random() * glyphs.length) | 0];
      }
      el.textContent = p < 1 ? out : final;
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  };

  // Sections fade in as they scroll into view, then play their numbers.
  const sections = document.querySelectorAll('.reveal');
  const play = (section) => {
    section.classList.add('in');
    section.querySelectorAll('[data-count]').forEach(countUp);
    section.querySelectorAll('[data-scramble]').forEach(scramble);
  };
  if (still || !('IntersectionObserver' in window)) {
    sections.forEach((s) => s.classList.add('in'));
  } else {
    const io = new IntersectionObserver((entries) => entries.forEach((e) => {
      if (e.isIntersecting) { io.unobserve(e.target); play(e.target); }
    }), { rootMargin: '0px 0px -6% 0px' });
    sections.forEach((s) => io.observe(s));
  }
  addEventListener('beforeprint', () => sections.forEach((s) => s.classList.add('in')));
  if (still) document.querySelectorAll('svg').forEach((s) => s.pauseAnimations && s.pauseAnimations());

  // Highlight the nav link of the section in view.
  const links = new Map([...document.querySelectorAll('.links a')].map((a) => [a.hash.slice(1), a]));
  if ('IntersectionObserver' in window) {
    const spy = new IntersectionObserver((entries) => entries.forEach((e) => {
      if (!e.isIntersecting) return;
      links.forEach((a) => a.classList.toggle('on', a.hash === '#' + e.target.id));
    }), { rootMargin: '-35% 0px -60% 0px' });
    links.forEach((_, id) => { const s = document.getElementById(id); if (s) spy.observe(s); });
  }

  // Record table: text filter, per-tool chips and sortable columns. Only one
  // page of rows lives in the table and the rest wait detached, so filtering
  // and sorting a scan of thousands of records never re-lays-out all of them.
  const table = document.getElementById('record-table');
  const search = document.getElementById('q');
  if (table && search) {
    const PAGE = 500;
    const body = table.tBodies[0];
    const rows = [...body.querySelectorAll('tr[data-tool]')];
    const text = new Map(rows.map((r) => [r, r.textContent.toLowerCase()]));
    const shown = document.getElementById('shown');
    const none = document.getElementById('none');
    const more = document.getElementById('more');
    const chips = document.querySelectorAll('.filters button');
    const collator = new Intl.Collator(undefined, { numeric: true });
    let tool = '', limit = PAGE, matches = rows;
    const render = () => {
      const frag = document.createDocumentFragment();
      matches.slice(0, limit).forEach((r) => frag.appendChild(r));
      body.replaceChildren(frag);
      shown.textContent = fmt.format(matches.length);
      none.hidden = matches.length > 0;
      const rest = matches.length - limit;
      more.hidden = rest <= 0;
      if (rest > 0) more.textContent = 'show ' + fmt.format(Math.min(rest, PAGE)) + ' more · ' + fmt.format(rest) + ' hidden';
    };
    const apply = () => {
      const needle = search.value.trim().toLowerCase();
      matches = rows.filter((r) => (!tool || r.dataset.tool === tool) && (!needle || text.get(r).includes(needle)));
      limit = PAGE;
      table.classList.add('settled');
      render();
    };
    search.addEventListener('input', apply);
    chips.forEach((b) => b.addEventListener('click', () => {
      tool = b.dataset.tool;
      chips.forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
      apply();
    }));
    more.addEventListener('click', () => { limit += PAGE; render(); });
    addEventListener('beforeprint', () => { limit = Infinity; render(); });
    table.tHead.querySelectorAll('th').forEach((th) => th.querySelector('button').addEventListener('click', () => {
      const col = th.cellIndex, numeric = th.dataset.sort === 'num';
      const dir = th.getAttribute('aria-sort') === 'ascending' ? -1 : 1;
      table.tHead.querySelectorAll('th').forEach((x) => x.removeAttribute('aria-sort'));
      th.setAttribute('aria-sort', dir === 1 ? 'ascending' : 'descending');
      const keys = new Map(rows.map((r) => [r, numeric ? Number(r.cells[col].textContent) : r.cells[col].textContent]));
      rows.sort((a, b) => dir * (numeric ? keys.get(a) - keys.get(b) : collator.compare(keys.get(a), keys.get(b))));
      apply();
    }));
    table.classList.add('paged');
    render();
  }

  // Screenshots: a placeholder for a missing file, a lightbox for the rest.
  document.querySelectorAll('.shot img').forEach((img) => {
    const miss = () => img.closest('.shot').classList.add('missing');
    if (img.complete && !img.naturalWidth) miss(); else img.addEventListener('error', miss);
  });
  const box = document.getElementById('lightbox');
  if (box) {
    const big = box.querySelector('img'), cap = box.querySelector('figcaption');
    const close = () => {
      box.classList.remove('open');
      setTimeout(() => { box.hidden = true; big.removeAttribute('src'); }, 220);
    };
    document.querySelectorAll('.shot a').forEach((a) => a.addEventListener('click', (ev) => {
      ev.preventDefault();
      if (a.closest('.shot').classList.contains('missing')) return;
      big.src = a.getAttribute('href');
      big.alt = cap.textContent = a.dataset.caption || '';
      box.hidden = false;
      requestAnimationFrame(() => requestAnimationFrame(() => box.classList.add('open')));
    }));
    box.addEventListener('click', close);
    addEventListener('keydown', (ev) => { if (ev.key === 'Escape' && !box.hidden) close(); });
  }
})();
"""


def _sha256(script: str) -> str:
    return (
        "'sha256-"
        + base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
        + "'"
    )


#: Only the two scripts above may run: an escaping slip in scan data still
#: could not execute. Screenshots load from the session directory.
_CSP = (
    "default-src 'none'; "
    f"script-src {_sha256(_HEAD_JS)} {_sha256(_JS)}; "
    "style-src 'unsafe-inline'; img-src 'self' data: file:; "
    "base-uri 'none'; form-action 'none'"
)

#: Light palette, applied for ``prefers-color-scheme: light``, the theme toggle and print.
_LIGHT = """
  color-scheme: light;
  --bg: #ffffff; --bg-2: #f5f7f9; --panel: #ffffff; --panel-2: #fafbfc;
  --line: rgba(17, 24, 39, .10); --line-2: rgba(17, 24, 39, .20);
  --text: #141a22; --muted: #5a6573; --dim: #8a929c;
  --accent: #2f55c7; --accent-2: #1f7f93; --violet: #6d4fe0;
  --ok: #1f8a5b; --warn: #946800; --err: #c52a45;
  --critical: #c42a47; --high: #b4591b; --medium: #8f6f0c; --low: #1f7d8e; --info: #2f66b8; --unknown: #6b7685;
"""

_CSS = (
    """
:root {
  color-scheme: dark;
  --bg: #14181e; --bg-2: #181d24; --panel: #181d24; --panel-2: #1d232b;
  --line: rgba(255, 255, 255, .10); --line-2: rgba(255, 255, 255, .20);
  --text: #e6ebf1; --muted: #98a2b1; --dim: #697181;
  --accent: #7f9cff; --accent-2: #5fb0c2; --violet: #a98bff;
  --ok: #4fb286; --warn: #d4a24a; --err: #e26178;
  --critical: #e26178; --high: #d98a52; --medium: #d2b256; --low: #57b0c2; --info: #7f9cff; --unknown: #98a2b1;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, "JetBrains Mono", "Cascadia Code", SFMono-Regular, Menlo, Consolas, monospace;
  --radius: 8px;
  --ease: ease;
}
@media (prefers-color-scheme: light) { :root:not([data-theme="dark"]) {"""
    + _LIGHT
    + """} }
:root[data-theme="light"] {"""
    + _LIGHT
    + """}

* { box-sizing: border-box; }
html { scroll-behavior: smooth; scroll-padding-top: 64px; -webkit-text-size-adjust: 100%; }
body { margin: 0; min-height: 100vh; background: var(--bg); color: var(--text); font: 14px/1.6 var(--sans); }
a { color: var(--accent); text-underline-offset: 2px; text-decoration-thickness: 1px; }
a:hover { text-decoration: underline; }
.mono, .target, .detail, .host { font-family: var(--mono); font-size: 12.5px; }
.dim { color: var(--dim); }

/* tone classes: components read var(--tone) */
.sev-critical { --tone: var(--critical); } .sev-high { --tone: var(--high); } .sev-medium { --tone: var(--medium); }
.sev-low { --tone: var(--low); } .sev-info { --tone: var(--info); } .sev-unknown { --tone: var(--unknown); }
.http-1xx { --tone: var(--muted); } .http-2xx { --tone: var(--ok); } .http-3xx { --tone: var(--accent-2); }
.http-4xx { --tone: var(--warn); } .http-5xx { --tone: var(--err); }
.st-ok, .t-ok { --tone: var(--ok); } .st-failed, .t-err { --tone: var(--err); } .st-skipped, .t-warn { --tone: var(--warn); }
.t-info { --tone: var(--accent-2); } .t-violet { --tone: var(--violet); }

/* navigation */
.nav { position: sticky; top: 0; z-index: 40; border-bottom: 1px solid var(--line); background: var(--bg); }
.nav-in { max-width: 960px; margin: 0 auto; padding: 0 20px; height: 52px; display: flex; align-items: center; gap: 16px; }
.logo { display: flex; align-items: center; gap: 8px; font: 600 15px var(--mono); text-decoration: none; color: var(--text); flex: none; }
.logo:hover { text-decoration: none; }
.logo i { width: 9px; height: 9px; border-radius: 2px; background: var(--accent); }
.links { display: flex; gap: 2px; overflow-x: auto; scrollbar-width: none; flex: 1; min-width: 0; }
.links::-webkit-scrollbar { display: none; }
.links a { padding: 6px 10px; border-radius: 6px; color: var(--muted); font-size: 13px; text-decoration: none; white-space: nowrap; }
.links a:hover { color: var(--text); text-decoration: none; }
.links a.on { color: var(--accent); }
#theme { flex: none; width: 32px; height: 32px; border-radius: 7px; border: 1px solid var(--line-2); background: var(--panel); color: var(--muted); cursor: pointer; display: grid; place-items: center; }
#theme:hover { color: var(--accent); border-color: var(--accent); }
#theme svg { width: 16px; height: 16px; }
html:not(.js) #theme { display: none; }

.wrap { max-width: 960px; margin: 0 auto; padding: 0 20px 64px; }

/* hero */
.hero { padding: 44px 0 8px; }
.eyebrow { color: var(--muted); font: 12px var(--mono); letter-spacing: .02em; }
.hero h1 { margin: 10px 0 16px; font: 600 clamp(26px, 4.6vw, 40px)/1.15 var(--sans); letter-spacing: -.02em; overflow-wrap: anywhere; }
.hero h1.long { font-size: clamp(21px, 3vw, 30px); }
.grad { color: var(--text); }
.meta { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.chip { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 6px; border: 1px solid var(--line); background: var(--panel-2); color: var(--muted); font-size: 12px; white-space: nowrap; }
.chip b { color: var(--text); font-weight: 600; }
.sum { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 16px; margin: 16px 0 0; color: var(--muted); font-size: 13px; }
.sum > b { color: var(--text); font: 600 15px var(--mono); margin-right: -10px; }
.sum .tool { font-weight: 500; color: var(--muted); }
.sum .tool b { color: var(--text); }
.pill { display: inline-flex; align-items: center; gap: 8px; padding: 4px 11px; border-radius: 6px; font: 600 12px var(--mono); letter-spacing: .03em;
  color: var(--tone); border: 1px solid color-mix(in srgb, var(--tone) 40%, transparent); background: color-mix(in srgb, var(--tone) 10%, transparent); }
.pill.success { --tone: var(--ok); }
.pill.failed { --tone: var(--err); }
.pill i { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }

/* sections */
section { margin-top: 44px; }
.sec-h { display: flex; align-items: baseline; flex-wrap: wrap; gap: 6px 12px; margin: 0 0 16px; padding-bottom: 8px; border-bottom: 1px solid var(--line); }
.sec-h h2 { margin: 0; font-size: 17px; font-weight: 600; letter-spacing: -.01em; }
.sec-h .count { color: var(--muted); font: 12px var(--mono); }
h3.sub { margin: 24px 0 10px; color: var(--muted); font-size: 12px; font-weight: 600; letter-spacing: .03em; }
.panel { padding: 16px; border-radius: var(--radius); border: 1px solid var(--line); background: var(--panel); }
.panel h3 { margin: 0 0 14px; color: var(--muted); font-size: 12px; font-weight: 600; letter-spacing: .03em; }
.grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 320px), 1fr)); gap: 12px; margin-top: 12px; }
.note, .empty { margin: 10px 2px 0; color: var(--dim); font: 12px var(--mono); }
.empty { padding: 18px; text-align: center; }

/* KPI tiles */
.tiles { display: grid; grid-template-columns: repeat(var(--cols, 4), minmax(0, 1fr)); gap: 10px; }
@media (max-width: 760px) { .tiles { grid-template-columns: repeat(auto-fit, minmax(min(100%, 140px), 1fr)); } }
.tile { padding: 14px; border-radius: var(--radius); border: 1px solid var(--line); border-left: 2px solid var(--tone, var(--line-2)); background: var(--panel); }
.tile .ico { width: 24px; height: 24px; display: grid; place-items: center; color: var(--tone, var(--muted)); }
.tile .ico svg { width: 16px; height: 16px; }
.tile .lbl { display: block; margin-top: 10px; color: var(--muted); font-size: 11.5px; letter-spacing: .03em; }
.tile .num { display: block; margin-top: 2px; font: 600 26px/1.15 var(--mono); letter-spacing: -.01em; font-variant-numeric: tabular-nums; white-space: nowrap; }
.tile .num .of { color: var(--dim); font-size: 17px; }
.tile small { display: block; margin-top: 3px; color: var(--muted); font-size: 12px; }

/* severity donut */
.sev-wrap { display: flex; flex-wrap: wrap; align-items: center; gap: 24px; }
.donut-box { position: relative; width: 150px; height: 150px; flex: none; }
.donut { width: 100%; height: 100%; overflow: visible; }
.donut .track { fill: none; stroke: var(--line); stroke-width: 12; }
.donut .seg { fill: none; stroke: var(--tone); stroke-width: 12; stroke-dasharray: var(--len) var(--c); stroke-dashoffset: var(--off);
  transform: rotate(-90deg); transform-origin: 60px 60px; }
.donut-c { position: absolute; inset: 0; display: grid; place-content: center; text-align: center; }
.donut-c b { font: 600 30px/1 var(--mono); }
.donut-c span { margin-top: 5px; color: var(--muted); font-size: 11px; letter-spacing: .04em; }
.legend { list-style: none; margin: 0; padding: 0; display: grid; gap: 9px; flex: 1; min-width: 170px; }
.legend li { display: grid; grid-template-columns: 10px 1fr auto auto; gap: 10px; align-items: center; font-size: 13px; text-transform: capitalize; }
.legend i { width: 10px; height: 10px; border-radius: 2px; background: var(--tone); }
.legend b { font-family: var(--mono); }
.legend .pct { width: 38px; text-align: right; color: var(--dim); font: 11px var(--mono); }
.legend.inline { display: flex; flex-wrap: wrap; gap: 8px 18px; margin-top: 14px; }
.legend.inline li { display: inline-flex; gap: 8px; text-transform: none; }
.clean { display: flex; align-items: center; gap: 16px; }
.clean svg { width: 52px; height: 52px; flex: none; color: var(--ok); }
.clean .shield { fill: color-mix(in srgb, var(--ok) 10%, transparent); stroke: currentColor; stroke-width: 2; stroke-linejoin: round; }
.clean .chk { fill: none; stroke: currentColor; stroke-width: 3; stroke-linecap: round; stroke-linejoin: round; }
.clean p { margin: 4px 0 0; color: var(--muted); }

/* records-per-tool bars and the HTTP stack */
.bars { list-style: none; margin: 0; padding: 0; display: grid; gap: 10px; }
.bars li { display: grid; grid-template-columns: minmax(72px, 112px) 1fr 56px; gap: 12px; align-items: center; font-size: 13px; }
.bars .name { display: flex; align-items: center; gap: 8px; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; font-family: var(--mono); }
.bars .name::before { content: ""; flex: none; width: 8px; height: 8px; border-radius: 2px; background: var(--c); }
.bars .track { height: 8px; border-radius: 3px; overflow: hidden; background: var(--line); }
.bars .track i { display: block; height: 100%; width: var(--w); border-radius: inherit; background: var(--c); }
.bars b { text-align: right; font-family: var(--mono); }
.stack { display: flex; gap: 2px; height: 10px; border-radius: 3px; overflow: hidden; background: var(--line); }
.stack i { width: var(--w); background: var(--tone); }

/* pipeline graph */
.flow { overflow-x: auto; padding: 8px 0; }
.flow svg { display: block; width: 100%; height: auto; }
.edge { fill: none; stroke: var(--line-2); stroke-width: 1.5; }
.edge.live { stroke: color-mix(in srgb, var(--accent) 45%, var(--line-2)); }
.edge.fail { stroke: color-mix(in srgb, var(--err) 60%, transparent); }
.edge.skip { stroke: color-mix(in srgb, var(--warn) 60%, transparent); stroke-dasharray: .02 .016; }
.pkt { display: none; }
.fbox { fill: var(--panel-2); stroke: var(--line-2); stroke-width: 1; }
.fn.st-failed .fbox { stroke: color-mix(in srgb, var(--err) 60%, transparent); }
.fn.st-skipped .fbox { stroke: color-mix(in srgb, var(--warn) 60%, transparent); stroke-dasharray: 5 4; }
.fstripe { fill: var(--c); }
.fdot { fill: var(--c); }
.ftool { fill: var(--text); font: 600 14px var(--mono); }
.fstage { fill: var(--muted); font: 12px var(--mono); }
.fcount { fill: var(--text); font: 600 18px var(--mono); }
.fstat circle { fill: var(--tone); }
.fstat path { fill: none; stroke: var(--panel-2); stroke-width: 2.2; stroke-linecap: round; stroke-linejoin: round; }
.seed .fbox { fill: color-mix(in srgb, var(--accent) 8%, var(--panel-2)); stroke: color-mix(in srgb, var(--accent) 45%, transparent); }
.seed .ping { display: none; }

/* tables */
.tbl { overflow-x: auto; border-radius: var(--radius); border: 1px solid var(--line); background: var(--panel); }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 9px 13px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: 13px; }
tbody tr:last-child td { border-bottom: 0; }
thead th { background: var(--panel-2); color: var(--muted); font-size: 11px; font-weight: 600; letter-spacing: .03em; white-space: nowrap; }
th button { all: unset; cursor: pointer; display: inline-flex; align-items: center; gap: 5px; }
th button:hover { color: var(--text); }
th button:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; border-radius: 3px; }
th[aria-sort] button { color: var(--accent); }
th[aria-sort=ascending] button::after { content: "▲"; font-size: 8px; }
th[aria-sort=descending] button::after { content: "▼"; font-size: 8px; }
tbody tr:hover { background: color-mix(in srgb, var(--text) 4%, transparent); }
html.js #record-table:not(.paged) tbody tr:nth-child(n+501) { display: none; }
#record-table tbody tr td:first-child { border-left: 2px solid var(--tone, transparent); }
#record-table .detail { color: var(--muted); overflow-wrap: anywhere; }
#record-table tr[class] .detail { color: color-mix(in srgb, var(--tone) 55%, var(--text)); }
.target { overflow-wrap: anywhere; min-width: 180px; }
.tool { display: inline-flex; align-items: center; gap: 7px; font: 600 12.5px var(--mono); white-space: nowrap; }
.tool::before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: var(--c); }
.badge { display: inline-flex; align-items: center; padding: 2px 7px; border-radius: 4px; white-space: nowrap; font: 600 11px var(--mono); letter-spacing: .02em;
  color: var(--tone); border: 1px solid color-mix(in srgb, var(--tone) 35%, transparent); background: color-mix(in srgb, var(--tone) 10%, transparent); }
.tag { display: inline-block; padding: 2px 7px; border-radius: 4px; background: var(--line); color: var(--muted); font: 11px var(--mono); white-space: nowrap; }
.tag.id { color: var(--text); }
.tag.cve { color: var(--critical); background: color-mix(in srgb, var(--critical) 10%, transparent); }
.tag.cvss { color: var(--high); background: color-mix(in srgb, var(--high) 10%, transparent); }
.host { white-space: nowrap; }
.ld { display: inline-block; width: 8px; height: 8px; margin-right: 10px; border-radius: 50%; background: var(--dim); vertical-align: 1px; }
.ld.on { background: var(--ok); }
.ttl { color: var(--muted); max-width: 280px; }
.ports { display: flex; flex-wrap: wrap; gap: 4px; }
.port { padding: 1px 6px; border-radius: 4px; font: 11.5px var(--mono); color: var(--violet); background: color-mix(in srgb, var(--violet) 12%, transparent); }
.port.more { color: var(--muted); background: var(--line); }
.sevn { min-width: 22px; padding: 1px 6px; border-radius: 4px; text-align: center; font: 600 11.5px var(--mono);
  color: var(--tone); background: color-mix(in srgb, var(--tone) 12%, transparent); }

/* record toolbar */
.toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; margin-bottom: 12px; }
html:not(.js) .toolbar { display: none; }
.search { position: relative; flex: 1 1 240px; }
.search svg { position: absolute; left: 12px; top: 50%; width: 16px; height: 16px; margin-top: -8px; color: var(--muted); pointer-events: none; }
.search input { width: 100%; padding: 9px 12px 9px 38px; border-radius: 7px; border: 1px solid var(--line-2); outline: none; background: var(--panel); color: var(--text); font: 13px var(--mono); }
.search input:focus { border-color: var(--accent); }
.filters { display: flex; flex-wrap: wrap; gap: 6px; }
.filters button { display: inline-flex; align-items: center; gap: 6px; padding: 6px 11px; border-radius: 6px; cursor: pointer; border: 1px solid var(--line-2); background: var(--panel); color: var(--muted); font: 12px var(--mono); }
.filters button:hover { color: var(--text); border-color: var(--c, var(--accent)); }
.filters button[aria-pressed=true] { color: var(--text); border-color: var(--c, var(--accent)); background: color-mix(in srgb, var(--c, var(--accent)) 12%, transparent); }
.filters button b { color: var(--dim); font-weight: 500; }
.shown { color: var(--muted); font: 12px var(--mono); }
.more-btn { display: block; margin: 14px auto 0; padding: 8px 16px; border-radius: 7px; cursor: pointer; border: 1px solid var(--line-2); background: var(--panel); color: var(--muted); font: 12.5px var(--mono); }
.more-btn:hover { color: var(--text); border-color: var(--accent); }
.more-btn[hidden] { display: none; }

/* finding cards */
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 340px), 1fr)); gap: 12px; }
.card { padding: 15px 15px 13px 18px; border-radius: var(--radius); border: 1px solid var(--line); border-left: 3px solid var(--tone); background: var(--panel); }
.card header { display: flex; align-items: flex-start; gap: 10px; }
.card h4 { margin: 0; font-size: 14.5px; line-height: 1.35; }
.card .where { margin: 10px 0 0; color: var(--muted); font: 12px var(--mono); overflow-wrap: anywhere; }
.card .desc { margin: 8px 0 0; color: var(--muted); font-size: 13px; }
.card footer { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 12px; }
details.more { margin-top: 14px; }
details.more summary { cursor: pointer; width: max-content; max-width: 100%; padding: 7px 13px; border-radius: 7px; margin-bottom: 12px; border: 1px solid var(--line-2); background: var(--panel); color: var(--muted); font: 12.5px var(--mono); }
details.more summary:hover { color: var(--text); border-color: var(--accent); }

/* screenshots */
.shots { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 260px), 1fr)); gap: 12px; }
.shot { margin: 0; overflow: hidden; border-radius: var(--radius); border: 1px solid var(--line); background: var(--panel); }
.shot a { position: relative; display: block; aspect-ratio: 16 / 10; overflow: hidden; background: var(--bg-2); cursor: zoom-in; }
.shot img { display: block; width: 100%; height: 100%; object-fit: cover; object-position: top; }
.shot.missing img { display: none; }
.shot.missing a { cursor: default; }
.shot.missing a::before { content: "screenshot not found"; position: absolute; inset: 0; display: grid; place-items: center; color: var(--dim); font: 12px var(--mono); background: repeating-linear-gradient(45deg, transparent 0 10px, var(--line) 10px 11px); }
.shot figcaption { display: grid; gap: 4px; padding: 10px 12px 12px; font-size: 12px; }
.shot .u { display: flex; align-items: center; gap: 8px; min-width: 0; }
.shot .u .mono { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.shot .ttl { max-width: none; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.lightbox { position: fixed; inset: 0; z-index: 60; display: grid; place-items: center; padding: 24px; cursor: zoom-out; background: rgba(8, 11, 16, .82); }
.lightbox[hidden] { display: none; }
.lightbox figure { margin: 0; display: grid; gap: 12px; justify-items: center; }
.lightbox img { max-width: min(1200px, 100%); max-height: 82vh; border-radius: 8px; }
.lightbox figcaption { color: #cfd8e3; font: 12.5px var(--mono); overflow-wrap: anywhere; text-align: center; }

/* run provenance */
.run { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 1px; margin: 0; overflow: hidden; border-radius: var(--radius); border: 1px solid var(--line); background: var(--line); }
.run > div { grid-column: span var(--span, 1); padding: 12px 14px; background: var(--panel); }
@media (max-width: 720px) { .run { grid-template-columns: minmax(0, 1fr); } .run > div { grid-column: auto; } }
.run dt { color: var(--muted); font-size: 11px; letter-spacing: .03em; }
.run dd { margin: 5px 0 0; font: 13px var(--mono); overflow-wrap: anywhere; }

.foot { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 8px; margin-top: 56px; padding-top: 18px; border-top: 1px solid var(--line); color: var(--dim); font: 12px var(--mono); }

@media (max-width: 720px) {
  .hero { padding-top: 30px; }
  .bars li { grid-template-columns: 78px 1fr 46px; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; transition: none !important; scroll-behavior: auto !important; }
}
@media print {
  :root, :root[data-theme] {"""
    + _LIGHT
    + """}
  body { background: #fff; }
  .nav, .toolbar, .lightbox, .pkt { display: none !important; }
  .tile, .panel, .card, .shot, .run > div { break-inside: avoid; }
  .tbl { overflow: visible; }
}
"""
)

_THEME_ICON = _icon(
    '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>'
)

#: The HTML skeleton. ``{...}`` placeholders are filled by :func:`_render_page`;
#: CSS and JS are substituted values, so their own braces need no escaping.
_PAGE_TEMPLATE = (
    """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>{title}</title>
<script>{head_js}</script>
<style>{css}</style>
</head>
<body>
<nav class="nav"><div class="nav-in">
<a class="logo" href="#top"><i></i>cyberfw</a>
<div class="links">{nav}</div>
<button id="theme" type="button" aria-label="Toggle light and dark theme" title="Toggle theme">"""
    + _THEME_ICON
    + """</button>
</div></nav>
<main class="wrap">
{hero}
{sections}
<footer class="foot"><span>generated {generated}</span><span>cyberfw {version}</span></footer>
</main>
{lightbox}
<script>{js}</script>
</body>
</html>
"""
)
