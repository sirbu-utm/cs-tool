"""Rich renderers: record and tool tables, the run summary, the plan, change lists, status."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from rich.cells import cell_len
from rich.console import Group, RenderableType
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from cyberfw import motion, vt
from cyberfw.cli.common import _tool_state, _tool_states, _tool_version
from cyberfw.config import Settings
from cyberfw.hud import (
    ALERT,
    BRAND,
    ByWidth,
    HudFrame,
    Pane,
    PathText,
    hud_table,
    join,
)
from cyberfw.logging import console
from cyberfw.manager import ToolManager
from cyberfw.pipeline.engine import (
    Node,
    NodeResult,
    PipelineResult,
)
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.report import diff as rundiff
from cyberfw.ui import (
    NEUTRAL_STYLE,
    SEVERITY_STYLES,
    TOOL_GUIDES,
    pip_word,
    record_detail,
    record_style,
    state_style,
)


def _sorted_ports(ports_list: str) -> list[str]:
    """Numeric-sort a comma-joined port list, tolerating stray whitespace."""
    ports = {p.strip() for p in ports_list.split(",") if p.strip()}
    return sorted(ports, key=lambda p: int(p) if p.isdigit() else 0)


#: Severities in the order the record table tallies them.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _severity_cell(severity: str) -> Text:
    """``critical`` as a solid badge that cannot be missed; the rest as pip and word."""
    if severity == "critical":
        return Text(" critical ", style="bold bright_white on red")
    return pip_word(severity, SEVERITY_STYLES.get(severity, NEUTRAL_STYLE))


def _finding_detail(record: ToolRecord) -> str:
    """The detail cell. A finding with a severity shows its name: the severity
    has a column of its own."""
    name = getattr(record, "name", "")
    if getattr(record, "severity", None) and name:
        return str(name)
    return record_detail(record)


def _record_table(records: list[ToolRecord], *, tool: str | None = None, target: str | None = None) -> HudFrame:
    """Validated records in the frame: one row each, a severity column and a
    tally in the bottom border when the records carry severities.

    A record carrying ``ports_list`` (RustScan's one-line-per-host summary)
    is expanded into one row per port — otherwise a dozen open ports collapse
    into an unreadable comma blob crammed into a single "detail" cell.
    """
    rows: list[tuple[ToolRecord, str, str, str]] = []  # record, target, kind, detail
    for record in records:
        ports_list = getattr(record, "ports_list", "")
        if ports_list:
            state = getattr(record, "port_state", "open")
            rows += [(record, f"{record.target}:{port}", "port", state) for port in _sorted_ports(ports_list)]
        else:
            rows.append((record, record.target, record.kind, _finding_detail(record)))
    severities = [str(getattr(record, "severity", "") or "").lower() for record, *_rest in rows]
    with_severity = any(severities)
    kinds = sorted({kind for _record, _target, kind, _detail in rows})
    table = hud_table()
    table.add_column("#", style="muted", justify="right", no_wrap=True)
    if with_severity:
        table.add_column("severity", no_wrap=True)
    table.add_column("target", ratio=3)
    if len(kinds) > 1:
        table.add_column("kind", style="muted", no_wrap=True)
    table.add_column("detail", overflow="fold", ratio=2)
    for index, ((record, row_target, kind, detail), severity) in enumerate(zip(rows, severities, strict=True), 1):
        style = record_style(record)
        cells: list[RenderableType] = [str(index)]
        if with_severity:
            cells.append(_severity_cell(severity))
        cells.append(PathText(row_target, style=style))
        if len(kinds) > 1:
            cells.append(Text(kind))
        cells.append(Text(detail, style=style))
        table.add_row(*cells)
    meta = [Text(f"{len(rows)} record(s)", style="white")]
    if len(kinds) == 1:
        meta.append(Text.assemble(("kind ", "muted"), (kinds[0], "white")))
    if tool:
        meta.insert(0, Text.assemble((tool, "tool"), (f" · {target}" if target else "", "white")))
    footer = None
    if with_severity:
        counts = {level: severities.count(level) for level in (*_SEVERITY_ORDER, "unknown")}
        footer = join(
            (Text.assemble((f"{level} ", SEVERITY_STYLES.get(level, NEUTRAL_STYLE)), (str(n), "bold white"))
             for level, n in counts.items() if n),
            "  ",
        )
    return HudFrame([Pane(table, title="Validated records", meta=join(meta, " · "), pad=0)], footer=footer)


def _node_table(result: PipelineResult) -> HudFrame:
    """Per-stage results (the raw-output mode's closing table)."""
    table = hud_table()
    table.add_column("tool", style="tool", no_wrap=True)
    table.add_column("stage", no_wrap=True)
    table.add_column("status", no_wrap=True)
    table.add_column("records", justify="right", no_wrap=True)
    table.add_column("error", style="err", overflow="fold", ratio=1)
    for node_result in result.nodes:
        state = _stage_outcome(node_result)
        table.add_row(
            node_result.node.tool,
            node_result.node.stage,
            pip_word(state, {"ok": "ok", "failed": "err", "skipped": "warn"}[state]),
            str(node_result.count),
            node_result.error or "",
        )
    return HudFrame([Pane(table, title="Pipeline stages", pad=0)])


def _stage_outcome(node_result: NodeResult) -> str:
    if node_result.ok:
        return "ok"
    return "skipped" if node_result.skipped else "failed"


def _print_changes(changes: rundiff.RunDiff, *, limit: int | None) -> None:
    """``Since <when> (<session>): 2 new findings · 1 port opened`` and the changes themselves."""
    base = changes.baseline
    when = str(base.get("started_at") or "")[:16].replace("T", " ")
    since = f"{when} UTC" if when else "the earlier run"
    session = f" ({escape(str(base['session_id']))})" if base.get("session_id") else ""
    summary = " · ".join(changes.summary()) or "nothing changed"
    console.print(f"Since {since}{session}: {escape(summary)}")
    shown = changes.changes if limit is None else changes.changes[:limit]
    for change in shown:
        style = {"bad": "err", "good": "ok"}.get(change.tone, "muted")
        severity = f" {change.severity}" if change.severity else ""
        detail = f" [muted]— {escape(change.detail)}[/muted]" if change.detail else ""
        console.print(f"  [{style}]{escape(change.label)}{severity}[/{style}]  {escape(change.subject)}{detail}")
    if limit is not None and len(changes.changes) > limit:
        console.print(f"  [muted]… and {len(changes.changes) - limit} more in the report[/muted]")
    for note in changes.not_compared:
        console.print(f"  [muted]not compared: {escape(note)}[/muted]")


def _plan_view(
    manager: ToolManager,
    name: str,
    seed: str | None,
    nodes: list[Node],
    blocking: list[tuple[str, str, str]],
    warnings: list[str],
    tools_dir: Path,
) -> HudFrame:
    """A dry-run picture of a pipeline: each stage, what it consumes, the state
    of its tool and any per-stage options, then the pre-flight verdict."""
    table = hud_table()
    table.add_column("#", style="muted", justify="right", no_wrap=True)
    table.add_column("tool", style="tool", no_wrap=True)
    table.add_column("stage", no_wrap=True)
    table.add_column("consumes", style="muted", no_wrap=True)
    table.add_column("state", no_wrap=True)
    table.add_column("options", style="muted", overflow="fold", ratio=1)
    previous: str | None = None
    for index, node in enumerate(nodes, start=1):
        consumes = node.input_from or ("seed" if previous is None else previous)
        opts = []
        if node.severity:
            opts.append(f"severity={node.severity}")
        if node.tags:
            opts.append(f"tags={node.tags}")
        if node.rate_limit:
            opts.append(f"rate={node.rate_limit}")
        if node.max_records:
            opts.append(f"max={node.max_records}")
        state = _tool_state(manager, node.tool, tools_dir)
        table.add_row(
            str(index), node.tool, node.stage, consumes, pip_word(state, state_style(state)), "  ".join(opts)
        )
        previous = node.stage
    verdict = (
        Text(f"{len(blocking)} stage(s) cannot run as-is — --force-start runs the rest", style="warn")
        if blocking
        else Text("ready to run", style="ok")
    )
    footer = join([Text(f"plan · {seed or '<target>'}", style="muted"), verdict], "   ")
    panes = [Pane(table, title=f"Plan · {name}", pad=0)]
    if warnings:
        panes.append(Pane(Group(*(Text(w, style="warn") for w in warnings)), title="Notes"))
    return HudFrame(panes, footer=footer)


#: Severities a run summary breaks findings down by, worst first.
_SUMMARY_SEVERITIES = ("critical", "high", "medium", "low", "info")
#: ``record.kind`` → the human label the summary counts it under.
_ASSET_KINDS = (
    ("host", "hosts"),
    ("http", "live"),
    ("port", "ports"),
    ("service", "services"),
    ("secret", "secrets"),
)


def _severity_tally(records: list[ToolRecord]) -> dict[str, int]:
    """How many findings (``kind == vuln``) at each severity."""
    counts = dict.fromkeys(_SUMMARY_SEVERITIES, 0)
    for record in records:
        if getattr(record, "kind", "") == "vuln":
            severity = str(getattr(record, "severity", "") or "").lower()
            if severity in counts:
                counts[severity] += 1
    return counts


def _asset_counts(records: list[ToolRecord]) -> dict[str, int]:
    """What the run found, by category — only the non-empty ones, in fixed order."""
    counts: dict[str, int] = {}
    for kind, label in _ASSET_KINDS:
        found = sum(1 for record in records if getattr(record, "kind", "") == kind)
        if found:
            counts[label] = found
    return counts


def _fix_first(records: list[ToolRecord], limit: int = 5) -> list[ToolRecord]:
    """The worst findings to act on: critical then high, un-muted, capped at ``limit``."""
    rank = {severity: index for index, severity in enumerate(_SUMMARY_SEVERITIES)}
    worst = [
        record
        for record in records
        if getattr(record, "kind", "") == "vuln"
        and not getattr(record, "muted", None)
        and str(getattr(record, "severity", "") or "").lower() in ("critical", "high")
    ]
    worst.sort(key=lambda record: rank.get(str(getattr(record, "severity", "") or "").lower(), 99))
    return worst[:limit]


def _findings_pane(records: list[ToolRecord]) -> Pane | None:
    """A breakdown of what the run found: severities, asset counts, worst first.
    ``None`` when there is nothing to describe."""
    lines: list[RenderableType] = []
    tally = _severity_tally(records)
    severities = join(
        (
            Text.assemble((f"{level} ", SEVERITY_STYLES.get(level, NEUTRAL_STYLE)), (str(count), "bold white"))
            for level in _SUMMARY_SEVERITIES
            if (count := tally[level])
        ),
        "  ",
    )
    if severities.cell_len:
        lines.append(severities)
    assets = _asset_counts(records)
    if assets:
        lines.append(join((Text.assemble((f"{label} ", "muted"), (str(n), "bold white")) for label, n in assets.items()), "   "))
    worst = _fix_first(records)
    if worst:
        lines.append(Text(""))
        lines.append(Text("Fix first", style="accent"))
        table = Table.grid(padding=(0, 2))
        table.add_column(no_wrap=True)  # severity badge
        table.add_column(no_wrap=True)  # target
        table.add_column(overflow="fold")  # finding name
        for record in worst:
            severity = str(getattr(record, "severity", "") or "").lower()
            name = str(getattr(record, "name", "") or _finding_detail(record))
            table.add_row(
                _severity_cell(severity), PathText(record.target, style=record_style(record)), Text(name, style="white")
            )
        lines.append(table)
    return Pane(Group(*lines), title="Findings", pad=2) if lines else None


def _run_summary(
    result: PipelineResult,
    *,
    name: str,
    session_id: str,
    reports: list[tuple[str, Path]],
    progress: float = 1.0,
) -> HudFrame:
    """Closing frame: the verdict, the yield per tool, what did not deliver and
    why, then where the artefacts are. Green-to-cyan for a clean run,
    red-to-amber for one that failed.

    ``progress`` below 1 is a frame of its entrance: the numbers and bars count up.
    """
    ok = result.succeeded()
    scale = motion.ease_out(progress)

    def counted(value: float) -> float:
        return value if progress >= 1 else value * scale

    verdict = Text(" success ", style="black on green") if ok else Text(" failed ", style="bold bright_white on red")
    duration = result.duration_s
    if duration is None:
        elapsed = "elapsed n/a"
    else:
        elapsed = f"elapsed {counted(duration):.1f}s" + (f" ({_clock_text(duration)})" if duration >= 60 else "")
    headline = Text.assemble(
        verdict,
        ("   ", ""),
        (f"{round(counted(len(result.records)))} record(s)", "bold white"),
        ("   ·   ", "muted"),
        (elapsed, "bold white"),
    )
    totals = result.totals_by_tool
    peak = max(totals.values(), default=0) or 1

    def yields(width: int) -> Table:
        # The name and the count always show; the bar takes what is left (up
        # to 24 cells) and is left out below 4, rather than push the count off.
        # Names are padded here, not with a column min_width: rich 13.x counts
        # a min_width column's edge padding even in a grid that has none, so
        # the table came out one cell wider than this sum and the count column
        # was dropped at 36-40 columns. The 2 = the cell after the name and
        # the cell after the bar.
        name_w = max([10, *(cell_len(tool) for tool in totals)])
        digits = max((len(str(count)) for count in totals.values()), default=1)
        bar_w = min(24, width - name_w - digits - 2)
        table = Table.grid(padding=(0, 1))
        table.add_column(style="tool", no_wrap=True)
        if bar_w >= 4:
            table.add_column(no_wrap=True)
        table.add_column(justify="right", no_wrap=True)
        for tool, count in totals.items():
            shown = counted(count)
            cells: list[str | Text] = [tool + " " * (name_w - cell_len(tool))]
            if bar_w >= 4:
                cells.append(motion.bar(shown / peak, bar_w, style="accent" if count else "muted"))
            cells.append(Text(str(round(shown)), style="bold white" if count else "muted"))
            table.add_row(*cells)
        return table

    rows = [Pane(Group(Text(""), headline, Text(""), ByWidth(yields)), title=Text(name), pad=2)]

    # What the run found, broken down — shown at full (it does not count up).
    findings = _findings_pane(result.records) if progress >= 1 else None
    if findings is not None:
        rows.append(findings)

    # Name the stages that did not deliver, and why the failed ones failed: the
    # frame is the last thing on screen, and the live table cuts long reasons off.
    issues: list[Text] = []
    for node_result in result.nodes:
        if node_result.ok or node_result.skipped:
            continue
        node = node_result.node
        reason = (node_result.error or "").removeprefix(f"{node.tool} ")
        issues.append(
            Text.assemble(pip_word("failed ", "err"), "  ", (f"{node.stage} ({node.tool})", "white"), (f"  {reason}", "muted"))
        )
    skipped = [n for n in result.nodes if n.skipped]
    if skipped:
        named = ", ".join(f"{n.node.stage} ({n.node.tool})" for n in skipped)
        issues.append(Text.assemble(pip_word("skipped", "warn"), "  ", (named, "white")))
    if issues:
        rows.append(Pane(Group(*issues), title="Issues", pad=2))

    artefacts = Table.grid(padding=(0, 2), expand=True)
    artefacts.add_column(style="muted", no_wrap=True)
    artefacts.add_column(ratio=1)
    artefacts.add_row("session", Text(session_id, style="bold white"))
    for label, path in reports:
        artefacts.add_row(label, PathText(path))
    rows.append(Pane(artefacts, title="Output", pad=2))
    return HudFrame(rows, palette=BRAND if ok else ALERT)


def _clock_text(seconds: float) -> str:
    """``12m34s`` — a long run read at a glance (the seconds stay alongside)."""
    minutes, rest = divmod(int(round(seconds)), 60)
    if minutes < 60:
        return f"{minutes}m{rest:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


@dataclass
class _ToolRow:
    """One registered tool as the launcher and ``status`` show it."""

    name: str
    version: str
    state: str
    repo: str


def _tool_rows(manager: ToolManager, tools_dir: Path, states: list[str] | None = None) -> list[_ToolRow]:
    """Every registered tool, in registry order. ``states`` reuses an inventory
    pass the caller already made."""
    names = manager.registry.names()
    if states is None or len(states) != len(names):
        states = _tool_states(manager, tools_dir)
    return [
        _ToolRow(name, _tool_version(manager, name), state, manager.spec(name).repo or "local")
        for name, state in zip(names, states, strict=True)
    ]


def _tools_table(rows: list[_ToolRow], *, numbered: bool, capability: bool, reveal: float = 1.0) -> Table:
    """The tool inventory: number, tool, what it does, version, state, source.

    A tool that cannot run is greyed out with ``muted``: a real grey, not
    ``dim``, which the classic Windows console ignores, and not bright black,
    which Solarized Dark draws in its background colour. On the classic
    console Rich lowers the grey to bright black itself. ``reveal`` below 1 is a
    frame of the launcher's entrance: the rows type in top to bottom, the
    newest one lit; a row not in yet is blank but as wide as it will be, so the
    columns stand still.
    """
    table = hud_table()
    if numbered:
        table.add_column("#", justify="right", no_wrap=True, width=2)
    table.add_column("tool", no_wrap=True)
    if capability:
        table.add_column("capability", no_wrap=True, overflow="ellipsis")
    table.add_column("version", style="muted", no_wrap=True)
    table.add_column("state", no_wrap=True)
    table.add_column("source", style="muted", no_wrap=True, overflow="ellipsis")
    shown = len(rows) if reveal >= 1 else int(len(rows) * max(reveal, 0.0))
    for index, row in enumerate(rows, start=1):
        ready = row.state == "ready"
        cells: list[Text] = []
        if numbered:
            cells.append(Text(str(index), style="bold bright_green" if ready else "muted"))
        fresh = reveal < 1 and index == shown
        cells.append(Text(row.name, style="bold bright_white" if fresh else ("tool" if ready else "muted")))
        if capability:
            cells.append(Text(TOOL_GUIDES.get(row.name, ("",))[0], style="white" if ready else "muted"))
        cells += [Text(row.version or "—"), pip_word(row.state, state_style(row.state)), Text(row.repo)]
        if index > shown:
            cells = [Text(" " * cell.cell_len) for cell in cells]
        table.add_row(*cells)
    return table


def _inventory_table(
    manager: ToolManager, tools_dir: Path, *, numbered: bool = False, states: list[str] | None = None
) -> tuple[Table, list[str]]:
    """The tool inventory, and the per-tool states it was built from."""
    rows = _tool_rows(manager, tools_dir, states)
    return _tools_table(rows, numbered=numbered, capability=False), [row.state for row in rows]


def _tool_menu(manager: ToolManager) -> Table:
    """Render the registry with installation status for the launcher."""
    table, _states = _inventory_table(manager, manager.settings.tools_dir, numbered=True)
    return table


def _dep_row(label: str, found: str | None, needed_by: str) -> tuple[str, Text, RenderableType]:
    if found:
        return (label, pip_word("found", "ok"), PathText(found, style="muted"))
    return (label, pip_word("missing", "warn"), Text(f"needed by {needed_by}", style="muted"))


def _status_view(rows: list[_ToolRow], settings: Settings, *, chrome: str | None) -> HudFrame:
    """``status`` as one panel: the tools (and where they are looked for), the
    external dependencies, the effective settings."""
    tools_dir = Table.grid(padding=(0, 1), pad_edge=True, expand=True)
    tools_dir.add_column(style="muted", no_wrap=True)
    tools_dir.add_column(ratio=1)
    tools_dir.add_row("tools dir", PathText(settings.tools_dir))
    tools = ByWidth(lambda width: Group(_tools_table(rows, numbered=False, capability=width >= 100), tools_dir))

    deps = hud_table()
    deps.add_column("dependency", style="tool", no_wrap=True)
    deps.add_column("state", no_wrap=True)
    deps.add_column("detail", ratio=1)
    deps.add_row(*_dep_row("nmap", shutil.which("nmap"), "rustscan (service/version detection)"))
    deps.add_row(*_dep_row("chrome/chromium", chrome, "gowitness (screenshots)"))

    def flag(value: bool, off: str = "off") -> Text:
        return pip_word("on", "ok") if value else pip_word(off, "warn")

    pairs: list[tuple[str, RenderableType]] = [
        ("parse", flag(settings.parse, "off (raw output)")),
        ("view", Text(settings.view)),
        ("animations", flag(settings.animations)),
        ("log_level", Text(settings.log_level, style="info")),
        ("log_to_file", flag(settings.log_to_file)),
        ("concurrency", Text(str(settings.concurrency))),
        (
            "stage_timeout",
            Text(f"{settings.stage_timeout:g}s") if settings.stage_timeout else Text("unlimited", style="muted"),
        ),
        ("github_token", pip_word("set", "ok") if settings.github_token else Text("unset (60 req/h)", style="muted")),
    ]
    paths: list[tuple[str, RenderableType]] = [
        ("wordlist", PathText(settings.wordlist) if settings.wordlist else Text("(unset → bundled common.txt)", style="muted")),
        ("reports_dir", PathText(settings.reports_dir)),
        ("logs_dir", PathText(settings.logs_dir)),
    ]

    def effective(width: int) -> RenderableType:
        columns = 2 if width >= 100 else 1
        grid = Table.grid(padding=(0, 2), expand=True)
        for _ in range(columns):
            grid.add_column(style="tool", no_wrap=True, min_width=13)
            grid.add_column(ratio=1)
        for start in range(0, len(pairs), columns):
            cells: list[RenderableType] = []
            for key, value in pairs[start : start + columns]:
                cells += [key, value]
            grid.add_row(*cells)
        where = Table.grid(padding=(0, 2), expand=True)
        where.add_column(style="tool", no_wrap=True, min_width=13)
        where.add_column(ratio=1)
        for key, value in paths:
            where.add_row(key, value)
        return Group(grid, Text(""), where)

    return HudFrame(
        [
            Pane(tools, title="Tools", pad=0),
            Pane(deps, title="External dependencies", pad=0),
            Pane(ByWidth(effective), title="Effective settings"),
        ],
        footer=Text("cyberfw status", style="muted"),
    )


def _print_reputation(rep: vt.Reputation) -> None:
    if not rep.found:
        console.print(f"[dim]{rep.target}[/dim] — not seen by VirusTotal")
        return
    verdict = (
        "[red]malicious[/red]"
        if rep.malicious
        else ("[yellow]suspicious[/yellow]" if rep.suspicious else "[green]clean[/green]")
    )
    console.print(f"[bold]{rep.target}[/bold] ({rep.kind}) — {verdict}")
    console.print(
        f"  detections: {rep.malicious} malicious · {rep.suspicious} suspicious · "
        f"{rep.harmless} harmless · reputation {rep.reputation}"
    )
    if rep.categories:
        console.print(f"  categories: {', '.join(rep.categories)}")
    console.print(f"  [dim]{rep.permalink}[/dim]")
