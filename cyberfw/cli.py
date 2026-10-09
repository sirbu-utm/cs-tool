"""Typer CLI — the public face of cyberfw.

Three commands, matching the acceptance criteria in the technical specification:

* ``cyberfw init [tools...]`` — fetch precompiled binaries into ``tools_bin/``
  (zero-friction: only Python, Git and curl/wget are required of the user).
* ``cyberfw run <tool> -t <target> (-l <hosts>)`` — run a single registered tool
  through its adapter and stream validated JSONL records.
* ``cyberfw pipeline <name> -t <domain>`` — run a ready-made pipeline
  (e.g. ``recon-to-vuln``) and render HTML + JSON reports.

A crashed/failed child never aborts the CLI: :class:`PipelineEngine` converts
stage failures into a ``NodeResult`` and the command exits with a helpful status.
"""

from __future__ import annotations

import functools
import json
import os
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import strftime
from typing import Annotated, Any, Protocol

import anyio
import httpx
import typer
from rich.cells import cell_len
from rich.console import Console, ConsoleOptions, Group, RenderableType, RenderResult
from rich.live import Live
from rich.prompt import Confirm as _RichConfirm
from rich.prompt import Prompt as _RichPrompt
from rich.table import Table
from rich.text import Text, TextType

from cyberfw import motion, threatintel, vt
from cyberfw.config import Settings, load_settings
from cyberfw.exceptions import (
    ChromiumUnsupportedError,
    CyberfwError,
    RegistryError,
    ToolNotFoundError,
)
from cyberfw.hud import (
    ALERT,
    BRAND,
    KEY,
    ByWidth,
    HudFrame,
    Pane,
    PathText,
    hud_table,
    join,
    keycap,
)
from cyberfw.live_view import PipelineLiveView, TopologyView
from cyberfw.logging import console, ensure_utf8_stdio, get_logger, setup_logging
from cyberfw.manager import ToolManager, load_registry
from cyberfw.pipeline.context import SessionContext
from cyberfw.pipeline.engine import (
    Node,
    NodeResult,
    PipelineEngine,
    PipelineResult,
    StageEvent,
    dependency_hint,
)
from cyberfw.pipeline.schemas import ToolRecord, validate_record
from cyberfw.pipelines import PIPELINES, available_pipelines, build
from cyberfw.report.html_report import generate_html_report
from cyberfw.report.json_report import generate_json_report
from cyberfw.report.run_info import RunInfo
from cyberfw.resources import default_wordlist, packaged_data
from cyberfw.tools import adapter_class
from cyberfw.tools.base import ToolContext
from cyberfw.ui import (
    NEUTRAL_STYLE,
    PIP,
    SEVERITY_STYLES,
    TOOL_GUIDES,
    Masthead,
    banner,
    pip_word,
    record_detail,
    record_style,
    state_style,
    tool_guide,
)

LOG = get_logger("cli")


class Prompt(_RichPrompt):
    """Every question asked the same way: ``» Target (domain, URL or host):``.

    Callers still pass the plain wording (it comes from the adapters), so a
    test that patches ``cyberfw.cli.Prompt.ask`` sees exactly that wording.
    Questions go to the app's console unless told otherwise: Rich's global
    console has no theme, and the lead-in's style would quietly drop.
    """

    def __init__(self, prompt: TextType = "", *, console: Console | None = None, **kwargs: Any) -> None:
        super().__init__(prompt, console=console or _app_console(), **kwargs)

    def make_prompt(self, default: Any) -> Text:
        return Text.assemble(("» ", "accent"), super().make_prompt(default))


class Confirm(_RichConfirm):
    """A yes/no question with the same ``» `` lead-in as :class:`Prompt`."""

    def __init__(self, prompt: TextType = "", *, console: Console | None = None, **kwargs: Any) -> None:
        super().__init__(prompt, console=console or _app_console(), **kwargs)

    def make_prompt(self, default: Any) -> Text:
        return Text.assemble(("» ", "accent"), super().make_prompt(default))


def _app_console() -> Console:
    """The themed console, looked up at call time (tests swap it)."""
    return console

app = typer.Typer(
    name="cyberfw",
    help="Integrated Cybersecurity Framework — orchestrates precompiled offensive tools.",
    no_args_is_help=False,
    rich_markup_mode="rich",
    add_completion=False,
)


@app.callback(invoke_without_command=True)
def app_callback(ctx: typer.Context) -> None:
    """Open the interactive launcher when no subcommand was supplied."""
    ensure_utf8_stdio()
    if ctx.invoked_subcommand is None:
        interactive_menu()


# -- shared plumbing ------------------------------------------------------------
#: ``-v/--verbose`` — raise this run's log level to DEBUG so the resolve /
#: download / extract steps are traced. Shared by init/status/run/pipeline.
VerboseOption = Annotated[
    bool,
    typer.Option(
        "--verbose",
        "-v",
        help="Trace what runs under the hood at DEBUG (release resolution, downloads, extraction).",
    ),
]


def _bootstrap(*, verbose: bool = False) -> tuple[Settings, ToolManager]:
    """Load settings + registry, ensure directories, wire logging, return manager.

    ``verbose`` forces this process's log level to DEBUG regardless of the
    configured ``log_level``, so ``-v`` surfaces the install/download trace
    without a permanent config change.
    """
    settings = load_settings()
    if verbose and settings.log_level != "DEBUG":
        settings = settings.model_copy(update={"log_level": "DEBUG"})
    settings.ensure_dirs()
    setup_logging(level=settings.log_level, log_dir=settings.logs_dir, log_to_file=settings.log_to_file)
    manager = ToolManager(settings, load_registry(_registry_path()))
    return settings, manager


def _registry_candidates() -> list[Path]:
    """Where ``registry.yaml`` may live, most specific first.

    The current directory (a workspace the user may have edited), then the
    checkout root next to the package (running from a clone elsewhere), then
    the copy the wheel ships as ``cyberfw/data/registry.yaml``.
    """
    candidates = [Path.cwd() / "registry.yaml", Path(__file__).resolve().parent.parent / "registry.yaml"]
    packaged = packaged_data("registry.yaml")
    if packaged is not None:
        candidates.append(packaged)
    return candidates


def _registry_path() -> Path:
    """Locate ``registry.yaml`` or raise a :class:`RegistryError` naming the places tried."""
    candidates = _registry_candidates()
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    tried = ", ".join(str(path) for path in candidates)
    raise RegistryError(f"registry.yaml not found (tried: {tried}). Run cyberfw from the project root.")


def _read_hosts(path: Path) -> list[str]:
    """Read a newline-separated host list, skipping blanks and ``#`` comments."""
    hosts: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            hosts.append(line)
    return hosts


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


def _is_interactive() -> bool:
    """True when there is a user at the keyboard to answer a prompt.

    A pipe, a CI job or a `< /dev/null` run must never block on a question.
    """
    return bool(console.is_interactive)


def _wants_to_save(decided: bool | None, *, default: bool, what: str) -> bool:
    """Whether to keep this run's artefacts: the flag if given, else ask, else default."""
    if decided is not None:
        return decided
    if not _is_interactive():
        return default
    return bool(Confirm.ask(f"Save the {what} report?", default=default))


def _discard_session(session_dir: Path, *, created: bool) -> None:
    """Remove a session directory this run created; never touch a pre-existing one."""
    if not created:
        console.print(f"[muted]report not saved; {session_dir} was left as it was[/muted]")
        return
    shutil.rmtree(session_dir, ignore_errors=True)
    console.print("[muted]report not saved[/muted]")


def _write_reports(
    result: PipelineResult, *, session_id: str, settings: Settings, run: RunInfo
) -> list[tuple[str, Path]]:
    """Render both reports into the session directory; returns ``(label, path)`` pairs."""
    json_path = generate_json_report(result, session_id=session_id, reports_dir=settings.reports_dir, run=run)
    html_path = generate_html_report(result, session_id=session_id, reports_dir=settings.reports_dir, run=run)
    return [("json", json_path), ("html", html_path)]


def _run_info(manager: ToolManager, *, name: str, seed: str | None, session_id: str, tools: set[str]) -> RunInfo:
    return RunInfo(
        pipeline=name,
        seed=seed,
        session_id=session_id,
        platform=manager.mapping.label,
        tool_versions={tool: (manager.install_state(tool) or {}).get("version") for tool in sorted(tools)},
    )


def _preflight(
    manager: ToolManager, nodes: list[Node], tools_dir: Path
) -> tuple[list[tuple[str, str, str]], list[str]]:
    """What stands between this plan and a useful run, in plan order.

    Returns ``(blocking, warnings)``. Blocking: a binary that cannot run, or a
    hard external requirement the adapter reports missing (gowitness without
    Chrome) — the stage could only fail. Warnings: a ``check_deps`` entry that
    is not on PATH (RustScan's Nmap), which costs capability, not the run.
    """
    blocking: list[tuple[str, str, str]] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for node in nodes:
        if node.tool in seen:
            continue
        seen.add(node.tool)
        state = _tool_state(manager, node.tool, tools_dir)
        if state != "ready":
            blocking.append((node.stage, node.tool, state))
            continue
        requirement = adapter_class(node.tool).missing_requirement(tools_dir)
        if requirement is not None:
            blocking.append((node.stage, node.tool, requirement))
        for dep in manager.spec(node.tool).check_deps:
            if shutil.which(dep) is None:
                warnings.append(
                    f"{node.tool} works best with `{dep}`, which is not on PATH — {dependency_hint(dep)}"
                )
    return blocking, warnings


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
        name_w = max([10, *(cell_len(tool) for tool in totals)])
        digits = max((len(str(count)) for count in totals.values()), default=1)
        bar_w = min(24, width - name_w - digits - 2)
        table = Table.grid(padding=(0, 1))
        table.add_column(style="tool", no_wrap=True, min_width=10)
        if bar_w >= 4:
            table.add_column(no_wrap=True)
        table.add_column(justify="right", no_wrap=True)
        for tool, count in totals.items():
            shown = counted(count)
            cells: list[str | Text] = [tool]
            if bar_w >= 4:
                cells.append(motion.bar(shown / peak, bar_w, style="accent" if count else "muted"))
            cells.append(Text(str(round(shown)), style="bold white" if count else "muted"))
            table.add_row(*cells)
        return table

    rows = [Pane(Group(Text(""), headline, Text(""), ByWidth(yields)), title=Text(name), pad=2)]

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


def _after_live() -> None:
    """``Live`` leaves its last frame on screen; on a pipe that frame ends
    without a newline, and the next line would be glued to its last row."""
    if not console.is_terminal:
        console.line()


def _live_fps(settings: Settings) -> int:
    """Redraws per second for a live view: smooth when animating, else just current."""
    return 12 if settings.animations else 4


def _session_tag(kind: str, name: str) -> str:
    return f"{kind}-{name}-{strftime('%Y%m%d-%H%M%S')}"


def _checked_session(session: str) -> str:
    """Accept ``--session`` only as a plain directory name under ``reports/``.

    It is joined onto the reports directory, and a session this run created is
    removed when the user declines to save — so ``../x``, ``a/b`` or ``C:x``
    must never get as far as a path. A usage error, exit 2.
    """
    if session in {".", ".."} or any(ch in session for ch in "/\\:"):
        console.print(f"[err]--session must be a plain directory name under reports/, got {session!r}.[/err]")
        raise typer.Exit(2)
    return session


def _tool_state(manager: ToolManager, name: str, tools_dir: Path) -> str:
    """``ready`` / ``blocked`` / ``not installed`` for one registered tool.

    Readiness is "can this run", so a binary that resolves is ready even
    without an install record (the record only carries the version, shown in
    its own column). ``blocked`` is the narrow case the user must act on: the
    file is on disk but cannot be read or executed — typically an antivirus
    quarantine.
    """
    # binary_path and _binary_on_disk both rglob tools_dir; a directory that
    # lists but cannot be entered raises PermissionError (OSError) there on
    # Python 3.10-3.13 (3.14 swallows it). Treat an unreadable tree as "not on
    # disk" rather than letting a traceback replace the banner. OSError around
    # binary_path is the same net is_installed already casts.
    try:
        manager.binary_path(name)
    except (CyberfwError, OSError):
        try:
            on_disk = _binary_on_disk(tools_dir, name, manager.spec(name).binary)
        except OSError:
            on_disk = False
        return "blocked" if on_disk else "not installed"
    return "ready"


def _tool_version(manager: ToolManager, name: str) -> str:
    return str((manager.install_state(name) or {}).get("version", ""))


def _tool_states(manager: ToolManager, tools_dir: Path) -> list[str]:
    """One state per registered tool, in registry order."""
    return [_tool_state(manager, name, tools_dir) for name in manager.registry.names()]


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
        _ToolRow(name, _tool_version(manager, name), state, manager.spec(name).repo)
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


#: Order the ``l`` hotkey cycles through.
_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


def _toggle_setting(action: str, settings: Settings) -> None:
    """Apply an interactive settings toggle by exporting the matching env var.

    The launcher re-bootstraps every loop, and env vars have top precedence, so
    writing ``CYBERFW_*`` here makes the change take effect on the next run (and
    the next render), without a config file or a restart.
    """
    # The launcher's SETTINGS panel reflects the new value on the next in-place
    # refresh, so no extra confirmation line is printed here.
    if action == "p":
        os.environ["CYBERFW_PARSE"] = "false" if settings.parse else "true"
    elif action == "f":
        os.environ["CYBERFW_LOG_TO_FILE"] = "false" if settings.log_to_file else "true"
    elif action == "l":
        current = settings.log_level if settings.log_level in _LOG_LEVELS else "INFO"
        os.environ["CYBERFW_LOG_LEVEL"] = _LOG_LEVELS[(_LOG_LEVELS.index(current) + 1) % len(_LOG_LEVELS)]
    elif action == "a":
        os.environ["CYBERFW_ANIMATIONS"] = "false" if settings.animations else "true"


def _start_screen(rows: list[_ToolRow], platform: str, settings: Settings) -> None:
    """The banner and the launcher, played in as one intro.

    The big banner when banner and launcher fit the window together, else the
    three-row masthead. Where not even that fits, only the masthead plays and
    the launcher is printed under it — the intro is never silently dropped.
    """
    states = [row.state for row in rows]

    def full(progress: float) -> RenderableType:
        return Group(
            banner(states, platform, motion.phase(progress, 0.0, 0.6)),
            _LauncherView(rows, settings, progress=motion.phase(progress, 0.45, 1.0)),
        )

    def compact(progress: float) -> RenderableType:
        return Group(
            Masthead(states, platform, progress=motion.phase(progress, 0.0, 0.55)),
            Text(""),
            _LauncherView(rows, settings, progress=motion.phase(progress, 0.35, 1.0)),
        )

    def fits(frame: Callable[[float], RenderableType]) -> bool:
        # One row stays free for the prompt under the screen.
        return len(console.render_lines(frame(1.0), pad=False)) < console.size.height - 1

    if fits(full):
        motion.play(console, full, duration=1.6, animate=settings.animations)
    elif fits(compact):
        motion.play(console, compact, duration=1.3, animate=settings.animations)
    else:
        motion.play(console, lambda p: Masthead(states, platform, progress=p), duration=0.8, animate=settings.animations)
        console.print(_LauncherView(rows, settings))


def interactive_menu() -> None:
    """Run the keyboard-driven launcher used by ``cs-tool`` without arguments."""
    _ensure_tools()
    settings, manager = _bootstrap()
    try:
        # One inventory pass serves the banner and the first launcher frame;
        # later frames recompute, since a tool can change state mid-session.
        _start_screen(_tool_rows(manager, settings.tools_dir), manager.mapping.label, settings)
    finally:
        manager.close()
    first = True
    while True:
        # Re-bootstrap each loop so a p/l/f settings change — exported as a
        # CYBERFW_* env var — takes effect on the next frame. The panel is
        # printed fresh each time rather than updated inside a Rich ``Live``:
        # a Live region sharing the console with an interactive ``Prompt.ask``
        # double-painted the panel on some terminals.
        settings, manager = _bootstrap()
        try:
            names = manager.registry.names()
            if not first:  # the start screen already showed this frame
                console.print(_launcher_view(manager, settings))
        finally:
            manager.close()
        first = False
        choice = _prompt_choice(names)
        if choice in _SETTINGS_KEYS:
            _toggle_setting(choice, settings)
            continue  # reprint the panel with the new setting
        try:
            if not _dispatch_choice(choice, names):
                return
        except typer.Exit:
            console.print("[warn]The operation failed. Returning to the launcher.[/warn]")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[muted]Goodbye.[/muted]")
            return


#: Launcher hotkeys that are not tool numbers. Tools are ``1``..``len(names)``,
#: so the pipeline and exit actions get letters rather than a number that a
#: ninth registry entry would collide with.
_PIPELINE_KEY = "r"
_EXIT_KEYS = frozenset({"0", "q"})
_SETTINGS_KEYS = frozenset({"p", "l", "f", "a"})


def _tool_range(names: list[str]) -> str:
    """``1-8`` for eight tools, ``1`` for a single one."""
    return "1" if len(names) == 1 else f"1-{len(names)}"


def _prompt_choice(names: list[str]) -> str:
    """Prompt for a menu choice, with an on-brand hint on invalid input.

    Returns a normalised token: a tool number, the pipeline key, an exit key
    or a settings hotkey (``p``/``l``/``f``/``a``). Anything else re-prompts with a
    plain explanation instead of Rich's generic "not a valid integer" loop.
    """
    valid = {str(index) for index in range(1, len(names) + 1)} | {_PIPELINE_KEY} | _EXIT_KEYS | _SETTINGS_KEYS
    while True:
        raw = Prompt.ask("Select tool or action").strip().lower()
        if raw in valid:
            return raw
        console.print(
            f"[warn]Type {_tool_range(names)} for a tool, {_PIPELINE_KEY} pipeline, 0 exit, "
            "or p/l/f/a to change settings.[/warn]"
        )


def _dispatch_choice(choice: str, names: list[str]) -> bool:
    """Run the action behind a validated launcher choice; False means "exit"."""
    if choice in _EXIT_KEYS:
        console.print("[muted]Goodbye.[/muted]")
        return False
    if choice == _PIPELINE_KEY:
        _interactive_pipeline()
    else:
        _interactive_run(names[int(choice) - 1])
    return True


def _launcher_view(
    manager: ToolManager, settings: Settings, *, states: list[str] | None = None, progress: float = 1.0
) -> _LauncherView:
    """The launcher workspace for the current registry and settings.

    ``states`` reuses an inventory pass the caller already made; the ready
    count itself is left to the banner, so it is shown once.
    """
    return _LauncherView(_tool_rows(manager, settings.tools_dir, states), settings, progress=progress)


class _LauncherView:
    """The launcher: the tools, then a row of keys, then the live settings.

    A renderable rather than a fixed table, so it lays itself out for the width
    it gets: the capability column only where there is room (80 columns keeps
    every column shown today, unsqueezed). ``progress`` below 1 is a frame of
    its entrance: the frame is in place from the first frame (nothing below it
    jumps), the rows type in, then the keys, the settings and the footer hint.
    """

    def __init__(self, rows: list[_ToolRow], settings: Settings, *, progress: float = 1.0) -> None:
        self.rows = rows
        self.settings = settings
        self.progress = progress

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        names = [row.name for row in self.rows]
        keys = join(
            [
                keycap(_tool_range(names), "select tool"),
                keycap(_PIPELINE_KEY, "run pipeline"),
                Text.assemble((" 0 ", KEY), " ", (" q ", KEY), " ", ("exit", "muted")),
            ]
        )
        toggles = self._toggles(compact=False)
        if toggles.cell_len > options.max_width - 4:
            toggles = self._toggles(compact=True)
        progress = self.progress
        table = _tools_table(
            self.rows, numbered=True, capability=options.max_width >= 100, reveal=motion.phase(progress, 0.0, 0.7)
        )
        yield HudFrame(
            [
                Pane(table, title="Tools", pad=0),
                Pane(keys if progress >= 0.8 else Text(""), title="Keys"),
                Pane(toggles if progress >= 0.9 else Text(""), title="Settings"),
            ],
            footer=Text("type a key, then Enter", style="muted") if progress >= 1 else None,
        )

    def _toggles(self, *, compact: bool) -> Text:
        """The four settings on one line, each behind the key that flips it.
        ``compact`` (a narrow terminal) drops the pips; the coloured words stay."""

        def flag(value: bool) -> Text:
            word, style = ("on", "ok") if value else ("off", "warn")
            return Text(word, style=style) if compact else pip_word(word, style)

        settings = self.settings
        items = [
            ("p", "parse", flag(settings.parse)),
            ("l", "log level", Text(settings.log_level, style="info")),
            ("f", "log file", flag(settings.log_to_file)),
            ("a", "animations", flag(settings.animations)),
        ]
        return join(
            (Text.assemble(keycap(key, label, slot=2, label_style="muted"), " ", value) for key, label, value in items),
            "  " if compact else "   ",
        )


def _ensure_tools() -> None:
    """Install every missing tool automatically before showing the launcher."""
    _, manager = _bootstrap()
    try:
        missing = [name for name in manager.registry.names() if not manager.is_installed(name)]
        if not missing:
            return
        console.print(f"[info]Preparing {len(missing)} tool(s) automatically...[/info]")
        for name in missing:
            console.print(f"[info]fetching[/info] {name} ({manager.spec(name).repo}) ...")
            try:
                result = manager.install(name)
            except CyberfwError as exc:
                console.print(f"[err]  failed {name}:[/err] {exc}")
            else:
                console.print(f"[ok]  ready {name} v{result.version}[/ok]")
    finally:
        manager.close()


def _interactive_run(tool: str) -> None:
    """Prompt for a target and run the tool selected by its menu number.

    The wording comes from the adapter (``target_prompt`` / ``extra_input_prompt``),
    so a new tool needs no launcher changes.
    """
    console.print(tool_guide(tool, **_tool_facts(tool)))
    adapter = adapter_class(tool)
    target = Prompt.ask(adapter.target_prompt)
    wordlist: str | None = None
    if adapter.extra_input_prompt is not None:
        wordlist = Prompt.ask(adapter.extra_input_prompt, default="") or None
    run_cmd(tool, target=target, wordlist=wordlist)


def _tool_facts(tool: str) -> dict[str, str | None]:
    """State, version and source for the tool card; nothing for a tool the
    registry does not list."""
    settings, manager = _bootstrap()
    try:
        if tool not in manager.registry.names():
            return {}
        version = _tool_version(manager, tool)
        return {
            "state": _tool_state(manager, tool, settings.tools_dir),
            "version": version or None,
            "repo": manager.spec(tool).repo,
        }
    finally:
        manager.close()


def _interactive_pipeline() -> None:
    choices = available_pipelines(load_settings().pipelines_dir)
    name = Prompt.ask("Pipeline", choices=choices, default=choices[0])
    target = Prompt.ask("Seed target (domain or URL)")
    include_ffuf = include_gowitness = False
    wordlist = None
    if name in PIPELINES:  # the optional stages are recon-to-vuln's; YAML pipelines have none
        include_ffuf = Confirm.ask("Include Ffuf?", default=False)
        if include_ffuf:
            wordlist = Prompt.ask("Ffuf wordlist path", default="") or None
        include_gowitness = Confirm.ask("Include Gowitness?", default=False)
    pipeline_cmd(
        name,
        target=target,
        ffuf=include_ffuf,
        gowitness=include_gowitness,
        wordlist=wordlist,
    )


# -- commands --------------------------------------------------------------------
@app.command("init")
def init_cmd(
    tools: Annotated[list[str] | None, typer.Argument(help="Tool names to install; omit for all.")] = None,
    token: Annotated[str | None, typer.Option("--token", envvar="CYBERFW_GITHUB_TOKEN",
                                             help="GitHub token to raise the rate limit.")] = None,
    force: Annotated[
        bool,
        typer.Option("--force", help="Re-download even when the wanted version is already installed."),
    ] = False,
    chromium: Annotated[
        bool,
        typer.Option(
            "--chromium/--no-chromium",
            help="Also download a portable Chromium for gowitness when no Chrome is found.",
        ),
    ] = True,
    verbose: VerboseOption = False,
) -> None:
    """Download and install precompiled tool binaries into ``tools_bin/``.

    A tool whose installed version already matches (the pinned ``version:`` in
    registry.yaml, or the latest release) is left alone unless ``--force``.

    When gowitness is installed and no Chrome/Chromium is on the machine, a
    portable Chromium (Chrome for Testing) is downloaded too, so the screenshot
    stage works without a system browser. Skip it with ``--no-chromium``.

    ``-v/--verbose`` traces each release resolution, download and extraction.
    """
    settings, manager = _bootstrap(verbose=verbose)
    if token:
        settings = settings.model_copy(update={"github_token": token})
        manager = ToolManager(settings, manager.registry, manager.mapping)

    targets = tools or manager.registry.names()
    console.print(
        Text.assemble(
            (f"Installing {len(targets)} tool(s) into ", "info"), (str(settings.tools_dir), "tool")
        )
    )
    with_chromium = chromium and "gowitness" in targets and "gowitness" in manager.registry.names()
    progress = _InstallProgress(len(targets) + with_chromium, animate=settings.animations)
    ok, failed = 0, 0
    try:
        # The table grows a row per tool inside the live region, over the
        # progress line; the last frame is the table alone (all a pipe sees).
        with Live(progress, console=console, refresh_per_second=_live_fps(settings), transient=False) as live:
            for name in targets:
                spec = manager.spec(name)
                wanted = spec.version if spec.version != "latest" else "latest release"
                progress.update(f"[info]checking[/info] {name} ({spec.repo}, {wanted}) ...")
                try:
                    result = manager.install(name, force=force)
                except CyberfwError as exc:
                    failed += 1
                    progress.add_row(name, "—", Text("failed", style="err"), str(exc))
                    progress.advance()
                    continue
                ok += 1
                state = (
                    Text("up to date", style="muted")
                    if result.up_to_date
                    else Text("installed", style="ok")
                )
                progress.add_row(name, result.version, state, _relative_to(result.binary, settings.tools_dir))
                progress.advance()
            if with_chromium:
                failed += _provision_chromium(manager, settings, progress, force=force, spinner=progress)
                progress.advance()
            live.update(progress.table(), refresh=True)
        _after_live()
    finally:
        manager.close()

    if failed:
        console.print(f"[warn]{ok} ready, {failed} failed.[/warn]")
        raise typer.Exit(1)
    console.print(f"[ok]Done: {ok} tool(s) ready.[/ok]")


class _RowSink(Protocol):
    """Where a result row goes: a Rich ``Table`` or :class:`_InstallProgress`."""

    def add_row(self, *cells: RenderableType | None) -> None: ...


class _InstallProgress:
    """``init``'s live frame: the result table, a row per finished tool, over a
    progress line (spinner, bar, ``3/8`` and what is being fetched now).

    :meth:`update` takes the markup message ``console.status`` used to, so
    :func:`_provision_chromium` reports through it unchanged. Rows are kept as
    a list and every frame builds its own table from a copy: ``Live`` renders
    on its refresh thread while rows are being added.
    """

    def __init__(self, total: int, *, animate: bool, clock: Callable[[], float] = time.monotonic) -> None:
        self.rows: list[tuple[RenderableType | None, ...]] = []
        self.total = total
        self.done = 0
        self.message = ""
        self._animate = animate
        self._clock = clock

    def update(self, message: str) -> None:
        self.message = message

    def advance(self) -> None:
        self.done += 1

    def add_row(self, *cells: RenderableType | None) -> None:
        self.rows.append(cells)

    def table(self) -> HudFrame:
        """The result table so far, in the frame."""
        # The detail is relative to tools_dir: an absolute Windows path is ~90
        # characters and squeezes every other column away.
        table = hud_table()
        table.add_column("tool", style="tool", no_wrap=True)
        table.add_column("version", style="muted", no_wrap=True)
        table.add_column("state", no_wrap=True)
        table.add_column("detail", style="muted", overflow="ellipsis", ratio=1)
        for row in list(self.rows):
            table.add_row(*row)
        return HudFrame([Pane(table, title="Install", pad=0)])

    def __rich__(self) -> RenderableType:
        now = self._clock()
        line = Text()
        line.append(f"{motion.spinner(now) if self._animate else PIP} ", style="info")
        line.append_text(
            motion.bar(
                self.done / self.total if self.total else 1.0,
                20,
                style="accent",
                shine=(now % 1.5) / 1.5 if self._animate else None,
            )
        )
        line.append(f" {self.done}/{self.total}  ", style="muted")
        line.append_text(Text.from_markup(self.message))
        return Group(self.table(), line) if self.rows else line


def _provision_chromium(
    manager: ToolManager, settings: Settings, table: _RowSink, *, force: bool, spinner: object
) -> int:
    """Download a portable Chromium for gowitness; add one row. Returns failures (0/1).

    A Chrome already on the machine (system or a previous portable install) is
    left alone — no 150 MB download when one is present, unless ``--force``.
    A platform Chrome for Testing has no build for is a ``skipped`` row, not a
    failure: gowitness simply needs a system Chrome there.
    """
    from cyberfw.tools.gowitness import _find_chrome

    if not force and _find_chrome(settings.tools_dir) is not None:
        table.add_row("chromium", "—", Text("present", style="muted"), "Chrome already available")
        return 0
    if hasattr(spinner, "update"):
        spinner.update("[info]checking[/info] chromium (Chrome for Testing) ...")
    try:
        result = manager.install_chromium(force=force)
    except ChromiumUnsupportedError as exc:
        table.add_row("chromium", "—", Text("skipped", style="warn"), str(exc))
        return 0
    except CyberfwError as exc:
        table.add_row("chromium", "—", Text("failed", style="err"), str(exc))
        return 1
    state = Text("up to date", style="muted") if result.up_to_date else Text("installed", style="ok")
    table.add_row("chromium", result.version, state, _relative_to(result.binary, settings.tools_dir))
    return 0


def _relative_to(path: Path, root: Path) -> str:
    """``subfinder/subfinder.exe`` instead of the full absolute path."""
    try:
        return str(path.relative_to(root))
    except ValueError:  # pragma: no cover - a tool installed outside tools_dir
        return str(path)


def _dep_row(label: str, found: str | None, needed_by: str) -> tuple[str, Text, RenderableType]:
    if found:
        return (label, pip_word("found", "ok"), PathText(found, style="muted"))
    return (label, pip_word("missing", "warn"), Text(f"needed by {needed_by}", style="muted"))


def _binary_on_disk(tools_dir: Path, name: str, binary_hint: str | None) -> bool:
    """True if a binary file for ``name`` exists at all (runnable or not).

    Lets status tell a Defender-blocked/unreadable download (present but broken)
    apart from one that was never fetched.
    """
    search = binary_hint or name
    for candidate in (tools_dir / search, tools_dir / f"{search}.exe"):
        if candidate.is_file():
            return True
    if tools_dir.is_dir():
        for candidate in tools_dir.rglob("*"):
            if candidate.is_file() and (candidate.name == search or candidate.stem == search):
                return True
    return False


@app.command("status")
@app.command("doctor")
def status_cmd(verbose: VerboseOption = False) -> None:
    """Show environment readiness: tools, external deps and effective settings.

    A pre-flight check so a missing binary, a Defender-blocked executable, or an
    absent Nmap/Chrome is visible up front instead of surfacing mid-run.
    """
    from cyberfw.tools.gowitness import _find_chrome

    settings, manager = _bootstrap(verbose=verbose)
    try:
        rows = _tool_rows(manager, settings.tools_dir)
        states = [row.state for row in rows]
        platform = manager.mapping.label
        motion.play(
            console,
            lambda p: Masthead(states, platform, subtitle="status", progress=p),
            duration=0.8,
            animate=settings.animations,
        )
        console.print(_status_view(rows, settings, chrome=_find_chrome(settings.tools_dir)))
    finally:
        manager.close()


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


@app.command("vt")
def vt_cmd(
    target: Annotated[
        str, typer.Argument(help="Domain, IP, http(s) URL or file hash to look up on VirusTotal.")
    ],
    api_key: Annotated[
        str | None,
        typer.Option("--api-key", help="VirusTotal key (else from env / ~/.vt.toml / prompt)."),
    ] = None,
    json_out: Annotated[
        bool, typer.Option("--json", help="Print the result as one JSON line (for scripts / the bot).")
    ] = False,
) -> None:
    """Look up a target's reputation on VirusTotal, using your own free API key."""
    settings = load_settings()
    key = vt.resolve_or_prompt(
        api_key or settings.vt_api_key,
        interactive=_is_interactive() and not json_out,
        env_path=settings.root_dir / ".env",
    )
    if not key:
        console.print(f"[yellow]No VirusTotal API key. Get one free: {vt.API_KEY_URL}[/yellow]")
        raise typer.Exit(1)
    try:
        rep = anyio.run(_vt_lookup, key, target)
    except vt.VtError as exc:
        console.print(f"[err]VirusTotal: {exc}[/err]")
        raise typer.Exit(1) from exc
    if json_out:
        print(json.dumps(rep.as_record()))
    else:
        _print_reputation(rep)


async def _vt_lookup(key: str, target: str) -> vt.Reputation:
    async with httpx.AsyncClient(timeout=30.0) as client:
        return await vt.lookup(client, key, target)


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


def _resolve_vt_key(settings: Settings, choice: bool | None) -> str | None:
    """Decide the VirusTotal key for a pipeline run.

    Enrichment is on by default: a key already configured (``--api-key`` is not
    a pipeline option, so this means env / ``.env`` / ``~/.vt.toml``) is used
    silently. When none is set, the console offers to save one — the first time
    only on a default run, or every time under ``--vt``. ``--no-vt`` turns it
    off and never prompts (CI, pipes, or just not wanting VirusTotal).
    """
    if choice is False:  # --no-vt
        return None
    key = vt.resolve_api_key(settings.vt_api_key)
    if key:
        return key
    # No key anywhere. Ask only when someone can answer, and — on a default run
    # — only the first time (``--vt`` forces the ask even after an earlier skip).
    should_ask = _is_interactive() and (choice is True or not settings.vt_prompted)
    if not should_ask:
        if choice is True:
            console.print(
                f"[warn]VirusTotal: no API key set and no prompt available. "
                f"Free key: {vt.API_KEY_URL}[/warn]"
            )
        return None
    env_path = settings.root_dir / ".env"
    entered = vt.resolve_or_prompt(None, interactive=True, env_path=env_path)
    # Offer once: record that we asked (a pasted key is already saved to .env by
    # resolve_or_prompt) so later default runs do not prompt again.
    vt.remember_prompt(env_path)
    if not entered:
        console.print(
            "[muted]VirusTotal enrichment off for this run — run with --vt to enable later.[/muted]"
        )
    return entered


def _enrich_with_intel(result: PipelineResult, cache_dir: Path) -> None:
    """Rate CVE findings by real-world exploitation (CISA KEV, EPSS, Exploit-DB)."""
    if not any(threatintel.cve_ids(r) for r in result.records if r.kind == "vuln"):
        return
    console.print("[muted]Threat intel: checking CVEs against CISA KEV, EPSS and Exploit-DB…[/muted]")
    try:
        summary = anyio.run(threatintel.enrich, result.records, cache_dir)
    except Exception as exc:  # noqa: BLE001 - intel must never fail the scan
        console.print(f"[warn]Threat intel failed: {exc}[/warn]")
        return
    for error in summary.errors:
        console.print(f"[warn]Threat intel — {error}[/warn]")
    parts = [f"{summary.cves} CVE(s) in {summary.findings} finding(s)"]
    if summary.exploited:
        parts.append(f"[err]{summary.exploited} exploited in the wild (CISA KEV)[/err]")
    if summary.exploits:
        parts.append(f"{summary.exploits} with a public exploit")
    if summary.likely:
        parts.append(f"{summary.likely} with EPSS ≥ {threatintel.EPSS_HIGH:.0%}")
    console.print("Threat intel: " + " · ".join(parts))


def _enrich_with_vt(result: PipelineResult, api_key: str, limit: int) -> None:
    """Append VirusTotal reputation records for the run's discovered targets."""
    targets = vt.enrichment_targets(result.records)
    if not targets:
        return
    console.print(
        f"[muted]VirusTotal: looking up {min(len(targets), limit)} target(s), throttled to 4/min…[/muted]"
    )
    try:
        reps = anyio.run(vt.enrich, targets, api_key, limit)
    except Exception as exc:  # noqa: BLE001 - enrichment must never fail the scan
        console.print(f"[warn]VirusTotal enrichment failed: {exc}[/warn]")
        return
    for index, rep in enumerate(reps, 1):
        result.records.append(validate_record("virustotal", json.dumps(rep.as_record()), index))
    flagged = sum(1 for rep in reps if rep.flagged)
    console.print(f"[muted]VirusTotal: {len(reps)} looked up, {flagged} flagged.[/muted]")


@app.command("run")
def run_cmd(
    tool: Annotated[str, typer.Argument(help="Tool name from registry.yaml (e.g. subfinder).")],
    target: Annotated[str | None, typer.Option("--target", "-t", help="Single target (host/URL/port).")] = None,
    list_file: Annotated[Path | None, typer.Option("--list", "-l", help="Host list file (newline separated).")] = None,
    wordlist: Annotated[str | None, typer.Option("--wordlist", "-w", help="Custom wordlist for fuzzing.")] = None,
    session: Annotated[str | None, typer.Option("--session", help="Session id, only meaningful together with --save.")] = None,
    no_parse: Annotated[
        bool,
        typer.Option(
            "--no-parse",
            help="Skip schema parsing: stream every raw stdout/stderr line exactly as the tool prints it.",
        ),
    ] = False,
    save: Annotated[
        bool | None,
        typer.Option(
            "--save/--no-save",
            help="Archive this run's records and reports to reports/<session>/. "
            "Omit both to be asked once the results are on screen.",
        ),
    ] = None,
    verbose: VerboseOption = False,
) -> None:
    """Run a single registered tool and print its records to the screen."""
    if target is None and list_file is None:
        console.print("[err]Provide a target via --target and/or a host list via --list.[/err]")
        raise typer.Exit(2)
    if session:
        _checked_session(session)

    settings, manager = _bootstrap(verbose=verbose)
    try:
        # The adapter knows what kind of target it takes; check that before
        # looking for the binary so a wrong target is a usage error (exit 2).
        if target is not None:
            adapter_class(tool).validate_target(target)
    except ValueError as exc:
        console.print(f"[err]{exc}[/err]")
        raise typer.Exit(2) from exc
    except CyberfwError as exc:
        console.print(f"[err]{exc}[/err]")
        raise typer.Exit(1) from exc
    try:
        # Validate the binary is installed so we can offer a targeted hint.
        manager.binary_path(tool)
    except ToolNotFoundError as exc:
        console.print(f"[err]{exc}[/err]")
        console.print("[warn]Run `cyberfw init` first (or export CYBERFW_GITHUB_TOKEN).[/warn]")
        raise typer.Exit(1) from exc
    except CyberfwError as exc:
        console.print(f"[err]{exc}[/err]")
        raise typer.Exit(1) from exc

    session_id = session or _session_tag("run", tool)
    # Only --save streams into reports/<session>/ as records arrive (crash-safe).
    # Undecided runs write nothing until the user has answered, so an ad-hoc
    # `run` never litters the filesystem with a folder nobody asked for.
    context = SessionContext(settings.reports_dir, session_id) if save else None
    engine = PipelineEngine(settings, manager, context=context)

    hosts = _read_hosts(list_file) if list_file is not None else []
    ctx = ToolContext(target=target, inputs=hosts, extra_input=wordlist or settings.wordlist)
    target_label = target or f"{len(hosts)} host(s) from {list_file}"
    console.print(f"[info]tool:[/info] [tool]{tool}[/tool]  [info]target:[/info] {target_label}")

    # Parsing is on by default; disable it via the config `parse:` setting
    # (CYBERFW_PARSE=false) or override per-run with --no-parse.
    do_parse = settings.parse and not no_parse

    # Timed here, around the process, so a saved report's duration is the
    # tool's — not the instant the user answered the save prompt.
    started_at = datetime.now(timezone.utc)
    if not do_parse:
        why = "--no-parse" if no_parse else "config parse=false"
        console.print(f"[muted]{why}: streaming raw stdout/stderr exactly as the tool prints it[/muted]")

        async def _print_stdout(record: ToolRecord) -> None:
            console.print(record.raw)

        async def _print_stderr(line: str) -> None:
            console.print(line, style="dim")

        engine.set_record_callback(_print_stdout)
        engine.set_stderr_callback(_print_stderr)
        try:
            node_result, records = anyio.run(_run_single, engine, ctx, tool, False)
        finally:
            manager.close()
        console.print(f"[info]{len(records)} line(s) captured[/info]")
    else:
        view = PipelineLiveView(
            [Node(tool=tool, stage=tool)], title=f"{tool} · {target_label}", animate=settings.animations
        )
        # The view is a renderable (``__rich__``) on auto-refresh: callbacks only
        # change its state, and the spinner, bars and timer move between them.
        with Live(view, console=console, refresh_per_second=_live_fps(settings), transient=False) as live:

            async def _on_record(record: ToolRecord) -> None:
                view.on_record(record)

            async def _on_stage(event: StageEvent) -> None:
                view.on_stage(event)

            engine.set_record_callback(_on_record)
            engine.set_stage_callback(_on_stage)
            try:
                node_result, records = anyio.run(_run_single, engine, ctx, tool, True)
            finally:
                manager.close()
                view.finish()
                live.refresh()
        _after_live()
        if records:
            console.print(_record_table(records, tool=tool, target=target_label))
        else:
            console.print("[muted]No records found.[/muted]")
    finished_at = datetime.now(timezone.utc)

    if context is not None:
        context.close()
    # --save decided up front (and streamed the records as they came); an
    # undecided run asks now, and only when there is something to keep.
    if save or (save is None and records and _wants_to_save(save, default=False, what=tool)):
        result = PipelineResult(
            nodes=[node_result],
            records=records,
            started_at=started_at,
            finished_at=finished_at,
        )
        if context is None:
            # Nothing was streamed, so archive the records now.
            with SessionContext(settings.reports_dir, session_id) as store:
                for record in records:
                    store.append(tool, record)
        written = _write_reports(
            result,
            session_id=session_id,
            settings=settings,
            run=_run_info(manager, name=tool, seed=target, session_id=session_id, tools={tool}),
        )
        console.print(f"[ok]saved:[/ok] {settings.reports_dir / session_id}")
        for label, path in written:
            console.print(f"[ok]{label}:[/ok] {path}")

    if not node_result.ok:
        console.print(f"[err]{node_result.error or 'stage failed'}[/err]")
        raise typer.Exit(1)


@app.command("pipeline")
def pipeline_cmd(
    name: Annotated[str, typer.Argument(help="Pipeline name: recon-to-vuln or a file from pipelines/<name>.yaml.")],
    target: Annotated[str | None, typer.Option("--target", "-t", help="Seed domain/URL for the first stage.")] = None,
    ffuf: Annotated[bool, typer.Option("--ffuf", help="Include the Ffuf node.")] = False,
    gowitness: Annotated[bool, typer.Option("--gowitness", help="Include the Gowitness node.")] = False,
    max_httpx: Annotated[int, typer.Option("--max-httpx", min=0, help="Cap live hosts passed onward (0 = all).")] = 0,
    wordlist: Annotated[str | None, typer.Option("--wordlist", "-w", help="Wordlist for the Ffuf stage (required with --ffuf).")] = None,
    session: Annotated[str | None, typer.Option("--session", help="Session id for the context store.")] = None,
    report: Annotated[
        bool | None,
        typer.Option(
            "--report/--no-report",
            help="Keep this run's reports/<session>/ directory. Omit both to be asked when the run ends.",
        ),
    ] = None,
    no_parse: Annotated[
        bool,
        typer.Option(
            "--no-parse",
            help="Verbose mode: stream every stage's raw stdout/stderr live "
            "(records are still parsed under the hood to thread stages).",
        ),
    ] = False,
    force_start: Annotated[
        bool,
        typer.Option("--force-start", help="Start even when a tool this pipeline needs is unavailable."),
    ] = False,
    topology: Annotated[
        bool | None,
        typer.Option(
            "--topology/--no-topology",
            "--map/--no-map",
            help="Live view: the topology map (seed → hosts → ports/vulns) or the stage table. "
            "Default comes from the `view` setting; this overrides it for one run.",
        ),
    ] = None,
    vt_enrich: Annotated[
        bool | None,
        typer.Option(
            "--vt/--no-vt",
            help="Enrich discovered domains/IPs/URLs with VirusTotal reputation after the scan. "
            "On by default, using your own key (env / .env / ~/.vt.toml); you are asked for one "
            "the first time. --no-vt skips it; --vt forces the prompt.",
        ),
    ] = None,
    vt_limit: Annotated[
        int,
        typer.Option("--vt-limit", min=1, help="Max VirusTotal lookups (free tier: 4/min, 500/day)."),
    ] = 20,
    intel: Annotated[
        bool,
        typer.Option(
            "--intel/--no-intel",
            help="Rate CVE findings by real-world exploitation: CISA KEV (exploited in the wild), "
            "EPSS (chance of attack in 30 days) and Exploit-DB (public exploit). Free, no keys; "
            "only public feeds are queried, never the target.",
        ),
    ] = True,
    verbose: VerboseOption = False,
) -> None:
    """Run a ready-made pipeline and render HTML/JSON reports.

    CVE findings are rated by real-world exploitation (CISA KEV, EPSS,
    Exploit-DB) — use --no-intel to skip. Discovered domains, IPs and URLs are
    enriched with VirusTotal reputation by default (your own free key; you are
    asked for one the first time) — use --no-vt to skip it.
    """
    if target is None:
        console.print("[err]Provide a seed target via --target.[/err]")
        raise typer.Exit(2)
    if session:
        _checked_session(session)

    settings, manager = _bootstrap(verbose=verbose)
    # Resolve the VirusTotal key up front (and prompt if needed) before the live
    # view takes over the terminal — a prompt and a Live render cannot coexist.
    vt_key = _resolve_vt_key(settings, vt_enrich)
    try:
        nodes = build(
            name,
            pipelines_dir=settings.pipelines_dir,
            include_ffuf=ffuf,
            include_gowitness=gowitness,
            max_httpx=max_httpx,
        )
        for node in nodes:  # a YAML pipeline may name a tool the registry (or the code) lacks
            manager.spec(node.tool)
            adapter_class(node.tool)
    except RegistryError as exc:
        console.print(f"[err]{exc}[/err]")
        manager.close()
        raise typer.Exit(2) from exc

    # Whether the run can happen at all is knowable now, and a scan takes
    # minutes: report what is unavailable up front instead of spending the
    # time only to say that a stage never ran.
    blocking, dep_warnings = _preflight(manager, nodes, settings.tools_dir)
    for warning in dep_warnings:
        console.print(f"[warn]{warning}[/warn]")
    if blocking and not force_start:
        for stage, tool, reason in blocking:
            console.print(f"[err]{tool}[/err] ({stage}): [err]{reason}[/err]")
        console.print(
            "[warn]Fix the above (`cyberfw init`, `cyberfw status`), "
            "or pass --force-start to run the stages that can.[/warn]"
        )
        manager.close()
        raise typer.Exit(2)

    wordlist = wordlist or settings.wordlist
    if ffuf and not wordlist:
        bundled = default_wordlist()
        if bundled is not None:
            console.print(
                f"[muted]--ffuf: no wordlist given, using the bundled {bundled.name} "
                "(pass --wordlist <path> to override)[/muted]"
            )
        else:
            console.print(
                "[warn]--ffuf needs a wordlist and the bundled default was not found; "
                "the fuzz stage will be skipped. Re-run with --wordlist <path>.[/warn]"
            )
    session_id = session or _session_tag("pipeline", name)
    # Remember whether the directory is ours: declining to save may remove it,
    # and a --session pointing at an earlier run must never be deleted.
    session_dir = settings.reports_dir / session_id
    session_is_new = not session_dir.exists()
    context = SessionContext(settings.reports_dir, session_id)
    # The pre-flight above already reported any missing optional dependency.
    engine = PipelineEngine(settings, manager, context=context, report_missing_deps=False)

    # Verbose view when parsing is disabled (config parse=false or --no-parse):
    # stream each stage's raw stdout/stderr live instead of the quiet spinner.
    # Stages are still parsed internally so results thread from one to the next.
    verbose = no_parse or not settings.parse
    run_engine = functools.partial(engine.run, extra_input=wordlist)
    # The flag overrides the `view` setting for this run; unset falls back to it.
    use_topology = topology if topology is not None else settings.view == "topology"
    if topology is True and verbose:
        # Only when the user explicitly asked: the config default silently yields
        # to the raw stream under --no-parse rather than nagging every run.
        why = "--no-parse" if no_parse else "config parse=false"
        console.print(f"[warn]--topology needs the parsed view; ignored under {why}.[/warn]")
    if verbose:
        why = "--no-parse" if no_parse else "config parse=false"
        console.print(f"[muted]{why}: streaming raw stdout/stderr from every stage[/muted]")

        async def _print_stdout(line: str) -> None:
            console.print(line)

        async def _print_stderr(line: str) -> None:
            console.print(line, style="dim")

        engine.set_stdout_raw_callback(_print_stdout)
        engine.set_stderr_callback(_print_stderr)
        try:
            result = anyio.run(run_engine, nodes, target)
        except CyberfwError as exc:
            console.print(f"[err]{exc}[/err]")
            raise typer.Exit(1) from exc
        finally:
            manager.close()
    else:
        # The live view IS the final frame, so it is not reprinted afterwards:
        # Live leaves its last frame on screen. On a non-TTY (CI, a pipe) Rich
        # prints that final frame once instead of redrawing.
        #
        # Both views are renderable objects (``__rich__``) driven by
        # auto-refresh, so spinners, bars, timers and the growth pulse animate
        # between events — callbacks only mutate state.
        view: PipelineLiveView | TopologyView
        if use_topology:
            view = TopologyView(nodes, seed=target, title=f"{name} · {target}", animate=settings.animations)
        else:
            view = PipelineLiveView(nodes, title=f"pipeline {name} · {target}", animate=settings.animations)
        with Live(view, console=console, refresh_per_second=_live_fps(settings), transient=False) as live:

            async def _on_record(record: ToolRecord) -> None:
                view.on_record(record)

            async def _on_stage(event: StageEvent) -> None:
                view.on_stage(event)

            engine.set_record_callback(_on_record)
            engine.set_stage_callback(_on_stage)
            try:
                result = anyio.run(run_engine, nodes, target)
            except CyberfwError as exc:
                console.print(f"[err]{exc}[/err]")
                raise typer.Exit(1) from exc
            finally:
                manager.close()
                view.finish()
                live.refresh()
        _after_live()

    if intel:
        _enrich_with_intel(result, settings.cache_dir)
    if vt_key:
        _enrich_with_vt(result, vt_key, vt_limit)

    if verbose:
        console.print(_node_table(result))

    context.close()
    written: list[tuple[str, Path]] = []
    if _wants_to_save(report, default=True, what=name):
        try:
            written = _write_reports(
                result,
                session_id=session_id,
                settings=settings,
                run=_run_info(
                    manager,
                    name=name,
                    seed=target,
                    session_id=session_id,
                    tools={n.tool for n in nodes},
                ),
            )
        except CyberfwError as exc:
            console.print(f"[err]report failed:[/err] {exc}")
            return
    else:
        _discard_session(session_dir, created=session_is_new)

    # A blank line: Live's last frame ends without one, so the panel would
    # otherwise start on the same line as the table's bottom edge.
    console.print()
    motion.play(
        console,
        lambda progress: _run_summary(
            result, name=name, session_id=session_id, reports=written, progress=progress
        ),
        duration=0.7,
        animate=settings.animations,
    )

    if not result.succeeded():
        raise typer.Exit(1)


# -- async helpers for anyio --------------------------------------------------------------------
async def _run_single(
    engine: PipelineEngine, ctx: ToolContext, tool: str, parse: bool
) -> tuple[NodeResult, list[ToolRecord]]:
    """Run one tool stage through the engine (handles fan-out and crashes)."""
    return await engine.run_single(Node(tool=tool, stage=tool), ctx, parse=parse)


if __name__ == "__main__":
    app()
