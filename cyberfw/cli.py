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
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from time import strftime
from typing import Annotated

import anyio
import typer
from rich import box
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from cyberfw.config import Settings, load_settings
from cyberfw.exceptions import CyberfwError, RegistryError, ToolNotFoundError
from cyberfw.live_view import PipelineLiveView
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
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.pipelines import PIPELINES, available_pipelines, build
from cyberfw.report.html_report import generate_html_report
from cyberfw.report.json_report import generate_json_report
from cyberfw.report.run_info import RunInfo
from cyberfw.resources import packaged_data
from cyberfw.tools import adapter_class
from cyberfw.tools.base import ToolContext
from cyberfw.ui import banner, readiness, record_detail, record_style, state_style, tool_guide

LOG = get_logger("cli")

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
def _bootstrap() -> tuple[Settings, ToolManager]:
    """Load settings + registry, ensure directories, wire logging, return manager."""
    settings = load_settings()
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


def _record_table(records: list[ToolRecord]) -> Table:
    """A Rich table summarising validated records for a stage.

    A record carrying ``ports_list`` (RustScan's one-line-per-host summary)
    is expanded into one row per port — otherwise a dozen open ports collapse
    into an unreadable comma blob crammed into a single "detail" cell.
    """
    table = Table(title="Validated records", title_style="accent", box=box.SIMPLE_HEAD)
    table.add_column("#", style="muted", justify="right")
    table.add_column("target", overflow="fold")
    table.add_column("kind", style="muted")
    table.add_column("detail", overflow="fold")
    index = 0
    for record in records:
        style = record_style(record)
        ports_list = getattr(record, "ports_list", "")
        if ports_list:
            state = getattr(record, "port_state", "open")
            for port in _sorted_ports(ports_list):
                index += 1
                table.add_row(str(index), Text(f"{record.target}:{port}", style=style), "port", state)
            continue
        index += 1
        table.add_row(
            str(index),
            Text(record.target, style=style),
            record.kind,
            Text(record_detail(record), style=style),
        )
    return table


def _node_table(result: PipelineResult) -> Table:
    """A Rich table of per-stage results."""
    table = Table(title="Pipeline stages", box=box.ROUNDED)
    table.add_column("tool", style="tool")
    table.add_column("stage")
    table.add_column("status")
    table.add_column("records", justify="right")
    table.add_column("error", style="err", overflow="fold")
    for node_result in result.nodes:
        status = "[ok]ok[/ok]" if node_result.ok else "[err]failed[/err]"
        table.add_row(
            node_result.node.tool,
            node_result.node.stage,
            status,
            str(node_result.count),
            node_result.error or "",
        )
    return table


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
        platform=f"{manager.mapping.os_name}/{manager.mapping.arch}",
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
        requirement = adapter_class(node.tool).missing_requirement()
        if requirement is not None:
            blocking.append((node.stage, node.tool, requirement))
        for dep in manager.spec(node.tool).check_deps:
            if shutil.which(dep) is None:
                warnings.append(
                    f"{node.tool} works best with `{dep}`, which is not on PATH — {dependency_hint(dep)}"
                )
    return blocking, warnings


def _run_summary(
    result: PipelineResult, *, name: str, session_id: str, reports: list[tuple[str, Path]]
) -> Panel:
    """Closing panel: did it work, what came out of it, where the artefacts are."""
    ok = result.succeeded()
    totals = "  ".join(f"{tool} [accent]{count}[/accent]" for tool, count in result.totals_by_tool.items())
    lines = [
        Text.assemble(
            ("success" if ok else "failed", "ok" if ok else "err"),
            ("  ·  ", "muted"),
            (f"{len(result.records)} record(s)", "white"),
            ("  ·  ", "muted"),
            (f"elapsed {result.duration_s:.1f}s" if result.duration_s is not None else "elapsed n/a", "white"),
        ),
        Text.from_markup(totals or "[muted]no records[/muted]"),
    ]
    # Name the stages that did not deliver: the panel is the last thing on
    # screen, and scrolling back through a long run to find out which one it
    # was is exactly what the summary exists to save.
    for label, style, entries in (
        ("failed ", "err", [n for n in result.nodes if not n.ok and not n.skipped]),
        ("skipped", "warn", [n for n in result.nodes if n.skipped]),
    ):
        if entries:
            named = ", ".join(f"{n.node.stage} ({n.node.tool})" for n in entries)
            lines.append(Text.assemble((f"{label}  ", style), (named, "white")))
    lines.append(Text.assemble(("session  ", "muted"), (session_id, "white")))
    lines += [Text.assemble((f"{label:<8} ", "muted"), (str(path), "white")) for label, path in reports]
    return Panel(
        Group(*lines),
        title=f"[bold]{name}[/bold]",
        border_style="ok" if ok else "err",
        box=box.ROUNDED,
        padding=(1, 2),
        expand=False,
    )


def _session_tag(kind: str, name: str) -> str:
    return f"{kind}-{name}-{strftime('%Y%m%d-%H%M%S')}"


def _tool_state(manager: ToolManager, name: str, tools_dir: Path) -> str:
    """``ready`` / ``blocked`` / ``not installed`` for one registered tool.

    Readiness is "can this run", so a binary that resolves is ready even
    without an install record (the record only carries the version, shown in
    its own column). ``blocked`` is the narrow case the user must act on: the
    file is on disk but cannot be read or executed — typically an antivirus
    quarantine.
    """
    try:
        manager.binary_path(name)
    except CyberfwError:
        return "blocked" if _binary_on_disk(tools_dir, name, manager.spec(name).binary) else "not installed"
    return "ready"


def _tool_version(manager: ToolManager, name: str) -> str:
    return str((manager.install_state(name) or {}).get("version", ""))


def _inventory_table(manager: ToolManager, tools_dir: Path, *, numbered: bool = False) -> tuple[Table, list[str]]:
    """The tool inventory shared by the launcher and ``status``.

    Returns the table and the per-tool states, so the caller can render the
    readiness summary without computing them twice.
    """
    table = Table(title="TOOLS", title_style="accent", box=box.SIMPLE_HEAD, expand=True, pad_edge=False)
    if numbered:
        table.add_column("#", style="accent", justify="right", width=2)
    table.add_column("tool", style="tool", no_wrap=True)
    table.add_column("version", style="muted", no_wrap=True)
    table.add_column("state", no_wrap=True)
    table.add_column("source", style="muted", overflow="ellipsis", no_wrap=True)
    states: list[str] = []
    for index, name in enumerate(manager.registry.names(), start=1):
        state = _tool_state(manager, name, tools_dir)
        states.append(state)
        row: list[str | Text] = [
            name,
            _tool_version(manager, name) or "—",
            Text(state, style=state_style(state)),
            manager.spec(name).repo,
        ]
        table.add_row(*([str(index), *row] if numbered else row))
    return table, states


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


def interactive_menu() -> None:
    """Run the keyboard-driven launcher used by ``cs-tool`` without arguments."""
    _ensure_tools()
    settings, manager = _bootstrap()
    try:
        states = [
            _tool_state(manager, name, settings.tools_dir) for name in manager.registry.names()
        ]
        platform = f"{manager.mapping.os_name}/{manager.mapping.arch}"
    finally:
        manager.close()
    console.print(banner(states, platform))
    while True:
        # Settings-adjust cycle: the launcher panel is a Live region, so the
        # p/l/f toggles redraw it in place instead of re-printing the whole
        # panel and scrolling the terminal. We leave Live only once a real
        # action (tool / pipeline / exit) is picked, so that action's output
        # scrolls normally below the panel.
        names: list[str] = []
        with Live(console=console, auto_refresh=False, screen=False, vertical_overflow="visible") as live:
            while True:
                settings, manager = _bootstrap()
                try:
                    names = manager.registry.names()
                    live.update(_launcher_view(manager, settings), refresh=True)
                finally:
                    manager.close()
                choice = _prompt_choice(names)
                if choice in _SETTINGS_KEYS:
                    _toggle_setting(choice, settings)
                    continue  # stay inside Live → in-place refresh
                break

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
_SETTINGS_KEYS = frozenset({"p", "l", "f"})


def _tool_range(names: list[str]) -> str:
    """``1-8`` for eight tools, ``1`` for a single one."""
    return "1" if len(names) == 1 else f"1-{len(names)}"


def _prompt_choice(names: list[str]) -> str:
    """Prompt for a menu choice, with an on-brand hint on invalid input.

    Returns a normalised token: a tool number, the pipeline key, an exit key
    or a settings hotkey (``p``/``l``/``f``). Anything else re-prompts with a
    plain explanation instead of Rich's generic "not a valid integer" loop.
    """
    valid = {str(index) for index in range(1, len(names) + 1)} | {_PIPELINE_KEY} | _EXIT_KEYS | _SETTINGS_KEYS
    while True:
        raw = Prompt.ask("Select tool or action").strip().lower()
        if raw in valid:
            return raw
        console.print(
            f"[warn]Type {_tool_range(names)} for a tool, {_PIPELINE_KEY} pipeline, 0 exit, "
            "or p/l/f to change settings.[/warn]"
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


def _launcher_view(manager: ToolManager, settings: Settings) -> Table:
    """Render the compact two-column launcher workspace."""
    table = Table.grid(expand=True, padding=(0, 2))
    table.add_column(width=28, no_wrap=True, vertical="top")
    table.add_column(ratio=1, vertical="top")

    def _flag(value: bool) -> tuple[str, str]:
        return ("on", "ok") if value else ("off", "warn")

    names = manager.registry.names()
    sidebar = Table.grid(padding=(0, 0))
    sidebar.add_row(Text("SHORTCUTS", style="accent"))
    sidebar.add_row(Text(f"  {_tool_range(names):<4} select tool", style="dim"))
    sidebar.add_row(Text(f"  {_PIPELINE_KEY:<4} run pipeline", style="dim"))
    sidebar.add_row(Text("  0    exit", style="dim"))
    sidebar.add_row("")
    sidebar.add_row(Text("SETTINGS", style="accent"))
    parse_text, parse_style = _flag(settings.parse)
    sidebar.add_row(Text.assemble(("  p  parse      ", "dim"), (parse_text, parse_style)))
    sidebar.add_row(Text.assemble(("  l  log level  ", "dim"), (settings.log_level, "info")))
    file_text, file_style = _flag(settings.log_to_file)
    sidebar.add_row(Text.assemble(("  f  log file   ", "dim"), (file_text, file_style)))

    content, states = _inventory_table(manager, settings.tools_dir, numbered=True)
    sidebar.add_row("")
    sidebar.add_row(Text("STATUS", style="accent"))
    sidebar.add_row(Text.assemble(("  ", ""), readiness(states)))

    table.add_row(Panel(sidebar, border_style="accent", padding=(1, 1), box=box.ROUNDED), content)
    return table


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
    console.print(tool_guide(tool))
    adapter = adapter_class(tool)
    target = Prompt.ask(adapter.target_prompt)
    wordlist: str | None = None
    if adapter.extra_input_prompt is not None:
        wordlist = Prompt.ask(adapter.extra_input_prompt, default="") or None
    run_cmd(tool, target=target, wordlist=wordlist)


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
) -> None:
    """Download and install precompiled tool binaries into ``tools_bin/``.

    A tool whose installed version already matches (the pinned ``version:`` in
    registry.yaml, or the latest release) is left alone unless ``--force``.
    """
    settings, manager = _bootstrap()
    if token:
        settings = settings.model_copy(update={"github_token": token})
        manager = ToolManager(settings, manager.registry, manager.mapping)

    targets = tools or manager.registry.names()
    console.print(
        Text.assemble(
            (f"Installing {len(targets)} tool(s) into ", "info"), (str(settings.tools_dir), "tool")
        )
    )
    # Not expanded, and the detail is relative to tools_dir: an absolute
    # Windows path is ~90 characters and squeezes every other column away.
    table = Table(box=box.SIMPLE_HEAD, pad_edge=False)
    table.add_column("tool", style="tool", no_wrap=True)
    table.add_column("version", style="muted", no_wrap=True)
    table.add_column("state", no_wrap=True)
    table.add_column("detail", style="muted", overflow="ellipsis")
    ok, failed = 0, 0
    try:
        with console.status("", spinner="dots") as spinner:
            for name in targets:
                spec = manager.spec(name)
                wanted = spec.version if spec.version != "latest" else "latest release"
                spinner.update(f"[info]checking[/info] {name} ({spec.repo}, {wanted}) ...")
                try:
                    result = manager.install(name, force=force)
                except CyberfwError as exc:
                    failed += 1
                    table.add_row(name, "—", Text("failed", style="err"), str(exc))
                    continue
                ok += 1
                state = (
                    Text("up to date", style="muted")
                    if result.up_to_date
                    else Text("installed", style="ok")
                )
                table.add_row(name, result.version, state, _relative_to(result.binary, settings.tools_dir))
    finally:
        manager.close()

    console.print(table)
    if failed:
        console.print(f"[warn]{ok} ready, {failed} failed.[/warn]")
        raise typer.Exit(1)
    console.print(f"[ok]Done: {ok} tool(s) ready.[/ok]")


def _relative_to(path: Path, root: Path) -> str:
    """``subfinder/subfinder.exe`` instead of the full absolute path."""
    try:
        return str(path.relative_to(root))
    except ValueError:  # pragma: no cover - a tool installed outside tools_dir
        return str(path)


def _dep_row(label: str, found: str | None, needed_by: str) -> tuple[str, str, str]:
    if found:
        return (label, "[ok]found[/ok]", found)
    return (label, "[warn]missing[/warn]", f"needed by {needed_by}")


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
def status_cmd() -> None:
    """Show environment readiness: tools, external deps and effective settings.

    A pre-flight check so a missing binary, a Defender-blocked executable, or an
    absent Nmap/Chrome is visible up front instead of surfacing mid-run.
    """
    from cyberfw.tools.gowitness import _find_chrome

    settings, manager = _bootstrap()
    try:
        tools, states = _inventory_table(manager, settings.tools_dir)
        platform = f"{manager.mapping.os_name}/{manager.mapping.arch}"
        console.print(banner(states, platform))
        # The banner already carries the readiness and the platform; what it
        # cannot show is where the binaries are looked for.
        console.print(
            Text.assemble(("tools dir  ", "muted"), (str(settings.tools_dir), "white"))
        )
        console.print(tools)

        deps = Table(title="External dependencies", box=box.SIMPLE_HEAD, expand=True)
        deps.add_column("dependency", style="tool")
        deps.add_column("state")
        deps.add_column("detail", style="muted", overflow="fold")
        deps.add_row(*_dep_row("nmap", shutil.which("nmap"), "rustscan (service/version detection)"))
        deps.add_row(*_dep_row("chrome/chromium", _find_chrome(), "gowitness (screenshots)"))
        console.print(deps)

        cfg = Table(title="Effective settings", box=box.SIMPLE_HEAD, expand=True)
        cfg.add_column("setting", style="tool")
        cfg.add_column("value")
        cfg.add_row("parse", "[ok]on[/ok]" if settings.parse else "[warn]off (raw output)[/warn]")
        cfg.add_row("log_level", settings.log_level)
        cfg.add_row("log_to_file", "on" if settings.log_to_file else "off")
        cfg.add_row("concurrency", str(settings.concurrency))
        cfg.add_row(
            "stage_timeout",
            f"{settings.stage_timeout:g}s" if settings.stage_timeout else "[muted]unlimited[/muted]",
        )
        cfg.add_row("wordlist", settings.wordlist or "[muted](unset — needed for ffuf)[/muted]")
        cfg.add_row("github_token", "[ok]set[/ok]" if settings.github_token else "[muted]unset (60 req/h)[/muted]")
        cfg.add_row("reports_dir", str(settings.reports_dir))
        cfg.add_row("logs_dir", str(settings.logs_dir))
        console.print(cfg)
    finally:
        manager.close()


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
) -> None:
    """Run a single registered tool and print its records to the screen."""
    if target is None and list_file is None:
        console.print("[err]Provide a target via --target and/or a host list via --list.[/err]")
        raise typer.Exit(2)

    settings, manager = _bootstrap()
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
        view = PipelineLiveView([Node(tool=tool, stage=tool)], title=f"{tool} · {target_label}")
        with Live(view.render(), console=console, refresh_per_second=4, transient=False) as live:

            async def _on_record(record: ToolRecord) -> None:
                view.on_record(record)
                live.update(view.render())

            async def _on_stage(event: StageEvent) -> None:
                view.on_stage(event)
                live.update(view.render())

            engine.set_record_callback(_on_record)
            engine.set_stage_callback(_on_stage)
            try:
                node_result, records = anyio.run(_run_single, engine, ctx, tool, True)
            finally:
                manager.close()
                live.update(view.render())
        if records:
            console.print(_record_table(records))
        else:
            console.print("[muted]No records found.[/muted]")

    if context is not None:
        context.close()
    if save:
        console.print(f"[ok]saved:[/ok] {settings.reports_dir / session_id}")
    elif records and _wants_to_save(save, default=False, what=tool):
        # Nothing was streamed, so archive the records now and report on them.
        result = PipelineResult(
            nodes=[node_result],
            records=records,
            started_at=datetime.now(timezone.utc),
            finished_at=datetime.now(timezone.utc),
        )
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
) -> None:
    """Run a ready-made pipeline and render HTML/JSON reports."""
    if target is None:
        console.print("[err]Provide a seed target via --target.[/err]")
        raise typer.Exit(2)

    settings, manager = _bootstrap()
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
        console.print(
            "[warn]--ffuf needs a wordlist; the fuzz stage will be skipped. "
            "Re-run with --wordlist <path> to enable it.[/warn]"
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
        # The live table IS the stage table, so it is not reprinted afterwards:
        # Live leaves its last frame on screen. On a non-TTY (CI, a pipe) Rich
        # prints that final frame once instead of redrawing.
        view = PipelineLiveView(nodes, title=f"pipeline {name} · {target}")
        with Live(view.render(), console=console, refresh_per_second=4, transient=False) as live:

            async def _on_record(record: ToolRecord) -> None:
                view.on_record(record)
                live.update(view.render())

            async def _on_stage(event: StageEvent) -> None:
                view.on_stage(event)
                live.update(view.render())

            engine.set_record_callback(_on_record)
            engine.set_stage_callback(_on_stage)
            try:
                result = anyio.run(run_engine, nodes, target)
            except CyberfwError as exc:
                console.print(f"[err]{exc}[/err]")
                raise typer.Exit(1) from exc
            finally:
                manager.close()
                live.update(view.render())

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
    console.print(_run_summary(result, name=name, session_id=session_id, reports=written))

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
