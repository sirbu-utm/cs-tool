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
from pathlib import Path
from time import strftime
from typing import Annotated

import anyio
import typer
from rich import box
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from cyberfw.config import Settings, load_settings
from cyberfw.exceptions import CyberfwError, RegistryError, ToolNotFoundError
from cyberfw.logging import console, ensure_utf8_stdio, get_logger, setup_logging
from cyberfw.manager import ToolManager, load_registry
from cyberfw.pipeline.context import SessionContext
from cyberfw.pipeline.engine import Node, NodeResult, PipelineEngine, PipelineResult
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.pipelines import build
from cyberfw.report.html_report import generate_html_report
from cyberfw.report.json_report import generate_json_report
from cyberfw.tools.base import ToolContext
from cyberfw.ui import banner, tool_guide

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


def _registry_path() -> Path:
    """Locate ``registry.yaml`` (repo root preferred, package-relative fallback)."""
    cwd = Path.cwd() / "registry.yaml"
    if cwd.exists():
        return cwd
    pkg_root = Path(__file__).resolve().parent.parent
    fallback = pkg_root / "registry.yaml"
    if fallback.exists():
        return fallback
    raise RegistryError(
        f"registry.yaml not found near {cwd}. Run cyberfw from the project root."
    )


def _read_hosts(path: Path) -> list[str]:
    """Read a newline-separated host list, skipping blanks and ``#`` comments."""
    hosts: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            hosts.append(line)
    return hosts


#: Per-tool fields worth surfacing as the table's one-line "detail", checked
#: in priority order via ``getattr`` (missing on other tools' record types,
#: so this is safe across every schema in ``pipeline/schemas.py``).
_DETAIL_FIELDS: tuple[str, ...] = (
    "severity",     # nuclei
    "ports_list",   # rustscan
    "rule_id",      # gitleaks
    "description",  # gitleaks
    "title",        # httpx / gowitness
    "status_code",  # httpx / gowitness
    "status",       # ffuf
    "length",       # ffuf
    "source",       # subfinder
    "protocol",     # naabu
)


def _record_note(record: ToolRecord) -> str:
    """Short human detail for the records table (severity/ports/title/etc.)."""
    for key in _DETAIL_FIELDS:
        value = getattr(record, key, None)
        if value:
            return str(value)
    return ""


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
    table = Table(title="Validated records", box=box.SIMPLE_HEAD)
    table.add_column("#", style="dim", justify="right")
    table.add_column("target", overflow="fold")
    table.add_column("kind")
    table.add_column("detail", overflow="fold")
    index = 0
    for record in records:
        ports_list = getattr(record, "ports_list", "")
        if ports_list:
            state = getattr(record, "port_state", "open")
            for port in _sorted_ports(ports_list):
                index += 1
                table.add_row(str(index), f"{record.target}:{port}", "port", state)
            continue
        index += 1
        table.add_row(str(index), record.target, record.kind, _record_note(record))
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


def _session_tag(kind: str, name: str) -> str:
    return f"{kind}-{name}-{strftime('%Y%m%d-%H%M%S')}"


def _tool_menu(manager: ToolManager) -> Table:
    """Render the registry with installation status for the launcher."""
    table = Table(title="Tool inventory", box=box.SIMPLE_HEAD)
    table.add_column("#", justify="right", style="accent")
    table.add_column("tool", style="tool")
    table.add_column("status")
    table.add_column("repository", style="muted")
    for index, name in enumerate(manager.registry.names(), start=1):
        status = "[ok]ready[/ok]" if manager.is_installed(name) else "[warn]not installed[/warn]"
        table.add_row(str(index), name, status, manager.spec(name).repo)
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
    _, manager = _bootstrap()
    try:
        tool_count = len(manager.registry.names())
    finally:
        manager.close()
    console.print(banner(tool_count))
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

    content = Table(title="TOOLS", title_style="bold white", box=box.SIMPLE_HEAD, expand=True)
    content.add_column("#", style="accent", justify="right")
    content.add_column("tool", style="bold white")
    content.add_column("status")
    content.add_column("source", style="dim")
    for index, name in enumerate(names, start=1):
        status = "[ok]ready[/ok]" if manager.is_installed(name) else "[warn]not installed[/warn]"
        content.add_row(str(index), name, status, manager.spec(name).repo)

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
    """Prompt for a target and run the tool selected by its menu number."""
    console.print(tool_guide(tool))
    if tool == "gitleaks":
        target = Prompt.ask("Local repository path")
    elif tool == "rustscan":
        target = Prompt.ask("Target host, IP or URL")
    else:
        target = Prompt.ask("Target (domain, URL or host)")
    wordlist = Prompt.ask("Wordlist path", default="") or None if tool == "ffuf" else None
    run_cmd(tool, target=target, wordlist=wordlist)


def _interactive_pipeline() -> None:
    name = Prompt.ask("Pipeline", choices=["recon-to-vuln"], default="recon-to-vuln")
    target = Prompt.ask("Seed target (domain or URL)")
    include_ffuf = Confirm.ask("Include Ffuf?", default=False)
    wordlist = None
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
) -> None:
    """Download and install precompiled tool binaries into ``tools_bin/``."""
    settings, manager = _bootstrap()
    if token:
        settings = settings.model_copy(update={"github_token": token})
        manager = ToolManager(settings, manager.registry, manager.mapping)

    targets = tools or manager.registry.names()
    console.print(f"[info]Installing {len(targets)} tool(s) into [tool]{settings.tools_dir}[/tool]...")
    ok, failed = 0, 0
    try:
        for name in targets:
            spec = manager.spec(name)
            console.print(f"[info]fetching[/info] {name} ({spec.repo}) ...")
            try:
                result = manager.install(name)
            except CyberfwError as exc:
                failed += 1
                console.print(f"[err]  ✗ {name}:[/err] {exc}")
                continue
            ok += 1
            console.print(f"[ok]  ✓ {name} v{result.version}[/ok] -> {result.binary}")
    finally:
        manager.close()

    if failed:
        console.print(f"[warn]{ok} installed, {failed} failed.[/warn]")
        raise typer.Exit(1)
    console.print(f"[ok]Done: {ok} tool(s) ready.[/ok]")


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
        console.print(banner(len(manager.registry.names())))
        console.print(
            f"[info]platform:[/info] {manager.mapping.os_name}/{manager.mapping.arch}  "
            f"[info]tools dir:[/info] {settings.tools_dir}"
        )

        tools = Table(title="Tools", box=box.SIMPLE_HEAD, expand=True)
        tools.add_column("tool", style="tool")
        tools.add_column("state")
        tools.add_column("version", style="muted")
        tools.add_column("repository", style="muted")
        for name in manager.registry.names():
            spec = manager.spec(name)
            version = (manager.install_state(name) or {}).get("version", "")
            try:
                manager.binary_path(name)  # resolves only if the binary is runnable
                state = "[ok]ready[/ok]"
            except CyberfwError:
                # Not runnable: present-but-unreadable (blocked) vs never fetched.
                if _binary_on_disk(settings.tools_dir, name, spec.binary):
                    state = "[err]blocked[/err]"
                else:
                    state = "[warn]not installed[/warn]"
            tools.add_row(name, state, version, spec.repo)
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
        bool,
        typer.Option(
            "--save",
            help="Archive this run's records to reports/<session>/. Off by default — results only print to screen.",
        ),
    ] = False,
) -> None:
    """Run a single registered tool and print its records to the screen."""
    if target is None and list_file is None:
        console.print("[err]Provide a target via --target and/or a host list via --list.[/err]")
        raise typer.Exit(2)
    if tool == "gitleaks" and target is not None:
        source = Path(target).expanduser()
        if not source.is_dir():
            console.print(
                "[err]gitleaks requires an existing local repository directory; "
                "URLs are not supported.[/err]"
            )
            raise typer.Exit(2)

    settings, manager = _bootstrap()
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
    # No reports/<session>/ directory is created unless --save is given: an
    # ad-hoc `run` should not litter the filesystem with empty session folders.
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
        with console.status(f"[tool]{tool}[/tool] running...", spinner="dots") as status:
            seen = 0

            async def _bump(record: ToolRecord) -> None:
                nonlocal seen
                seen += 1
                status.update(f"[tool]{tool}[/tool] running...  {seen} record(s)")

            engine.set_record_callback(_bump)
            try:
                node_result, records = anyio.run(_run_single, engine, ctx, tool, True)
            finally:
                manager.close()
        if records:
            console.print(_record_table(records))
        else:
            console.print("[muted]No records found.[/muted]")

    if save:
        console.print(f"[ok]saved:[/ok] {settings.reports_dir / session_id}")

    if not node_result.ok:
        console.print(f"[err]{node_result.error or 'stage failed'}[/err]")
        raise typer.Exit(1)


@app.command("pipeline")
def pipeline_cmd(
    name: Annotated[str, typer.Argument(help="Pipeline name (recon-to-vuln).")],
    target: Annotated[str | None, typer.Option("--target", "-t", help="Seed domain/URL for the first stage.")] = None,
    ffuf: Annotated[bool, typer.Option("--ffuf", help="Include the Ffuf node.")] = False,
    gowitness: Annotated[bool, typer.Option("--gowitness", help="Include the Gowitness node.")] = False,
    max_httpx: Annotated[int, typer.Option("--max-httpx", min=0, help="Cap live hosts passed onward (0 = all).")] = 0,
    wordlist: Annotated[str | None, typer.Option("--wordlist", "-w", help="Wordlist for the Ffuf stage (required with --ffuf).")] = None,
    session: Annotated[str | None, typer.Option("--session", help="Session id for the context store.")] = None,
    no_report: Annotated[bool, typer.Option("--no-report", help="Skip HTML/JSON report generation.")] = False,
    no_parse: Annotated[
        bool,
        typer.Option(
            "--no-parse",
            help="Verbose mode: stream every stage's raw stdout/stderr live "
            "(records are still parsed under the hood to thread stages).",
        ),
    ] = False,
) -> None:
    """Run a ready-made pipeline and render HTML/JSON reports."""
    if target is None:
        console.print("[err]Provide a seed target via --target.[/err]")
        raise typer.Exit(2)

    try:
        nodes = build(name, include_ffuf=ffuf, include_gowitness=gowitness, max_httpx=max_httpx)
    except RegistryError as exc:
        console.print(f"[err]{exc}[/err]")
        raise typer.Exit(2) from exc

    settings, manager = _bootstrap()
    wordlist = wordlist or settings.wordlist
    if ffuf and not wordlist:
        console.print(
            "[warn]--ffuf needs a wordlist; the fuzz stage will be skipped. "
            "Re-run with --wordlist <path> to enable it.[/warn]"
        )
    session_id = session or _session_tag("pipeline", name)
    context = SessionContext(settings.reports_dir, session_id)
    engine = PipelineEngine(settings, manager, context=context)

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
        with console.status(f"running pipeline [tool]{name}[/tool]...", spinner="dots") as status:
            seen = 0

            async def _bump(record: ToolRecord) -> None:
                nonlocal seen
                seen += 1
                status.update(f"running pipeline [tool]{name}[/tool]...  {seen} record(s)  ·  last: {record.tool}")

            engine.set_record_callback(_bump)
            try:
                result = anyio.run(run_engine, nodes, target)
            except CyberfwError as exc:
                console.print(f"[err]{exc}[/err]")
                raise typer.Exit(1) from exc
            finally:
                manager.close()

    console.print(_node_table(result))
    console.print(f"[info]session:[/info] {session_id}  [info]records:[/info] {len(result.records)}")

    if not no_report:
        try:
            json_path = generate_json_report(result, session_id=session_id, reports_dir=settings.reports_dir)
            html_path = generate_html_report(result, session_id=session_id, reports_dir=settings.reports_dir)
        except CyberfwError as exc:
            console.print(f"[err]report failed:[/err] {exc}")
            return
        console.print(f"[ok]json:[/ok] {json_path}\n[ok]html:[/ok] {html_path}")

    if not result.succeeded():
        raise typer.Exit(1)


# -- async helpers for anyio --------------------------------------------------------------------
async def _run_single(
    engine: PipelineEngine, ctx: ToolContext, tool: str, parse: bool
) -> tuple[NodeResult, list[ToolRecord]]:
    """Run one tool stage through the engine (handles fan-out and crashes)."""
    return await engine._run_node(
        Node(tool=tool, stage=tool),
        ctx.target,
        ctx.inputs,
        parse=parse,
        extra_input=ctx.extra_input,
    )


if __name__ == "__main__":
    app()
