"""The interactive launcher: menu, help card, prompts and the no-argument entry point."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import typer
from rich.console import Console, ConsoleOptions, Group, RenderableType, RenderResult
from rich.table import Table
from rich.text import Text

from cyberfw import completion, motion
from cyberfw.cli.app import app
from cyberfw.cli.common import (
    Confirm,
    Prompt,
    _bootstrap,
    _clear_screen,
    _fresh_screen,
    _is_interactive,
    _tool_state,
    _tool_version,
)
from cyberfw.cli.scan import pipeline_cmd, run_cmd
from cyberfw.cli.tools import _ensure_tools
from cyberfw.cli.views import _tool_rows, _ToolRow, _tools_table
from cyberfw.config import Settings, load_settings
from cyberfw.exceptions import (
    RegistryError,
)
from cyberfw.hud import (
    KEY,
    HudFrame,
    Pane,
    join,
    keycap,
)
from cyberfw.logging import console, ensure_utf8_stdio
from cyberfw.manager import ToolManager
from cyberfw.pipelines import PIPELINES, available_pipelines, build
from cyberfw.tools import adapter_class
from cyberfw.ui import (
    TOOL_GUIDES,
    Masthead,
    banner,
    pip_word,
    tool_guide,
)


@app.callback(invoke_without_command=True)
def app_callback(ctx: typer.Context) -> None:
    """Open the interactive launcher when no subcommand was supplied."""
    ensure_utf8_stdio()
    if ctx.invoked_subcommand is None:
        interactive_menu()


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
    # Whatever installing / checking printed is done with: the interface starts
    # on a clean, titled screen.
    _fresh_screen()
    settings, manager = _bootstrap()
    try:
        # One inventory pass serves the banner and the first launcher frame;
        # later frames recompute, since a tool can change state mid-session.
        _start_screen(_tool_rows(manager, settings.tools_dir), manager.mapping.label, settings)
    finally:
        manager.close()
    first = True
    review = False  # the last action printed output the user should read first
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
                if not _back_to_launcher(review):
                    _goodbye(settings)
                    return
                _show_launcher(manager, settings)
        finally:
            manager.close()
        first = False
        review = False
        try:
            choice = _prompt_choice(names)
        except (KeyboardInterrupt, EOFError):
            # Ctrl+C / Ctrl+D at the menu is a normal way out, not a failure: exit
            # 0, so a Windows Terminal window opened for the interface closes.
            _goodbye(settings)
            return
        if choice in _SETTINGS_KEYS:
            _toggle_setting(choice, settings)
            continue  # reprint the panel with the new setting
        if choice == _HELP_KEY:
            _show_help(names)
            review = True  # the cheatsheet stays until Enter, then the launcher redraws
            continue
        try:
            if not _dispatch_choice(choice, names):
                _goodbye(settings, newline=False)
                return
        except typer.Exit:
            console.print("[warn]The operation failed. Returning to the launcher.[/warn]")
        except (KeyboardInterrupt, EOFError):
            _goodbye(settings)
            return
        review = True


def _show_launcher(manager: ToolManager, settings: Settings) -> None:
    """The launcher frame, played in each time the menu comes back — rows type
    in, then the keys and settings — the same entrance as the start screen."""
    rows = _tool_rows(manager, settings.tools_dir)
    motion.play(
        console, lambda progress: _LauncherView(rows, settings, progress=progress),
        duration=0.45, animate=settings.animations,
    )


def _goodbye(settings: Settings, *, newline: bool = True) -> None:
    """Sign off: "Goodbye." resolves out of noise; a pipe just gets the word."""
    if newline:  # after ^C the cursor sits at the end of the prompt line
        console.print()
    motion.play(
        console, lambda progress: motion.decode("Goodbye.", progress, style="muted"),
        duration=0.55, animate=settings.animations,
    )


def _back_to_launcher(review: bool) -> bool:
    """Make room for the next launcher frame on a clean screen.

    After an action (a scan, a tool run) the user first reads its output and
    presses Enter; a settings toggle redraws straight away. Returns False when
    they leave at that prompt (Ctrl+C / Ctrl+D). Non-interactive: no-op, so the
    transcript keeps scrolling as before.
    """
    if not _is_interactive():
        return True
    if review:
        try:
            console.input("\n[muted]Enter — back to the launcher[/muted] ")
        except (KeyboardInterrupt, EOFError):
            return False
    _clear_screen()
    return True


#: Launcher hotkeys that are not tool numbers. Tools are ``1``..``len(names)``,
#: so the pipeline and exit actions get letters rather than a number that a
#: ninth registry entry would collide with.
_PIPELINE_KEY = "r"
_HELP_KEY = "?"
_EXIT_KEYS = frozenset({"0", "q"})
_SETTINGS_KEYS = frozenset({"p", "l", "f", "a"})


def _tool_range(names: list[str]) -> str:
    """``1-8`` for eight tools, ``1`` for a single one."""
    return "1" if len(names) == 1 else f"1-{len(names)}"


#: The launcher's actions by name, as Tab completes them; each answers like
#: its key: ``word: (key, hint shown beside it in the list)``.
_ACTION_WORDS: dict[str, tuple[str, str]] = {
    "pipeline": (_PIPELINE_KEY, "run a pipeline"),
    "help": (_HELP_KEY, "this cheatsheet"),
    "parse": ("p", "parsing on/off"),
    "log-level": ("l", "next log level"),
    "log-file": ("f", "log file on/off"),
    "animations": ("a", "animations on/off"),
    "exit": ("q", "leave"),
}


def _menu_options(names: list[str]) -> list[completion.Option]:
    """What Tab offers at the launcher: every tool by name, then the actions,
    each with the key that does the same beside it."""
    tools = []
    for index, name in enumerate(names, start=1):
        capability = TOOL_GUIDES.get(name, ("",))[0]
        tools.append(completion.Option(name, f"{index} · {capability}" if capability else str(index)))
    actions = [completion.Option(word, f"{key} · {hint}") for word, (key, hint) in _ACTION_WORDS.items()]
    return tools + actions


def _prompt_choice(names: list[str]) -> str:
    """Prompt for a menu choice, with an on-brand hint on invalid input.

    Returns a normalised token: a tool number, the pipeline key, an exit key
    or a settings hotkey (``p``/``l``/``f``/``a``). A name, a tool's or one of
    :data:`_ACTION_WORDS` (what Tab completes), answers like its key. Anything
    else re-prompts with a plain explanation instead of Rich's generic "not a
    valid integer" loop.
    """
    valid = (
        {str(index) for index in range(1, len(names) + 1)}
        | {_PIPELINE_KEY, _HELP_KEY}
        | _EXIT_KEYS
        | _SETTINGS_KEYS
    )
    by_name = {name.lower(): str(index) for index, name in enumerate(names, start=1)}
    by_name.update((word, key) for word, (key, _hint) in _ACTION_WORDS.items())
    options = _menu_options(names)
    while True:
        with completion.offering(options):
            raw = Prompt.ask("Select tool or action").strip().lower()
        if raw in valid:
            return raw
        if raw in by_name:
            return by_name[raw]
        console.print(
            f"[warn]Type {_tool_range(names)} or a tool's name, {_PIPELINE_KEY} pipeline, ? help, 0 exit, "
            "or p/l/f/a to change settings. Tab lists them all.[/warn]"
        )


def _help_card(names: list[str]) -> HudFrame:
    """The cheatsheet behind ``?``: the menu keys, what each setting changes, and
    the command-line calls the menu never shows. ``names`` only sizes the tool
    range (``1-8``)."""
    keys = Table.grid(padding=(0, 2))
    keys.add_column(no_wrap=True)
    keys.add_column(overflow="fold")
    for cap, what in (
        (Text(f" {_tool_range(names)} ", style=KEY), "select a tool by its number"),
        (Text(f" {_PIPELINE_KEY} ", style=KEY), "run a pipeline"),
        (Text(" Tab ", style=KEY), "list the choices or complete a name"),
        (Text(f" {_HELP_KEY} ", style=KEY), "this cheatsheet"),
        (Text.assemble((" 0 ", KEY), " ", (" q ", KEY)), "exit"),
    ):
        keys.add_row(cap, Text(what, style="white"))

    settings = Table.grid(padding=(0, 2))
    settings.add_column(no_wrap=True)
    settings.add_column(no_wrap=True)
    settings.add_column(overflow="fold")
    for key, name, what in (
        ("p", "parse", "validate records by schema, or show raw stdout/stderr"),
        ("l", "log level", "DEBUG → INFO → WARNING → ERROR"),
        ("f", "log file", "write logs/cyberfw.log on or off"),
        ("a", "animations", "console motion on or off"),
    ):
        settings.add_row(Text(f" {key} ", style=KEY), Text(name, style="accent"), Text(what, style="white"))

    commands = Table.grid(padding=(0, 2))
    commands.add_column(no_wrap=True, style="bold bright_cyan")
    commands.add_column(overflow="fold")
    for call, what in (
        ("cstool status", "what is installed and ready to run"),
        ("cstool run <tool> -t <target>", "run a single tool"),
        ("cstool pipeline recon-to-vuln -t example.com", "full chain; --ffuf / --gowitness add stages"),
        ("cstool diff <old> <new>", "what changed between two saved runs"),
        ("cstool vt example.com", "VirusTotal reputation of a domain, IP, URL or file hash"),
        ('cstool mute <id> --target "*.dev"', "silence a finding in future scans"),
    ):
        commands.add_row(Text(call), Text(what, style="muted"))

    return HudFrame(
        [
            Pane(keys, title="Keys"),
            Pane(settings, title="Settings"),
            Pane(commands, title="Command line"),
        ]
    )


def _show_help(names: list[str]) -> None:
    """Print the cheatsheet to the launcher's console (the ``?`` key)."""
    console.print(_help_card(names))


def _dispatch_choice(choice: str, names: list[str]) -> bool:
    """Run the action behind a validated launcher choice; False means "exit"
    (the caller signs off)."""
    if choice in _EXIT_KEYS:
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
        wide = options.max_width >= 100
        key_items = [
            keycap(_tool_range(names), "select tool"),
            keycap(_PIPELINE_KEY, "run pipeline"),
            Text.assemble((" 0 ", KEY), " ", (" q ", KEY), " ", ("exit", "muted")),
            keycap("Tab", "list"),
        ]
        if wide:  # `? help` rides along only where there is room, like the capability column
            key_items.append(keycap(_HELP_KEY, "help"))
        keys = join(key_items)
        toggles = self._toggles(compact=False)
        if toggles.cell_len > options.max_width - 4:
            toggles = self._toggles(compact=True)
        progress = self.progress
        table = _tools_table(
            self.rows, numbered=True, capability=wide, reveal=motion.phase(progress, 0.0, 0.7)
        )
        yield HudFrame(
            [
                Pane(table, title="Tools", pad=0),
                Pane(keys if progress >= 0.8 else Text(""), title="Keys"),
                Pane(toggles if progress >= 0.9 else Text(""), title="Settings"),
            ],
            footer=Text("type a key or a name, then Enter", style="muted") if progress >= 1 else None,
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


def _pipeline_options(names: list[str], pipelines_dir: Path | None) -> list[completion.Option]:
    """The pipelines as Tab offers them, each with its stages beside it:
    ``subfinder → httpx → nuclei``. A file that does not load is listed all
    the same; picking it reports why, as before."""
    options = []
    for name in names:
        try:
            hint = " → ".join(node.tool for node in build(name, pipelines_dir=pipelines_dir))
        except RegistryError:
            hint = "invalid pipeline file"
        options.append(completion.Option(name, hint))
    return options


def _interactive_pipeline() -> None:
    pipelines_dir = load_settings().pipelines_dir
    choices = available_pipelines(pipelines_dir)
    with completion.offering(_pipeline_options(choices, pipelines_dir)):
        name = Prompt.ask("Pipeline", choices=choices, default=choices[0])
    target = Prompt.ask("Seed target (domain or URL)")
    include_ffuf = False
    gowitness: bool | None = None
    wordlist = None
    if name in PIPELINES:  # the optional stages are recon-to-vuln's; YAML pipelines have none
        include_ffuf = Confirm.ask("Include Ffuf?", default=False)
        if include_ffuf:
            wordlist = Prompt.ask("Ffuf wordlist path", default="") or None
        # Default yes, but graceful: accepting keeps the sensible default (run it
        # where it can), None, rather than forcing it even without a browser.
        gowitness = None if Confirm.ask("Include Gowitness?", default=True) else False
    pipeline_cmd(
        name,
        target=target,
        ffuf=include_ffuf,
        gowitness=gowitness,
        wordlist=wordlist,
    )
