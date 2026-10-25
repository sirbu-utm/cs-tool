"""Plumbing the commands share: bootstrap, registry and lock paths, prompts, terminal and screen helpers."""

from __future__ import annotations

from pathlib import Path
from time import strftime
from typing import Annotated, Any, TextIO

import typer
from rich.console import Console
from rich.prompt import Confirm as _RichConfirm
from rich.prompt import Prompt as _RichPrompt
from rich.text import Text, TextType

from cyberfw import completion
from cyberfw.config import Settings, load_settings
from cyberfw.core.workspace import open_manager, tool_state
from cyberfw.logging import console, get_logger, setup_logging
from cyberfw.manager import ToolManager

LOG = get_logger("cli")


class Prompt(_RichPrompt):
    """Every question asked the same way: ``» Target (domain, URL or host):``.

    Callers still pass the plain wording (it comes from the adapters), so a
    test that patches ``cyberfw.cli.Prompt.ask`` sees exactly that wording.
    Questions go to the app's console unless told otherwise: Rich's global
    console has no theme, and the lead-in's style would quietly drop.
    A question asked inside :func:`completion.offering` reads its answer with
    Tab completion when a person is at the terminal.
    """

    def __init__(self, prompt: TextType = "", *, console: Console | None = None, **kwargs: Any) -> None:
        super().__init__(prompt, console=console or _app_console(), **kwargs)

    def make_prompt(self, default: Any) -> Text:
        return Text.assemble(("» ", "accent"), super().make_prompt(default))

    @classmethod
    def get_input(cls, console: Console, prompt: TextType, password: bool, stream: TextIO | None = None) -> str:
        options = completion.offered()
        if options and not password and stream is None and completion.available(console):
            return completion.read_line(console, prompt, options)
        return super().get_input(console, prompt, password, stream=stream)


class Confirm(_RichConfirm):
    """A yes/no question with the same ``» `` lead-in as :class:`Prompt`."""

    def __init__(self, prompt: TextType = "", *, console: Console | None = None, **kwargs: Any) -> None:
        super().__init__(prompt, console=console or _app_console(), **kwargs)

    def make_prompt(self, default: Any) -> Text:
        return Text.assemble(("» ", "accent"), super().make_prompt(default))


def _app_console() -> Console:
    """The themed console, looked up at call time (tests swap it)."""
    return console


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
    return settings, open_manager(settings)


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


def _tool_version(manager: ToolManager, name: str) -> str:
    return str((manager.install_state(name) or {}).get("version", ""))


def _tool_states(manager: ToolManager, tools_dir: Path) -> list[str]:
    """One state per registered tool, in registry order."""
    return [tool_state(manager, name, tools_dir) for name in manager.registry.names()]


def _clear_screen() -> None:
    """Clear the screen *and* the scrollback, so nothing is left to scroll back to.

    ``console.clear()`` erases only the visible screen (CSI 2J) and homes the
    cursor; the frame that was there stays in the terminal's scrollback. CSI 3J
    erases that too, so the launcher reopens on a truly blank screen. It is sent
    only to a real terminal — the same gate Rich's own ``clear`` uses — so a
    dumb terminal gets neither code; a pipe/CI never reaches here (callers guard
    on :func:`_is_interactive`)."""
    console.clear()
    if console.is_terminal and not console.is_dumb_terminal:
        console.file.write("\x1b[3J")
        console.file.flush()


def _fresh_screen() -> None:
    """Title the window and clear it — only for a person at a terminal; a pipe,
    a log or a test keeps its plain transcript."""
    if not _is_interactive():
        return
    console.set_window_title("CS-TOOL")
    _clear_screen()
