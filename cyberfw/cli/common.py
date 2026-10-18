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
from cyberfw.exceptions import (
    CyberfwError,
    RegistryError,
)
from cyberfw.logging import console, get_logger, setup_logging
from cyberfw.manager import ToolManager, load_registry
from cyberfw.manager.lock import LOCK_NAME
from cyberfw.resources import packaged_data

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
    registry_path = _registry_path()
    manager = ToolManager(settings, load_registry(registry_path), lock_path=registry_path.with_name(LOCK_NAME))
    return settings, manager


def _registry_candidates() -> list[Path]:
    """Where ``registry.yaml`` may live, most specific first.

    The current directory (a workspace the user may have edited), then the
    checkout root next to the package (running from a clone elsewhere), then
    the copy the wheel ships as ``cyberfw/data/registry.yaml``.
    """
    candidates = [Path.cwd() / "registry.yaml", Path(__file__).resolve().parents[2] / "registry.yaml"]
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


def _is_packaged(path: Path) -> bool:
    """True for a file next to the wheel's packaged registry: an installed copy
    in site-packages, with no repository to commit it to."""
    packaged = packaged_data("registry.yaml")
    return packaged is not None and path.resolve().parent == packaged.resolve().parent


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
