"""`prepare`, `init`, `lock`, `doctor` / `status` — installing, pinning and checking the tools."""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Protocol

import typer
from rich.console import Group, RenderableType
from rich.live import Live
from rich.markup import escape
from rich.text import Text

from cyberfw import motion
from cyberfw.cli.app import app
from cyberfw.cli.common import VerboseOption, _after_live, _bootstrap, _live_fps
from cyberfw.cli.views import _status_view, _tool_rows
from cyberfw.config import Settings
from cyberfw.core.workspace import is_packaged
from cyberfw.exceptions import (
    ChromiumUnsupportedError,
    CyberfwError,
    LockError,
)
from cyberfw.hud import (
    HudFrame,
    Pane,
    hud_table,
)
from cyberfw.logging import console
from cyberfw.manager import ToolManager
from cyberfw.manager.lock import LOCK_NAME, LockChange
from cyberfw.ui import (
    PIP,
    Masthead,
)


@app.command("prepare", hidden=True)
def prepare_cmd() -> None:
    """Install every missing tool, then exit.

    The launchers (cstool.bat / start.sh) run this in the install window, so the
    interface then opens in a clean terminal with nothing left to download.
    """
    _ensure_tools()


def _ensure_tools() -> None:
    """Install every missing tool automatically before showing the launcher."""
    settings, manager = _bootstrap()
    lock_existed = manager.lock_path.exists()
    try:
        missing = [
            name
            for name in manager.registry.names()
            if not manager.is_installed(name) and not manager.spec(name).is_local
        ]
        if not missing:
            return
        console.print(f"[info]Preparing {len(missing)} tool(s) automatically...[/info]")
        for name in missing:
            console.print(f"[info]fetching[/info] {name} ({manager.spec(name).repo}) ...")
            try:
                with motion.Activity(console, f"Fetching {name}", animate=settings.animations,
                                     detail=manager.spec(name).repo):
                    result = manager.install(name)
            except CyberfwError as exc:
                console.print(f"[err]  failed {name}:[/err] {exc}")
            else:
                console.print(f"[ok]  ready {name} v{result.version}[/ok]")
        _report_lock_additions(manager, existed=lock_existed)
    finally:
        manager.close()


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
    """Download, verify and install precompiled tool binaries into ``tools_bin/``.

    Installs exactly the releases ``tools.lock`` pins and checks every archive's
    SHA-256 against it; a tool missing from the lock is added to it first. A tool
    already installed from its locked archive is left alone unless ``--force``.
    Newer releases come only through ``cyberfw lock --upgrade``.

    When gowitness is installed and no Chrome/Chromium is on the machine, a
    portable Chromium (Chrome for Testing) is downloaded too, so the screenshot
    stage works without a system browser. Skip it with ``--no-chromium``.

    ``-v/--verbose`` traces each release resolution, download and extraction.
    """
    settings, manager = _bootstrap(verbose=verbose)
    if token:
        settings = settings.model_copy(update={"github_token": token})
        manager = ToolManager(settings, manager.registry, manager.mapping, lock_path=manager.lock_path)

    requested = tools or manager.registry.names()
    # A local tool (source: local) is the user's to install — never downloaded.
    for name in [n for n in requested if manager.spec(n).is_local]:
        console.print(
            f"[muted]{name} is a local tool — install it with your package manager "
            "(apt/brew/winget); skipping.[/muted]"
        )
    targets = [n for n in requested if not manager.spec(n).is_local]
    lock_existed = manager.lock_path.exists()
    locked_tags = _locked_tags(manager)
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
                wanted = locked_tags.get(name, "not locked yet")
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

    _report_lock_additions(manager, existed=lock_existed)
    if failed:
        console.print(f"[warn]{ok} ready, {failed} failed.[/warn]")
        raise typer.Exit(1)
    console.print(f"[ok]Done: {ok} tool(s) ready.[/ok]")


def _locked_tags(manager: ToolManager) -> dict[str, str]:
    """The tag each tool is locked to, for progress lines. Empty when the lock
    cannot be read — installing then reports that error per tool."""
    try:
        return {name: tool.tag for name, tool in manager.load_lock().tools.items()}
    except LockError:
        return {}


def _report_lock_additions(manager: ToolManager, *, existed: bool) -> None:
    """Say which tools this run pinned into ``tools.lock`` — and, in a workspace,
    that the file wants committing so every machine installs the same tools."""
    added = manager.added_to_lock
    if not added:
        return
    names = ", ".join(added)
    name = manager.lock_path.name
    what = f"Added {names} to {name}" if existed else f"Created {name} with {names}"
    hint = "" if is_packaged(manager.lock_path) else " — commit it so every machine installs the same, verified tools."
    console.print(f"[info]{escape(what)}[/info]{hint}")


#: How each ``cyberfw lock`` outcome is coloured.
_LOCK_CHANGE_STYLES = {
    "added": "ok",
    "upgraded": "ok",
    "updated": "info",
    "re-resolved": "warn",
    "removed": "muted",
    "unchanged": "muted",
    "failed": "err",
}


def _lock_table(changes: list[LockChange]) -> HudFrame:
    """``cyberfw lock``'s report: a row per tool, before → now, and where its hashes came from."""
    table = hud_table()
    table.add_column("tool", style="tool", no_wrap=True)
    table.add_column("before", style="muted", no_wrap=True)
    table.add_column("now", no_wrap=True)
    table.add_column("change", no_wrap=True)
    table.add_column("hashes", style="muted", overflow="fold", ratio=1)
    for change in changes:
        table.add_row(
            change.tool,
            change.before or "—",
            change.after or "—",
            Text(change.change, style=_LOCK_CHANGE_STYLES[change.change]),
            Text(change.error, style="err") if change.error else change.sources,
        )
    return HudFrame([Pane(table, title=LOCK_NAME, pad=0)])


@app.command("lock")
def lock_cmd(
    tools: Annotated[
        list[str] | None, typer.Argument(help="Tool names to lock; omit for every downloadable tool.")
    ] = None,
    upgrade: Annotated[
        bool, typer.Option("--upgrade", help="Also move tools to the newest release registry.yaml allows.")
    ] = False,
    token: Annotated[str | None, typer.Option("--token", envvar="CYBERFW_GITHUB_TOKEN",
                                             help="GitHub token to raise the rate limit.")] = None,
    verbose: VerboseOption = False,
) -> None:
    """Pin tools to exact releases and record each platform's SHA-256 in ``tools.lock``.

    Only what the registry no longer matches changes: missing tools are added,
    stale entries (a changed ``repo`` / ``version:``) re-resolved and removed
    tools dropped. ``--upgrade`` also moves tools to their newest allowed
    release; a release whose files changed under the same tag is refused.
    ``cyberfw init`` installs exactly what the lock pins — commit it.
    """
    settings, manager = _bootstrap(verbose=verbose)
    if token:
        settings = settings.model_copy(update={"github_token": token})
        manager = ToolManager(settings, manager.registry, manager.mapping, lock_path=manager.lock_path)
    for name in tools or []:
        if name not in manager.registry:
            console.print(f"[err]Unknown tool {name!r}.[/err] Known: {', '.join(manager.registry.names())}")
            manager.close()
            raise typer.Exit(2)
        if manager.spec(name).is_local:
            console.print(f"[muted]{name} is a local tool — nothing to lock; skipping.[/muted]")
    console.print(Text.assemble(("Locking tools into ", "info"), (str(manager.lock_path), "tool")))
    try:
        update = manager.update_lock(tools or None, upgrade=upgrade)
    except CyberfwError as exc:
        console.print(f"[err]{exc}[/err]")
        raise typer.Exit(1) from exc
    finally:
        manager.close()
    if update.changes:
        console.print(_lock_table(update.changes))
    if update.error:
        console.print(f"[err]{escape(update.error)}[/err]")
    elif update.written:
        hint = "" if is_packaged(update.path) else " — commit it so every machine installs the same, verified tools."
        console.print(f"[ok]Wrote {update.path.name}[/ok]{hint}")
    elif not update.changes and not update.path.exists():
        console.print("[muted]Nothing to lock: registry.yaml lists no downloadable tools.[/muted]")
    else:
        console.print(f"[muted]{update.path.name} unchanged.[/muted]")
    if update.failed:
        raise typer.Exit(1)


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
