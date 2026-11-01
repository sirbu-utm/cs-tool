"""`plugins` — the plugin packages installed next to cyberfw: list them, enable or disable one."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.markup import escape
from rich.table import Table

from cyberfw.cli.app import app
from cyberfw.config import load_settings
from cyberfw.core.plugins import disable_plugin, enable_plugin
from cyberfw.exceptions import PluginError
from cyberfw.logging import console
from cyberfw.manager.plugins import PluginInfo, load_plugins

plugins_app = typer.Typer(
    help="List the plugin packages installed next to cyberfw; enable or disable one.",
    rich_markup_mode="rich",
)
app.add_typer(plugins_app, name="plugins")

#: A state's colour: what works, what waits for the user; anything else is a problem.
_STATE_STYLES = {"enabled": "ok", "disabled": "muted"}

_HOW_TO_ADD = (
    "No plugin packages are installed. Add one next to cyberfw — "
    "`uv tool install cyberfw --with cyberfw-foo`, or `pip install cyberfw-foo` in cyberfw's "
    "environment — then `cyberfw plugins enable cyberfw-foo`."
)


@plugins_app.callback(invoke_without_command=True)
def plugins_cmd(ctx: typer.Context) -> None:
    """List the plugin packages installed next to cyberfw: each tool, its kind, the
    extra variables it is given (``env:``), its state and why."""
    if ctx.invoked_subcommand is not None:
        return
    infos = load_plugins(load_settings()).infos
    if not infos:
        console.print(f"[muted]{escape(_HOW_TO_ADD)}[/muted]")
        return
    console.print(_table(infos, package=True))


@plugins_app.command("enable")
def enable_cmd(
    package: Annotated[str, typer.Argument(help="The installed package to enable, e.g. cyberfw-foo.")],
    allow_code: Annotated[bool, typer.Option(
        "--allow-code", help="Let a code package's Python run inside cyberfw, with access to all it can reach.",
    )] = False,
) -> None:
    """Enable a plugin package: write it to plugins.yaml and load it at once.

    Exit 0 when every tool of it loads (or it was enabled already); 1 when one is
    broken, incompatible or in conflict — it stays enabled, so a fixed release needs
    nothing more; 2 when no installed package by that name declares cyberfw tools,
    or a code package is enabled without --allow-code.
    """
    try:
        result = enable_plugin(load_settings(), package, allow_code=allow_code)
    except PluginError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(2) from exc
    console.print(f"{result.package}: already enabled" if result.already else f"Enabled {result.package}.")
    console.print(_table(result.tools, package=False))
    if not (result.already or result.working):
        raise typer.Exit(1)


@plugins_app.command("disable")
def disable_cmd(
    package: Annotated[str, typer.Argument(help="The package to disable, installed or not.")],
) -> None:
    """Disable a plugin package: take it off plugins.yaml, installed or not."""
    try:
        disabled = disable_plugin(load_settings(), package)
    except PluginError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(2) from exc
    console.print(f"Disabled {escape(package)}." if disabled else f"{escape(package)} was not enabled.")


def _table(infos: list[PluginInfo], *, package: bool) -> Table:
    """Plugin tools one per row — with their package and version when ``package``. The
    names stay whole on a narrow terminal; only the reason wraps."""
    headers = [*(["package", "version"] if package else []), "kind", "tool", "env", "state", "reason"]
    table = Table.grid(padding=(0, 2))
    for header in headers:
        table.add_column(no_wrap=header != "reason", overflow="fold" if header == "reason" else "ellipsis")
    table.add_row(*(f"[muted]{header}[/muted]" for header in headers))
    for info in infos:
        style = _STATE_STYLES.get(info.state, "warn")
        cells = [escape(info.package), escape(info.version) or "—"] if package else []
        cells += [
            info.kind or "—",
            escape(info.tool) or "—",
            escape(", ".join(info.env)) or "—",
            f"[{style}]{info.state}[/{style}]",
            f"[muted]{escape(info.reason)}[/muted]",
        ]
        table.add_row(*cells)
    return table
