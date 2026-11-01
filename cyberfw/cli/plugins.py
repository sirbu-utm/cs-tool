"""`plugins` — the plugin packages installed next to cyberfw: list them, enable or disable one."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Group
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from cyberfw.cli.app import app
from cyberfw.config import load_settings
from cyberfw.core.plugins import disable_plugin, enable_plugin
from cyberfw.exceptions import PluginError
from cyberfw.logging import console
from cyberfw.manager.plugins import PluginInfo, load_plugins, read_plugins_file

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
    extra variables it is given (``env:``), its state and why. Exit 2 when
    plugins.yaml cannot be read — the list would only say every package is disabled."""
    if ctx.invoked_subcommand is not None:
        return
    settings = load_settings()
    try:
        read_plugins_file(settings.plugins_file)
    except PluginError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(2) from exc
    infos = load_plugins(settings).infos
    if not infos:
        console.print(f"[muted]{escape(_HOW_TO_ADD)}[/muted]")
        return
    console.print(_listing(infos, package=True))


@plugins_app.command("enable")
def enable_cmd(
    package: Annotated[str, typer.Argument(help="The installed package to enable, e.g. cyberfw-foo.")],
    allow_code: Annotated[bool, typer.Option(
        "--allow-code", help="Let a code package's Python run inside cyberfw, with access to all it can reach.",
    )] = False,
) -> None:
    """Enable a plugin package: write it to plugins.yaml and load it at once.

    Exit 0 when every tool of it loads (or it was enabled already); 1 when one is
    broken, incompatible or in conflict — it stays enabled, so a fixed release
    needs nothing more; 2 when no installed package by that name declares cyberfw
    tools, a code package is enabled without --allow-code, or plugins.yaml cannot
    be read or written.
    """
    try:
        result = enable_plugin(load_settings(), package, allow_code=allow_code)
    except PluginError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(2) from exc
    name = escape(result.package)
    console.print(f"{name}: already enabled" if result.already else f"Enabled {name}.")
    console.print(_listing(result.tools, package=False))
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


def _listing(infos: list[PluginInfo], *, package: bool) -> Group:
    """Plugin tools one per row — with their package and version when ``package`` — and,
    under the table, each tool's ``env:`` and why it does not work, if it does not: a
    line of its own, so it wraps at its words and its command can be copied whole on
    a narrow terminal. The names and states in the table never shrink."""
    headers = [*(["package", "version"] if package else []), "kind", "tool", "state"]
    rows = [
        [*([info.package, info.version or "—"] if package else []), info.kind or "—", info.tool or "—", info.state]
        for info in infos
    ]
    table = Table.grid(padding=(0, 2))
    for index, header in enumerate(headers):
        table.add_column(no_wrap=True, min_width=max(len(header), *(len(row[index]) for row in rows)))
    table.add_row(*(f"[muted]{header}[/muted]" for header in headers))
    details: list[Text] = []
    for info, row in zip(infos, rows, strict=True):
        style = _STATE_STYLES.get(info.state, "warn")
        table.add_row(*(escape(cell) for cell in row[:-1]), f"[{style}]{info.state}[/{style}]")
        said = [*([(f"env {', '.join(info.env)}", "info")] if info.env else []),
                *([(info.reason, "muted")] if info.reason else [])]
        if said:
            parts: list[tuple[str, str]] = [(f"{info.tool or info.package}: ", "tool")]
            for index, part in enumerate(said):
                parts += [(" — ", "muted"), part] if index else [part]
            details.append(Text.assemble(*parts))
    return Group(table, *([Text(""), *details] if details else []))
