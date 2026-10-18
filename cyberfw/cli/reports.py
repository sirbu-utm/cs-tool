"""`vt`, `diff`, `export` — looking a target up and working with saved runs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import anyio
import httpx
import typer
from rich.markup import escape

from cyberfw import motion, vt
from cyberfw.cli.app import app
from cyberfw.cli.common import _is_interactive
from cyberfw.cli.views import _print_changes, _print_reputation
from cyberfw.config import load_settings
from cyberfw.logging import console
from cyberfw.report import diff as rundiff
from cyberfw.report.csv_report import to_csv
from cyberfw.report.sarif import to_sarif


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
        with motion.Activity(console, f"VirusTotal {target}", animate=settings.animations and not json_out):
            rep = anyio.run(_vt_lookup, key, target)
    except vt.VtError as exc:
        console.print(f"[err]VirusTotal: {exc}[/err]")
        raise typer.Exit(1) from exc
    if json_out:
        print(json.dumps(rep.as_record()))
    else:
        _print_reputation(rep)


@app.command("diff")
def diff_cmd(
    old: Annotated[str, typer.Argument(help="The earlier run: a session id, its directory or its report.json.")],
    new: Annotated[str, typer.Argument(help="The later run, given the same way.")],
    json_out: Annotated[bool, typer.Option("--json", help="Print the changes as JSON.")] = False,
) -> None:
    """Show what changed between two saved runs.

    New or gone findings, opened or closed ports, new subdomains, renewed
    certificates, CVEs that have since become exploited in the wild.
    """
    settings = load_settings()
    try:
        before = rundiff.load_report(rundiff.resolve_report(old, settings.reports_dir))
        after = rundiff.load_report(rundiff.resolve_report(new, settings.reports_dir))
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(2) from exc
    changes = rundiff.compare(before, after)
    if json_out:
        print(json.dumps(changes.as_dict(), ensure_ascii=False, indent=2))
        return
    _print_changes(changes, limit=None)


@app.command("export")
def export_cmd(
    run: Annotated[
        str, typer.Argument(help="A saved run: a session id, its directory, or a path to report.json.")
    ],
    sarif: Annotated[
        bool, typer.Option("--sarif", help="Export the findings as SARIF 2.1.0 (for CI / code scanning).")
    ] = False,
    csv_out: Annotated[
        bool, typer.Option("--csv", help="Export every record as CSV (for triage in a spreadsheet).")
    ] = False,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write to this file instead of stdout.")
    ] = None,
) -> None:
    """Convert a saved run to SARIF (findings) or CSV (every record).

    Reads the run's ``report.json`` (from `pipeline` / `run --save`), so any
    past run re-exports without re-scanning. By default the document is written
    to stdout; ``-o`` writes a file.
    """
    if sarif == csv_out:  # neither, or both
        console.print("[err]Choose exactly one format: --sarif or --csv.[/err]")
        raise typer.Exit(2)
    settings = load_settings()
    try:
        payload = rundiff.load_report(rundiff.resolve_report(run, settings.reports_dir))
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(2) from exc

    document = json.dumps(to_sarif(payload), ensure_ascii=False, indent=2) if sarif else to_csv(payload)
    if output is None:
        print(document)  # the whole of stdout is the document — nothing themed
        return
    try:
        output.write_text(document if document.endswith("\n") else document + "\n", encoding="utf-8")
    except OSError as exc:
        console.print(f"[err]cannot write {output}: {escape(str(exc))}[/err]")
        raise typer.Exit(1) from exc
    console.print(f"[ok]Wrote[/ok] {output}")


async def _vt_lookup(key: str, target: str) -> vt.Reputation:
    async with httpx.AsyncClient(timeout=30.0) as client:
        return await vt.lookup(client, key, target)
