"""`mute`, `unmute`, `mutes` — silencing accepted findings on future scans."""

from __future__ import annotations

from datetime import date
from typing import Annotated

import typer
from rich.markup import escape
from rich.table import Table

from cyberfw import triage
from cyberfw.cli.app import app
from cyberfw.config import load_settings
from cyberfw.logging import console


@app.command("mute")
def mute_cmd(
    template: Annotated[str, typer.Argument(
        help="Check / template id to silence (e.g. tls-cert-self-signed, CVE-2021-1234), or * for any.")],
    target: Annotated[str | None, typer.Option("--target", "-t",
        help="Limit to a host or URL (fnmatch, e.g. dev.example.com or *.staging.example.com).")] = None,
    reason: Annotated[str, typer.Option("--reason", "-r",
        help="Why: false_positive | accepted_risk | wont_fix | other.")] = "other",
    note: Annotated[str | None, typer.Option("--note", "-n", help="Free-text note kept with the mute.")] = None,
    expires: Annotated[str | None, typer.Option("--expires",
        help="Date (YYYY-MM-DD) after which the mute lapses — good practice for accepted risk.")] = None,
) -> None:
    """Silence a finding on future scans (triage).

    It then shows in a muted block rather than as an active finding, and is not
    counted as new when runs are compared.
    """
    settings = load_settings()
    if reason not in triage.REASONS:
        console.print(f"[err]Unknown reason {reason!r}. Use one of: {', '.join(sorted(triage.REASONS))}.[/err]")
        raise typer.Exit(2)
    if expires and not _is_iso_date(expires):
        console.print("[err]--expires must be a date like 2027-01-31.[/err]")
        raise typer.Exit(2)
    try:
        rules = triage.load_rules(settings.triage_file)
        rule = triage.Rule(
            id=triage.new_rule_id(rules), template=template.strip(), target=(target or "").strip(),
            reason=reason, note=(note or "").strip(), added=date.today().isoformat(), expires=(expires or "").strip(),
        )
        triage.save_rules(settings.triage_file, [*rules, rule])
    except triage.TriageError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(1) from exc
    scope = f" on {rule.target}" if rule.target else " everywhere"
    console.print(
        f"[ok]Muted[/ok] {escape(rule.template)}{escape(scope)} "
        f"({triage.REASONS[reason]}) as [bold]{rule.id}[/bold] — {settings.triage_file}"
    )


@app.command("unmute")
def unmute_cmd(
    rule_id: Annotated[str, typer.Argument(help="The mute id to remove (see `cyberfw mutes`).")],
) -> None:
    """Remove a mute rule by id."""
    settings = load_settings()
    try:
        rules = triage.load_rules(settings.triage_file)
    except triage.TriageError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(1) from exc
    kept = [r for r in rules if r.id != rule_id]
    if len(kept) == len(rules):
        console.print(f"[warn]No mute with id {rule_id!r}.[/warn]")
        raise typer.Exit(1)
    triage.save_rules(settings.triage_file, kept)
    console.print(f"[ok]Removed[/ok] mute {rule_id}.")


@app.command("mutes")
def mutes_cmd() -> None:
    """List the triage mute rules and whether each is still active."""
    settings = load_settings()
    try:
        rules = triage.load_rules(settings.triage_file)
    except triage.TriageError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(1) from exc
    if not rules:
        console.print(f"[muted]No mutes. Add one with `cyberfw mute <template>`. ({settings.triage_file})[/muted]")
        return
    today = date.today()
    table = Table.grid(padding=(0, 2))
    for _ in range(5):
        table.add_column()
    table.add_row("[muted]id[/muted]", "[muted]template[/muted]", "[muted]target[/muted]",
                  "[muted]reason[/muted]", "[muted]state[/muted]")
    for rule in rules:
        state = "active" if rule.active(today) else f"[warn]expired {rule.expires}[/warn]"
        table.add_row(rule.id, escape(rule.template), escape(rule.target or "*"),
                      triage.REASONS.get(rule.reason, rule.reason), state)
        if rule.note:
            table.add_row("", f"[muted]{escape(rule.note)}[/muted]", "", "", "")
    console.print(table)


def _is_iso_date(value: str) -> bool:
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True
