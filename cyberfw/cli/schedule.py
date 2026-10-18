"""`schedule` — recurring monitoring scans through cron / the Windows Task Scheduler."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Annotated

import typer
from rich.markup import escape

from cyberfw import schedule
from cyberfw.cli.app import app
from cyberfw.config import load_settings
from cyberfw.logging import console
from cyberfw.report import diff as rundiff


def _is_posix() -> bool:
    """True on Linux/macOS (cron), False on Windows (Task Scheduler)."""
    return os.name != "nt"


def _schedule_program() -> list[str]:
    """How a scheduled entry should invoke cyberfw, as argv tokens: the installed
    command if it is on PATH, else this interpreter with ``-m cyberfw``. Returned
    as tokens so each is quoted correctly for its scheduler."""
    found = shutil.which("cyberfw")
    if found:
        return [found]
    return [sys.executable, "-m", "cyberfw"]


@app.command("schedule")
def schedule_cmd(
    name: Annotated[str, typer.Argument(help="Pipeline name, as `pipeline` takes it.")],
    target: Annotated[str, typer.Option("--target", "-t", help="Seed domain/URL to scan on a schedule.")],
    every: Annotated[str, typer.Option("--every", help="How often: daily | weekly | hourly.")] = "daily",
    at: Annotated[str, typer.Option("--at", help="Time HH:MM (24h) for daily/weekly; ignored for hourly.")] = "09:00",
    cron: Annotated[
        str | None,
        typer.Option("--cron", help="Raw 5-field cron expression; overrides --every/--at (POSIX only)."),
    ] = None,
    alert_severity: Annotated[
        str, typer.Option("--alert-severity", help="Lowest severity that alerts: critical|high|medium|low.")
    ] = "low",
    ffuf: Annotated[bool, typer.Option("--ffuf", help="Include the Ffuf stage in the scheduled scan.")] = False,
    gowitness: Annotated[bool, typer.Option("--gowitness", help="Include the Gowitness stage.")] = False,
    wordlist: Annotated[str | None, typer.Option("--wordlist", "-w", help="Wordlist for the Ffuf stage.")] = None,
    no_mail: Annotated[bool, typer.Option("--no-mail", help="Skip the email-spoofing check.")] = False,
    no_intel: Annotated[bool, typer.Option("--no-intel", help="Skip CVE exploitation rating.")] = False,
    no_vt: Annotated[bool, typer.Option("--no-vt", help="Skip VirusTotal enrichment.")] = False,
    install: Annotated[bool, typer.Option("--install", help="Install the entry into the OS scheduler, not just print it.")] = False,
    remove: Annotated[bool, typer.Option("--remove", help="Remove the previously installed entry for this pipeline+target.")] = False,
) -> None:
    """Generate an OS-scheduler entry that runs ``pipeline … --alert`` on a schedule.

    By default it prints the entry for the current OS (a crontab line on
    Linux/macOS, a ``schtasks`` command on Windows) and touches nothing;
    ``--install`` applies it and ``--remove`` deletes it. The entry carries this
    workspace (``CYBERFW_ROOT_DIR``) and appends output to ``logs/schedule.log``,
    and the scan exits 3 when it finds something new (see ``pipeline --alert``).
    """
    if alert_severity not in rundiff.REAL:
        console.print(f"[err]--alert-severity must be one of {', '.join(rundiff.REAL)}.[/err]")
        raise typer.Exit(2)
    try:
        # The target becomes part of a scheduled shell command; refuse an
        # injection-shaped one up front, before anything is generated or written.
        schedule.validate_target(target)
    except ValueError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(2) from exc
    posix = _is_posix()
    if cron is not None:
        if not posix:
            console.print("[err]--cron is POSIX-only; on Windows use --every/--at.[/err]")
            raise typer.Exit(2)
        if len(cron.split()) != 5:
            console.print(f"[err]--cron must be a 5-field expression, got {escape(cron)!r}.[/err]")
            raise typer.Exit(2)

    scan_args: list[str] = []
    if ffuf:
        scan_args.append("--ffuf")
    if gowitness:
        scan_args.append("--gowitness")
    if wordlist:
        scan_args += ["--wordlist", wordlist]
    for flag, on in (("--no-mail", no_mail), ("--no-intel", no_intel), ("--no-vt", no_vt)):
        if on:
            scan_args.append(flag)

    plan = schedule.Schedule(
        pipeline=name, target=target, every=every, at=at,
        alert_severity=alert_severity, scan_args=tuple(scan_args),
    )
    settings = load_settings()
    program = _schedule_program()
    root = str(settings.root_dir)
    log = str(settings.logs_dir / "schedule.log")

    try:
        if posix:
            _schedule_posix(plan, program=program, root=root, log=log, cron=cron, install=install, remove=remove)
        else:
            _schedule_windows(plan, program=program, root=root, log=log, install=install, remove=remove)
    except ValueError as exc:  # a bad cadence/time from the generators
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(2) from exc
    except (OSError, RuntimeError) as exc:  # the scheduler refused the install/remove
        console.print(f"[err]scheduler error: {escape(str(exc))}[/err]")
        raise typer.Exit(1) from exc


def _schedule_posix(
    plan: schedule.Schedule, *, program: list[str], root: str, log: str, cron: str | None, install: bool, remove: bool
) -> None:
    if remove:
        gone = schedule.remove_cron(plan)
        console.print(f"[ok]Removed[/ok] {schedule.tag(plan)}" if gone else f"[muted]No entry {schedule.tag(plan)} to remove.[/muted]")
        return
    if install:
        settings = load_settings()
        settings.ensure_dirs()  # so the log's directory exists for the redirect
        schedule.install_cron(plan, program=program, root=root, log=log, expr=cron)
        console.print(f"[ok]Installed[/ok] cron entry {schedule.tag(plan)} (crontab).")
        return
    line = schedule.cron_line(plan, program=program, root=root, log=log, expr=cron)
    console.print("[muted]Add this line to your crontab (`crontab -e`), or re-run with --install:[/muted]")
    console.print(line, highlight=False)


def _schedule_windows(
    plan: schedule.Schedule, *, program: list[str], root: str, log: str, install: bool, remove: bool
) -> None:
    if remove:
        gone = schedule.remove_schtasks(plan)
        console.print(f"[ok]Removed[/ok] task {schedule.tag(plan)}" if gone else f"[muted]No task {schedule.tag(plan)} to remove.[/muted]")
        return
    if install:
        settings = load_settings()
        settings.ensure_dirs()
        schedule.install_schtasks(plan, program=program, root=root, log=log)
        console.print(f"[ok]Installed[/ok] task {schedule.tag(plan)} (Task Scheduler).")
        return
    argv = schedule.schtasks_command(plan, program=program, root=root, log=log)
    console.print("[muted]Run this to register the task (or re-run with --install):[/muted]")
    console.print(subprocess.list2cmdline(argv), highlight=False)
