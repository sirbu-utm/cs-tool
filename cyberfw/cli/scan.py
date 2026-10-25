"""`run` and `pipeline`: their flags, questions and rendering — the runs themselves are cyberfw.core's."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.live import Live
from rich.markup import escape
from rich.text import Text

from cyberfw import motion, vt
from cyberfw.cli.app import app
from cyberfw.cli.common import (
    VerboseOption,
    _after_live,
    _bootstrap,
    _checked_session,
    _is_interactive,
    _live_fps,
    _wants_to_save,
)
from cyberfw.cli.views import (
    _node_table,
    _plan_view,
    _print_note,
    _print_step_start,
    _print_step_summary,
    _record_table,
    _run_summary,
)
from cyberfw.config import Settings
from cyberfw.core.events import Note, RunObserver, StepEvent
from cyberfw.core.finish import finalize
from cyberfw.core.scan import choose_wordlist, execute_pipeline, prepare_pipeline
from cyberfw.core.sessions import open_session
from cyberfw.core.steps import post_scan
from cyberfw.core.tool_run import check_tool, keep_tool_run, run_tool_once
from cyberfw.exceptions import (
    CyberfwError,
    RegistryError,
    ToolNotFoundError,
)
from cyberfw.live_view import PipelineLiveView, TopologyView
from cyberfw.logging import console
from cyberfw.pipeline.engine import (
    Node,
    StageEvent,
)
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.report import diff as rundiff


def _read_hosts(path: Path) -> list[str]:
    """Read a newline-separated host list, skipping blanks and ``#`` comments."""
    hosts: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            hosts.append(line)
    return hosts


def _scan_control_overrides(
    *, severity: str, tags: str, rate_limit: int | None, exclude: list[str]
) -> dict[str, object]:
    """The ``Settings`` fields to override for this run — only the controls the
    caller actually set, so an unset flag leaves the env/YAML/default in place."""
    overrides: dict[str, object] = {}
    if severity:
        overrides["severity"] = severity
    if tags:
        overrides["tags"] = tags
    if rate_limit is not None:
        overrides["rate_limit"] = rate_limit
    if exclude:
        overrides["exclude"] = exclude
    return overrides


def _pipeline_exit_code(*, succeeded: bool, alert_hits: int) -> int:
    """The process exit code: a failed run (1) outranks an alert (3), which
    outranks a clean run (0). A broken scan is reported as broken, never as
    "nothing new"."""
    if not succeeded:
        return 1
    if alert_hits > 0:
        return 3
    return 0


def _resolve_vt_key(settings: Settings, choice: bool | None) -> str | None:
    """Decide the VirusTotal key for a pipeline run.

    Enrichment is on by default: a key already configured (``--api-key`` is not
    a pipeline option, so this means env / ``.env`` / ``~/.vt.toml``) is used
    silently. When none is set, the console offers to save one — the first time
    only on a default run, or every time under ``--vt``. ``--no-vt`` turns it
    off and never prompts (CI, pipes, or just not wanting VirusTotal).
    """
    if choice is False:  # --no-vt
        return None
    key = vt.resolve_api_key(settings.vt_api_key)
    if key:
        return key
    # No key anywhere. Ask only when someone can answer, and — on a default run
    # — only the first time (``--vt`` forces the ask even after an earlier skip).
    should_ask = _is_interactive() and (choice is True or not settings.vt_prompted)
    if not should_ask:
        if choice is True:
            console.print(
                f"[warn]VirusTotal: no API key set and no prompt available. "
                f"Free key: {vt.API_KEY_URL}[/warn]"
            )
        return None
    env_path = settings.root_dir / ".env"
    entered = vt.resolve_or_prompt(None, interactive=True, env_path=env_path)
    # Offer once: record that we asked (a pasted key is already saved to .env by
    # resolve_or_prompt) so later default runs do not prompt again.
    vt.remember_prompt(env_path)
    if not entered:
        console.print(
            "[muted]VirusTotal enrichment off for this run — run with --vt to enable later.[/muted]"
        )
    return entered


#: Steps that show a live activity line while they run: its label and detail.
_ACTIVITIES = {
    "mail": ("Email {subject}", "SPF · DMARC · MX"),
    "takeover": ("Subdomain takeover", "dangling CNAMEs"),
    "intel": ("Rating CVEs", "KEV · EPSS · Exploit-DB"),
    "vt": ("VirusTotal", "free tier: 4 lookups/min"),
}


class _CliObserver(RunObserver):
    """Shows a run on the console.

    During the scan, stages and records go to the live view when there is one.
    The view IS the final frame, so it is not reprinted afterwards: Live leaves
    its last frame on screen, and on a non-TTY (CI, a pipe) Rich prints that
    frame once instead of redrawing. Both views are renderables driven by
    auto-refresh, so spinners, bars, timers and the growth pulse animate between
    events — events only change their state. With ``echo_output`` the scan prints
    every raw stdout/stderr line instead; with ``raw_records`` (``run
    --no-parse``) each record's raw line, and stderr dimmed. Raw lines are printed
    as ``Text``, never as markup, so a tool's ``[...]`` or ``:ok:`` shows as the
    tool wrote it. After the scan: a live activity line
    while a slow step runs, its result line when it ends, notes as warning or
    muted lines.
    """

    def __init__(
        self,
        *,
        animate: bool,
        view: PipelineLiveView | TopologyView | None = None,
        echo_output: bool = False,
        raw_records: bool = False,
        fps: int = 4,
    ) -> None:
        self.animate = animate
        self.view = view
        self.echo_output = echo_output
        self.raw_records = raw_records
        self.fps = fps
        self._live: Live | None = None
        self._activity: motion.Activity | None = None

    def on_stage(self, event: StageEvent) -> None:
        if self.view is not None:
            self.view.on_stage(event)

    def on_record(self, record: ToolRecord) -> None:
        if self.view is not None:
            self.view.on_record(record)
        elif self.raw_records:
            console.print(Text(record.raw))

    def on_output(self, line: str, stream: str) -> None:
        if stream == "stderr" and (self.echo_output or self.raw_records):
            console.print(Text(line, style="dim"))
        elif stream == "stdout" and self.echo_output:
            console.print(Text(line))

    def on_step(self, event: StepEvent) -> None:
        if event.step == "scan":
            self._scan(event)
        elif event.kind == "start":
            _print_step_start(event)
            if event.step in _ACTIVITIES:
                label, detail = _ACTIVITIES[event.step]
                self._activity = motion.Activity(
                    console, label.format(subject=event.subject), animate=self.animate,
                    total=event.total, detail=detail,
                )
                self._activity.__enter__()
        elif event.kind == "advance":
            if self._activity is not None:
                self._activity.advance(event.done)
        else:
            if self._activity is not None:
                self._activity.__exit__(None, None, None)
                self._activity = None
            if event.summary is not None:
                _print_step_summary(event.summary)

    def on_note(self, note: Note) -> None:
        _print_note(note)

    def _scan(self, event: StepEvent) -> None:
        """Open the live view as the scan starts; leave its final frame when it ends."""
        if self.view is None:
            return
        if event.kind == "start":
            self._live = Live(self.view, console=console, refresh_per_second=self.fps, transient=False)
            self._live.start(refresh=True)
        elif event.kind == "done" and self._live is not None:
            self.view.finish()
            self._live.refresh()
            self._live.stop()
            self._live = None
            _after_live()


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
        bool | None,
        typer.Option(
            "--save/--no-save",
            help="Archive this run's records and reports to reports/<session>/. "
            "Omit both to be asked once the results are on screen.",
        ),
    ] = None,
    severity: Annotated[
        str, typer.Option("--severity", help="nuclei -severity, e.g. critical,high (overrides the setting).")
    ] = "",
    tags: Annotated[
        str, typer.Option("--tags", help="nuclei -tags, e.g. cve,exposure (overrides the setting).")
    ] = "",
    rate_limit: Annotated[
        int | None,
        typer.Option("--rate-limit", min=1, help="Max requests/sec for nuclei/httpx/naabu/ffuf (overrides the setting)."),
    ] = None,
    verbose: VerboseOption = False,
) -> None:
    """Run a single registered tool and print its records to the screen."""
    if target is None and list_file is None:
        console.print("[err]Provide a target via --target and/or a host list via --list.[/err]")
        raise typer.Exit(2)
    if session:
        _checked_session(session)

    settings, manager = _bootstrap(verbose=verbose)
    overrides = _scan_control_overrides(severity=severity, tags=tags, rate_limit=rate_limit, exclude=[])
    if overrides:
        settings = settings.model_copy(update=overrides)
    try:
        # The adapter knows what kind of target it takes; check that before
        # looking for the binary so a wrong target is a usage error (exit 2).
        check_tool(manager, tool, target)
    except ValueError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(2) from exc
    except ToolNotFoundError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        console.print("[warn]Run `cyberfw init` first (or export CYBERFW_GITHUB_TOKEN).[/warn]")
        raise typer.Exit(1) from exc
    except CyberfwError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(1) from exc

    # Only --save streams into reports/<session>/ as records arrive (crash-safe).
    # Undecided runs write nothing until the user has answered, so an ad-hoc
    # `run` never litters the filesystem with a folder nobody asked for.
    run_session = open_session(settings.reports_dir, kind="run", name=tool, session=session, stream=bool(save))
    hosts = _read_hosts(list_file) if list_file is not None else []
    target_label = target or f"{len(hosts)} host(s) from {list_file}"
    console.print(f"[info]tool:[/info] [tool]{tool}[/tool]  [info]target:[/info] {target_label}")

    # Parsing is on by default; disable it via the config `parse:` setting
    # (CYBERFW_PARSE=false) or override per-run with --no-parse.
    do_parse = settings.parse and not no_parse
    if do_parse:
        view = PipelineLiveView(
            [Node(tool=tool, stage=tool)], title=f"{tool} · {target_label}", animate=settings.animations
        )
        observer = _CliObserver(animate=settings.animations, view=view, fps=_live_fps(settings))
    else:
        why = "--no-parse" if no_parse else "config parse=false"
        console.print(f"[muted]{why}: streaming raw stdout/stderr exactly as the tool prints it[/muted]")
        observer = _CliObserver(animate=settings.animations, raw_records=True)
    ran = run_tool_once(
        tool, settings=settings, manager=manager, target=target, inputs=hosts, wordlist=wordlist,
        parse=do_parse, session=run_session, observer=observer,
    )
    records = ran.records
    if not do_parse:
        console.print(f"[info]{len(records)} line(s) captured[/info]")
    elif records:
        console.print(_record_table(records, tool=tool, target=target_label))
    else:
        console.print("[muted]No records found.[/muted]")

    # --save decided up front (and streamed the records as they came); an
    # undecided run asks now, and only when there is something to keep.
    if save or (save is None and records and _wants_to_save(save, default=False, what=tool)):
        written = keep_tool_run(ran, settings=settings, manager=manager)
        console.print(f"[ok]saved:[/ok] {run_session.dir}")
        for label, path in written.items():
            console.print(f"[ok]{label}:[/ok] {path}")

    if not ran.node.ok:
        console.print(f"[err]{escape(ran.node.error or 'stage failed')}[/err]")
        raise typer.Exit(1)


@app.command("pipeline")
def pipeline_cmd(
    name: Annotated[str, typer.Argument(help="Pipeline name: recon-to-vuln or a file from pipelines/<name>.yaml.")],
    target: Annotated[str | None, typer.Option("--target", "-t", help="Seed domain/URL for the first stage.")] = None,
    ffuf: Annotated[bool, typer.Option("--ffuf", help="Include the Ffuf node.")] = False,
    gowitness: Annotated[
        bool | None,
        typer.Option(
            "--gowitness/--no-gowitness",
            help="Include the Gowitness (screenshots) stage. Default: on when it can run "
            "(installed, and a Chrome/Chromium is present), off otherwise — so a plain run "
            "gains screenshots where possible and never fails for the lack of a browser.",
        ),
    ] = None,
    max_httpx: Annotated[int, typer.Option("--max-httpx", min=0, help="Cap live hosts passed onward (0 = all).")] = 0,
    wordlist: Annotated[str | None, typer.Option("--wordlist", "-w", help="Wordlist for the Ffuf stage (required with --ffuf).")] = None,
    session: Annotated[str | None, typer.Option("--session", help="Session id for the context store.")] = None,
    report: Annotated[
        bool | None,
        typer.Option(
            "--report/--no-report",
            help="Keep this run's reports/<session>/ directory. Omit both to be asked when the run ends.",
        ),
    ] = None,
    no_parse: Annotated[
        bool,
        typer.Option(
            "--no-parse",
            help="Verbose mode: stream every stage's raw stdout/stderr live "
            "(records are still parsed under the hood to thread stages).",
        ),
    ] = False,
    force_start: Annotated[
        bool,
        typer.Option("--force-start", help="Start even when a tool this pipeline needs is unavailable."),
    ] = False,
    topology: Annotated[
        bool | None,
        typer.Option(
            "--topology/--no-topology",
            "--map/--no-map",
            help="Live view: the topology map (seed → hosts → ports/vulns) or the stage table. "
            "Default comes from the `view` setting; this overrides it for one run.",
        ),
    ] = None,
    vt_enrich: Annotated[
        bool | None,
        typer.Option(
            "--vt/--no-vt",
            help="Enrich discovered domains/IPs/URLs with VirusTotal reputation after the scan. "
            "On by default, using your own key (env / .env / ~/.vt.toml); you are asked for one "
            "the first time. --no-vt skips it; --vt forces the prompt.",
        ),
    ] = None,
    vt_limit: Annotated[
        int,
        typer.Option("--vt-limit", min=1, help="Max VirusTotal lookups (free tier: 4/min, 500/day)."),
    ] = 20,
    intel: Annotated[
        bool,
        typer.Option(
            "--intel/--no-intel",
            help="Rate CVE findings by real-world exploitation: CISA KEV (exploited in the wild), "
            "EPSS (chance of attack in 30 days) and Exploit-DB (public exploit). Free, no keys; "
            "only public feeds are queried, never the target.",
        ),
    ] = True,
    mail: Annotated[
        bool,
        typer.Option(
            "--mail/--no-mail",
            help="Check whether mail can be forged as the seed domain: SPF, DMARC and MX, looked "
            "up over DNS-over-HTTPS (Cloudflare, then Google) — the target is not contacted.",
        ),
    ] = True,
    takeover: Annotated[
        bool,
        typer.Option(
            "--takeover/--no-takeover",
            help="Check discovered subdomains for a dangling CNAME to an unclaimed third-party "
            "service (GitHub Pages, Heroku, S3…) that could be taken over. DNS over DoH, plus one "
            "HTTP read of a matching host — on the service's edge, not your origin.",
        ),
    ] = True,
    baseline: Annotated[
        str | None,
        typer.Option(
            "--baseline",
            help="Earlier run to compare with: a session id, its directory or its report.json. "
            "By default the newest earlier run of the same pipeline and seed is used.",
        ),
    ] = None,
    no_baseline: Annotated[
        bool, typer.Option("--no-baseline", help="Do not compare with an earlier run.")
    ] = False,
    alert: Annotated[
        bool,
        typer.Option(
            "--alert",
            help="Exit 3 (and print an ALERT line) when this run has NEW findings versus the "
            "previous saved scan of the same target. For scheduled monitoring; see `cyberfw schedule`.",
        ),
    ] = False,
    alert_severity: Annotated[
        str,
        typer.Option(
            "--alert-severity",
            help="Lowest severity that counts for --alert: critical|high|medium|low (default low).",
        ),
    ] = "low",
    severity: Annotated[
        str,
        typer.Option("--severity", help="nuclei -severity, e.g. critical,high (overrides the setting; empty = all)."),
    ] = "",
    tags: Annotated[
        str, typer.Option("--tags", help="nuclei -tags, e.g. cve,exposure (overrides the setting; empty = all).")
    ] = "",
    rate_limit: Annotated[
        int | None,
        typer.Option("--rate-limit", min=1, help="Max requests/sec for nuclei/httpx/naabu/ffuf (overrides the setting)."),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", help="Hostname glob to keep out of scope; repeatable. A discovered host matching any is not scanned."),
    ] = None,
    plan: Annotated[
        bool,
        typer.Option("--plan", help="Print the stage graph and pre-flight, then exit without scanning (a dry run)."),
    ] = False,
    verbose: VerboseOption = False,
) -> None:
    """Run a ready-made pipeline and render HTML/JSON reports.

    After the scan: TLS certificates httpx saw are checked for expiry, trust and
    host-name match; the seed domain is checked for email spoofing (SPF/DMARC —
    --no-mail skips it); discovered subdomains are checked for a dangling CNAME
    that could be taken over (--no-takeover skips it); CVE findings are rated by
    real-world exploitation
    (CISA KEV, EPSS, Exploit-DB — --no-intel skips it); and discovered domains,
    IPs and URLs get VirusTotal reputation (your own free key, asked for the
    first time — --no-vt skips it). Finally the run is compared with the
    previous scan of the same target (new findings, opened ports, renewed
    certificates...) — --baseline picks another run, --no-baseline skips it.
    """
    if target is None and not plan:
        console.print("[err]Provide a seed target via --target.[/err]")
        raise typer.Exit(2)
    if alert and no_baseline:
        console.print("[err]--alert needs a baseline to compare with; it cannot be used with --no-baseline.[/err]")
        raise typer.Exit(2)
    if alert and alert_severity not in rundiff.REAL:
        console.print(
            f"[err]--alert-severity must be one of {', '.join(rundiff.REAL)} (got {escape(alert_severity)}).[/err]"
        )
        raise typer.Exit(2)
    if session:
        _checked_session(session)

    settings, manager = _bootstrap(verbose=verbose)
    overrides = _scan_control_overrides(
        severity=severity, tags=tags, rate_limit=rate_limit, exclude=exclude or []
    )
    if overrides:
        settings = settings.model_copy(update=overrides)
    # Resolve the VirusTotal key up front (and prompt if needed) before the live
    # view takes over the terminal — a prompt and a Live render cannot coexist.
    # A --plan dry run scans nothing, so it never prompts for a key.
    vt_key = None if plan else _resolve_vt_key(settings, vt_enrich)
    # Whether the run can happen at all is knowable now, and a scan takes
    # minutes: report what is unavailable up front instead of spending the
    # time only to say that a stage never ran.
    try:
        prepared = prepare_pipeline(
            name, target, settings=settings, manager=manager, ffuf=ffuf, gowitness=gowitness, max_httpx=max_httpx
        )
    except RegistryError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        manager.close()
        raise typer.Exit(2) from exc
    if plan:
        console.print(_plan_view(prepared))
        manager.close()
        return
    assert target is not None  # a non-plan run required --target above; narrows for the scan path
    for warning in prepared.warnings:
        console.print(f"[warn]{warning}[/warn]")
    if prepared.blocking and not force_start:
        for stage, tool, reason in prepared.blocking:
            console.print(f"[err]{tool}[/err] ({stage}): [err]{reason}[/err]")
        console.print(
            "[warn]Fix the above (`cyberfw init`, `cyberfw status`), "
            "or pass --force-start to run the stages that can.[/warn]"
        )
        manager.close()
        raise typer.Exit(2)

    # Verbose view when parsing is disabled (config parse=false or --no-parse):
    # stream each stage's raw stdout/stderr live instead of the quiet spinner.
    # Stages are still parsed internally so results thread from one to the next.
    verbose = no_parse or not settings.parse
    # The flag overrides the `view` setting for this run; unset falls back to it.
    use_topology = topology if topology is not None else settings.view == "topology"
    view: PipelineLiveView | TopologyView | None = None
    if not verbose:
        if use_topology:
            view = TopologyView(prepared.nodes, seed=target, title=f"{name} · {target}", animate=settings.animations)
        else:
            view = PipelineLiveView(prepared.nodes, title=f"pipeline {name} · {target}", animate=settings.animations)
    observer = _CliObserver(animate=settings.animations, view=view, echo_output=verbose, fps=_live_fps(settings))

    wordlist = choose_wordlist(settings, wordlist, ffuf=ffuf, observer=observer)
    # The session knows whether its directory is ours: declining to save may
    # remove it, and a --session pointing at an earlier run must never be deleted.
    run_session = open_session(settings.reports_dir, kind="pipeline", name=name, session=session, stream=True)
    if topology is True and verbose:
        # Only when the user explicitly asked: the config default silently yields
        # to the raw stream under --no-parse rather than nagging every run.
        why = "--no-parse" if no_parse else "config parse=false"
        console.print(f"[warn]--topology needs the parsed view; ignored under {why}.[/warn]")
    if verbose:
        why = "--no-parse" if no_parse else "config parse=false"
        console.print(f"[muted]{why}: streaming raw stdout/stderr from every stage[/muted]")
    try:
        result = execute_pipeline(prepared, session=run_session, wordlist=wordlist, observer=observer)
    except CyberfwError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(1) from exc

    post_scan(
        result, seed=target, settings=settings, mail=mail, takeover=takeover, intel=intel,
        vt_key=vt_key, vt_limit=vt_limit, observer=observer,
    )

    def _decide() -> bool:
        # Asked once the comparison is on screen; the raw stream's stage table comes first.
        if verbose:
            console.print(_node_table(result))
        return _wants_to_save(report, default=True, what=name)

    try:
        finished = finalize(
            result, manager=manager, settings=settings, name=name, seed=target,
            tools={n.tool for n in prepared.nodes}, session=run_session, compare=not no_baseline,
            baseline=baseline, save=_decide, observer=observer,
        )
    except CyberfwError as exc:
        console.print(f"[err]report failed:[/err] {escape(str(exc))}")
        return
    changes = finished.changes
    written = list(finished.reports.items())

    # A blank line: Live's last frame ends without one, so the panel would
    # otherwise start on the same line as the table's bottom edge.
    console.print()
    motion.play(
        console,
        lambda progress: _run_summary(
            result, name=name, session_id=run_session.id, reports=written, progress=progress
        ),
        duration=0.7,
        animate=settings.animations,
    )

    alert_hits = changes.new_findings_at_least(alert_severity) if (alert and changes is not None) else 0
    if alert_hits:
        base = changes.baseline.get("session_id") if changes else None  # narrow for the type checker
        since = f" since {base}" if base else ""
        console.print(
            f"[err]ALERT: {alert_hits} new finding(s) >= {alert_severity}{since}[/err]"
        )

    code = _pipeline_exit_code(succeeded=result.succeeded(), alert_hits=alert_hits)
    if code:
        raise typer.Exit(code)
