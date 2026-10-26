"""`run` and `pipeline`: their flags, questions and rendering — the runs themselves go through cyberfw.api."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer
from rich.live import Live
from rich.markup import escape
from rich.text import Text

from cyberfw import motion, vt
from cyberfw.api import Plan, plan_pipeline, run_pipeline, run_tool
from cyberfw.cli.app import app
from cyberfw.cli.common import (
    VerboseOption,
    _after_live,
    _checked_session,
    _is_interactive,
    _live_fps,
    _setup,
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
from cyberfw.exceptions import (
    CyberfwError,
    PreflightError,
    RegistryError,
    ReportError,
    ToolNotFoundError,
)
from cyberfw.live_view import PipelineLiveView, TopologyView
from cyberfw.logging import console
from cyberfw.pipeline.engine import (
    Node,
    PipelineResult,
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
        make_view: Callable[[Plan], PipelineLiveView | TopologyView | None] | None = None,
        before_scan: Callable[[], None] | None = None,
        after_scan: Callable[[PipelineResult], None] | None = None,
    ) -> None:
        self.animate = animate
        self.view = view
        self.echo_output = echo_output
        self.raw_records = raw_records
        self.fps = fps
        #: Builds the live view from the plan the run sends first (``pipeline``).
        self.make_view = make_view
        #: Prints what comes right before the scan: the mode lines, a tool's header.
        self.before_scan = before_scan
        #: Prints what the scan's result shows right after it: a tool's records.
        self.after_scan = after_scan
        #: The scan's own result, once it has ended.
        self.scan_result: PipelineResult | None = None
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
                self._close_activity()  # one a step never ended must not stay on screen
                label, detail = _ACTIVITIES[event.step]
                self._activity = motion.Activity(
                    console, label.format(subject=event.subject), animate=self.animate,
                    total=event.total, detail=detail,
                )
                self._activity.__enter__()
        elif event.kind == "advance":
            if self._activity is not None:
                self._activity.advance(event.completed)
        else:
            self._close_activity()
            if event.summary is not None:
                _print_step_summary(event.summary)

    def on_note(self, note: Note) -> None:
        _print_note(note)

    def _close_activity(self) -> None:
        if self._activity is not None:
            self._activity.__exit__(None, None, None)
            self._activity = None

    def on_plan(self, plan: Plan) -> None:
        if self.make_view is not None:
            self.view = self.make_view(plan)

    def _scan(self, event: StepEvent) -> None:
        """As the scan starts its lead-in lines, then the live view; as it ends the
        view's final frame — and the scan's result, for whoever prints it later."""
        if event.kind == "start":
            if self.before_scan is not None:
                self.before_scan()
            if self.view is not None:
                self._live = Live(self.view, console=console, refresh_per_second=self.fps, transient=False)
                self._live.start(refresh=True)
        elif event.kind == "done":
            if isinstance(event.summary, PipelineResult):
                self.scan_result = event.summary
            if self.view is not None and self._live is not None:
                try:
                    self.view.finish()
                    self._live.refresh()
                finally:  # a view that fails to finish must not leave the display live
                    self._live.stop()
                    self._live = None
                    _after_live()
            if self.after_scan is not None and self.scan_result is not None:
                self.after_scan(self.scan_result)


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

    settings = _setup(verbose=verbose)
    hosts = _read_hosts(list_file) if list_file is not None else []
    target_label = target or f"{len(hosts)} host(s) from {list_file}"
    # Parsing is on by default; disable it via the config `parse:` setting
    # (CYBERFW_PARSE=false) or override per-run with --no-parse.
    do_parse = settings.parse and not no_parse

    def _header() -> None:
        console.print(f"[info]tool:[/info] [tool]{tool}[/tool]  [info]target:[/info] {target_label}")
        if not do_parse:
            why = "--no-parse" if no_parse else "config parse=false"
            console.print(f"[muted]{why}: streaming raw stdout/stderr exactly as the tool prints it[/muted]")

    def _records(result: PipelineResult) -> None:
        if not do_parse:
            console.print(f"[info]{len(result.records)} line(s) captured[/info]")
        elif result.records:
            console.print(_record_table(result.records, tool=tool, target=target_label))
        else:
            console.print("[muted]No records found.[/muted]")

    view = (
        PipelineLiveView([Node(tool=tool, stage=tool)], title=f"{tool} · {target_label}", animate=settings.animations)
        if do_parse
        else None
    )
    observer = _CliObserver(
        animate=settings.animations, view=view, raw_records=not do_parse, fps=_live_fps(settings),
        before_scan=_header, after_scan=_records,
    )
    # --save streams into reports/<session>/ as records arrive (crash-safe). An
    # undecided run asks once the results are on screen, and only when there is
    # something to keep, so an ad-hoc `run` never litters the filesystem.
    decide = save if save is not None else (lambda: _wants_to_save(None, default=False, what=tool))
    try:
        # The adapter knows what kind of target it takes; that is checked before
        # the binary is looked for, so a wrong target is a usage error (exit 2).
        outcome = run_tool(
            tool, target=target, inputs=hosts, wordlist=wordlist, settings=settings, severity=severity,
            tags=tags, rate_limit=rate_limit, parse=do_parse, session=session, save=decide, observer=observer,
        )
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

    if outcome.reports:
        console.print(f"[ok]saved:[/ok] {outcome.session_dir}")
        for label, path in outcome.reports.items():
            console.print(f"[ok]{label}:[/ok] {path}")

    (stage,) = outcome.result.nodes
    if not stage.ok:
        console.print(f"[err]{escape(stage.error or 'stage failed')}[/err]")
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

    settings = _setup(verbose=verbose)
    # Resolve the VirusTotal key up front (and prompt if needed) before the live
    # view takes over the terminal — a prompt and a Live render cannot coexist.
    # A --plan dry run scans nothing, so it never prompts for a key.
    vt_key = None if plan else _resolve_vt_key(settings, vt_enrich)
    if plan:
        try:
            dry_run = plan_pipeline(name, target, settings=settings, ffuf=ffuf, gowitness=gowitness, max_httpx=max_httpx)
        except RegistryError as exc:
            console.print(f"[err]{escape(str(exc))}[/err]")
            raise typer.Exit(2) from exc
        console.print(_plan_view(dry_run))
        return
    assert target is not None  # a non-plan run required --target above; narrows for the scan path

    # Verbose view when parsing is disabled (config parse=false or --no-parse):
    # stream each stage's raw stdout/stderr live instead of the quiet spinner.
    # Stages are still parsed internally so results thread from one to the next.
    verbose = no_parse or not settings.parse
    # The flag overrides the `view` setting for this run; unset falls back to it.
    use_topology = topology if topology is not None else settings.view == "topology"

    def _make_view(prepared: Plan) -> PipelineLiveView | TopologyView | None:
        if verbose:
            return None
        nodes = [Node(tool=stage.tool, stage=stage.stage) for stage in prepared.stages]
        if use_topology:
            return TopologyView(nodes, seed=target, title=f"{name} · {target}", animate=settings.animations)
        return PipelineLiveView(nodes, title=f"pipeline {name} · {target}", animate=settings.animations)

    def _before_scan() -> None:
        if topology is True and verbose:
            # Only when the user explicitly asked: the config default silently yields
            # to the raw stream under --no-parse rather than nagging every run.
            why = "--no-parse" if no_parse else "config parse=false"
            console.print(f"[warn]--topology needs the parsed view; ignored under {why}.[/warn]")
        if verbose:
            why = "--no-parse" if no_parse else "config parse=false"
            console.print(f"[muted]{why}: streaming raw stdout/stderr from every stage[/muted]")

    observer = _CliObserver(
        animate=settings.animations, make_view=_make_view, before_scan=_before_scan,
        echo_output=verbose, fps=_live_fps(settings),
    )

    def _decide() -> bool:
        # Asked once the comparison is on screen; the raw stream's stage table comes first.
        if verbose and observer.scan_result is not None:
            console.print(_node_table(observer.scan_result))
        return _wants_to_save(report, default=True, what=name)

    try:
        outcome = run_pipeline(
            name, target, settings=settings, ffuf=ffuf, wordlist=wordlist, gowitness=gowitness,
            max_httpx=max_httpx, severity=severity, tags=tags, rate_limit=rate_limit, exclude=exclude or [],
            mail=mail, takeover=takeover, intel=intel, vt_key=vt_key, vt_limit=vt_limit, baseline=baseline,
            compare=not no_baseline, session=session, save=_decide, force_start=force_start, observer=observer,
        )
    except RegistryError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(2) from exc
    except PreflightError as exc:
        # Whether the run can happen at all is knowable before it starts, and a
        # scan takes minutes: say what is unavailable instead of spending the time.
        for stage, tool, reason in exc.blocking:
            console.print(f"[err]{tool}[/err] ({stage}): [err]{reason}[/err]")
        console.print(
            "[warn]Fix the above (`cyberfw init`, `cyberfw status`), "
            "or pass --force-start to run the stages that can.[/warn]"
        )
        raise typer.Exit(2) from exc
    except ReportError as exc:
        console.print(f"[err]report failed:[/err] {escape(str(exc))}")
        return
    except CyberfwError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(1) from exc

    # A blank line: Live's last frame ends without one, so the panel would
    # otherwise start on the same line as the table's bottom edge.
    console.print()
    motion.play(
        console,
        lambda progress: _run_summary(
            outcome.result, name=name, session_id=outcome.session_id, reports=list(outcome.reports.items()),
            progress=progress,
        ),
        duration=0.7,
        animate=settings.animations,
    )

    alert_hits = outcome.alert_hits(alert_severity) if alert else 0
    if alert_hits:
        base = outcome.changes.baseline.get("session_id") if outcome.changes else None
        since = f" since {base}" if base else ""
        console.print(
            f"[err]ALERT: {alert_hits} new finding(s) >= {alert_severity}{since}[/err]"
        )

    code = outcome.exit_code(alert_severity if alert else None)
    if code:
        raise typer.Exit(code)
