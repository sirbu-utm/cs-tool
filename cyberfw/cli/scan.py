"""`run` and `pipeline` — running a tool or a pipeline and finishing the run."""

from __future__ import annotations

import functools
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import anyio
import typer
from rich.live import Live
from rich.markup import escape

from cyberfw import motion, threatintel, triage, vt
from cyberfw.cli.app import app
from cyberfw.cli.common import (
    VerboseOption,
    _after_live,
    _bootstrap,
    _checked_session,
    _is_interactive,
    _live_fps,
    _session_tag,
    _tool_state,
    _wants_to_save,
)
from cyberfw.cli.views import _node_table, _plan_view, _print_changes, _record_table, _run_summary
from cyberfw.config import Settings
from cyberfw.exceptions import (
    CyberfwError,
    RegistryError,
    ToolNotFoundError,
)
from cyberfw.live_view import PipelineLiveView, TopologyView
from cyberfw.logging import console
from cyberfw.manager import ToolManager
from cyberfw.pipeline.context import SessionContext
from cyberfw.pipeline.engine import (
    Node,
    NodeResult,
    PipelineEngine,
    PipelineResult,
    StageEvent,
    dependency_hint,
)
from cyberfw.pipeline.schemas import ToolRecord, validate_record
from cyberfw.pipelines import build
from cyberfw.posture import mail as mailcheck
from cyberfw.posture import takeover as takeovercheck
from cyberfw.posture import tls as tlscheck
from cyberfw.report import diff as rundiff
from cyberfw.report.html_report import generate_html_report
from cyberfw.report.json_report import generate_json_report, report_payload
from cyberfw.report.run_info import RunInfo
from cyberfw.resources import default_wordlist
from cyberfw.tools import adapter_class
from cyberfw.tools.base import ToolContext


def _read_hosts(path: Path) -> list[str]:
    """Read a newline-separated host list, skipping blanks and ``#`` comments."""
    hosts: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            hosts.append(line)
    return hosts


def _discard_session(session_dir: Path, *, created: bool) -> None:
    """Remove a session directory this run created; never touch a pre-existing one."""
    if not created:
        console.print(f"[muted]report not saved; {session_dir} was left as it was[/muted]")
        return
    shutil.rmtree(session_dir, ignore_errors=True)
    console.print("[muted]report not saved[/muted]")


def _write_reports(
    result: PipelineResult,
    *,
    session_id: str,
    settings: Settings,
    run: RunInfo,
    changes: rundiff.RunDiff | None = None,
) -> list[tuple[str, Path]]:
    """Render both reports into the session directory; returns ``(label, path)`` pairs."""
    json_path = generate_json_report(
        result, session_id=session_id, reports_dir=settings.reports_dir, run=run, changes=changes
    )
    html_path = generate_html_report(
        result, session_id=session_id, reports_dir=settings.reports_dir, run=run, changes=changes
    )
    return [("json", json_path), ("html", html_path)]


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


def _apply_triage(result: PipelineResult, triage_file: Path) -> None:
    """Silence findings the triage file has muted, and say how many."""
    try:
        rules = triage.load_rules(triage_file)
    except triage.TriageError as exc:
        console.print(f"[warn]Triage skipped — {escape(str(exc))}[/warn]")
        return
    if not rules:
        return
    summary = triage.apply(result.records, rules)
    if summary.muted:
        console.print(f"[muted]Triage: {escape(summary.line())}[/muted]")
    if summary.expired:
        console.print(f"[warn]Triage: {len(summary.expired)} rule(s) expired — {', '.join(summary.expired)}[/warn]")


def _compare_with_earlier(
    result: PipelineResult, run: RunInfo, reports_dir: Path, explicit: str | None
) -> rundiff.RunDiff | None:
    """Compare this run with an earlier one — the one named, else the newest
    earlier run of the same pipeline and seed — and print what changed."""
    try:
        if explicit:
            path: Path | None = rundiff.resolve_report(explicit, reports_dir)
        else:
            path = rundiff.find_baseline(
                reports_dir, seed=run.seed, pipeline=run.pipeline, before=result.started_at
            )
        if path is None:
            return None  # a first scan of this target: nothing to compare with
        changes = rundiff.compare(rundiff.load_report(path), report_payload(result, run))
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[warn]Not compared with an earlier run: {escape(str(exc))}[/warn]")
        return None
    _print_changes(changes, limit=8)
    return changes


def _run_info(manager: ToolManager, *, name: str, seed: str | None, session_id: str, tools: set[str]) -> RunInfo:
    return RunInfo(
        pipeline=name,
        seed=seed,
        session_id=session_id,
        platform=manager.mapping.label,
        tool_versions={tool: (manager.install_state(tool) or {}).get("version") for tool in sorted(tools)},
    )


def _preflight(
    manager: ToolManager, nodes: list[Node], tools_dir: Path
) -> tuple[list[tuple[str, str, str]], list[str]]:
    """What stands between this plan and a useful run, in plan order.

    Returns ``(blocking, warnings)``. Blocking: a binary that cannot run, or a
    hard external requirement the adapter reports missing (gowitness without
    Chrome) — the stage could only fail. Warnings: a ``check_deps`` entry that
    is not on PATH (RustScan's Nmap), which costs capability, not the run.
    """
    blocking: list[tuple[str, str, str]] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for node in nodes:
        if node.tool in seen:
            continue
        seen.add(node.tool)
        state = _tool_state(manager, node.tool, tools_dir)
        if state != "ready":
            blocking.append((node.stage, node.tool, state))
            continue
        requirement = adapter_class(node.tool).missing_requirement(tools_dir)
        if requirement is not None:
            blocking.append((node.stage, node.tool, requirement))
        for dep in manager.spec(node.tool).check_deps:
            if shutil.which(dep) is None:
                warnings.append(
                    f"{node.tool} works best with `{dep}`, which is not on PATH — {dependency_hint(dep)}"
                )
    return blocking, warnings


def _resolve_gowitness(flag: bool | None, manager: ToolManager, tools_dir: Path) -> bool:
    """Whether recon-to-vuln should run gowitness.

    An explicit ``--gowitness`` / ``--no-gowitness`` is taken as given. The
    vanilla default (``None``) includes it only when it can actually run —
    registered, installed, and a Chrome/Chromium present — so a plain run gains
    screenshots where possible and never fails for the lack of a browser."""
    if flag is not None:
        return flag
    from cyberfw.tools.gowitness import _find_chrome

    return (
        "gowitness" in manager.registry.names()
        and manager.is_installed("gowitness")
        and _find_chrome(tools_dir) is not None
    )


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


def _check_tls(result: PipelineResult) -> None:
    """Certificate health from what httpx's -tls-grab already collected (no network)."""
    certs = tlscheck.certificates(result.records)
    if not certs:
        return
    now = datetime.now(timezone.utc)
    result.records.extend(tlscheck.findings(certs, result.records, now=now))
    expired = sum(1 for cert in certs if cert.is_expired(now))
    soon = sum(
        1
        for cert in certs
        if not cert.is_expired(now) and (days := cert.days_left(now)) is not None
        and days <= tlscheck.SOON_DAYS
    )
    untrusted = sum(1 for cert in certs if cert.self_signed or cert.mismatched)
    parts = [f"{len(certs)} certificate(s)"]
    if expired:
        parts.append(f"[err]{expired} expired[/err]")
    if soon:
        parts.append(f"[warn]{soon} expire within {tlscheck.SOON_DAYS} days[/warn]")
    if untrusted:
        parts.append(f"[warn]{untrusted} untrusted or for another name[/warn]")
    if len(parts) == 1:
        parts.append(f"[ok]all valid for {tlscheck.SOON_DAYS}+ days[/ok]")
    console.print("TLS: " + " · ".join(parts))


def _check_mail(result: PipelineResult, seed: str, *, animate: bool = True) -> None:
    """Whether mail can be forged as the seed domain (SPF / DMARC over DNS-over-HTTPS)."""
    domain = mailcheck.mail_domain(seed)
    if domain is None:
        return
    try:
        with motion.Activity(console, f"Email {domain}", animate=animate, detail="SPF · DMARC · MX"):
            record, found = anyio.run(mailcheck.check, domain)
    except mailcheck.DnsError as exc:
        console.print(f"[warn]Email check skipped — DNS-over-HTTPS unreachable: {exc}[/warn]")
        return
    except Exception as exc:  # noqa: BLE001 - a posture check must never fail the scan
        console.print(f"[warn]Email check failed: {exc}[/warn]")
        return
    result.records.append(record)
    result.records.extend(found)
    style = {"protected": "ok", "partial": "warn"}.get(record.verdict, "err")
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    worst = sorted(found, key=lambda f: rank.get(f.severity, 4))
    reason = f" — {worst[0].name}" if worst else ""
    console.print(f"Email ({domain}): [{style}]{record.verdict}[/{style}]{reason}")


def _check_takeover(result: PipelineResult, *, animate: bool = True) -> None:
    """Flag subdomains with a dangling CNAME to an unclaimed third-party service."""
    hosts = takeovercheck.candidates(result.records)
    if not hosts:
        return
    try:
        total = min(len(hosts), 300)
        with motion.Activity(console, "Subdomain takeover", animate=animate, total=total,
                             detail="dangling CNAMEs") as activity:
            findings, notes = anyio.run(
                functools.partial(takeovercheck.scan, hosts, progress=activity.advance)
            )
    except Exception as exc:  # noqa: BLE001 - a posture check must never fail the scan
        console.print(f"[warn]Subdomain-takeover check failed: {escape(str(exc))}[/warn]")
        return
    result.records.extend(findings)
    for note in notes:
        console.print(f"[warn]Takeover: {escape(note)}[/warn]")
    if findings:
        hosts_hit = ", ".join(sorted({f.target.split("//", 1)[-1] for f in findings})[:3])
        console.print(f"Subdomain takeover: [err]{len(findings)} possible[/err] — {escape(hosts_hit)}")
    else:
        console.print(f"Subdomain takeover: [ok]none[/ok] in {len(hosts)} host(s)")


def _enrich_with_intel(result: PipelineResult, cache_dir: Path, *, animate: bool = True) -> None:
    """Rate CVE findings by real-world exploitation (CISA KEV, EPSS, Exploit-DB)."""
    if not any(threatintel.cve_ids(r) for r in result.records if r.kind == "vuln"):
        return
    console.print("[muted]Threat intel: checking CVEs against CISA KEV, EPSS and Exploit-DB…[/muted]")
    try:
        with motion.Activity(console, "Rating CVEs", animate=animate, detail="KEV · EPSS · Exploit-DB"):
            summary = anyio.run(threatintel.enrich, result.records, cache_dir)
    except Exception as exc:  # noqa: BLE001 - intel must never fail the scan
        console.print(f"[warn]Threat intel failed: {exc}[/warn]")
        return
    for error in summary.errors:
        console.print(f"[warn]Threat intel — {error}[/warn]")
    parts = [f"{summary.cves} CVE(s) in {summary.findings} finding(s)"]
    if summary.exploited:
        parts.append(f"[err]{summary.exploited} exploited in the wild (CISA KEV)[/err]")
    if summary.exploits:
        parts.append(f"{summary.exploits} with a public exploit")
    if summary.likely:
        parts.append(f"{summary.likely} with EPSS ≥ {threatintel.EPSS_HIGH:.0%}")
    console.print("Threat intel: " + " · ".join(parts))


def _enrich_with_vt(result: PipelineResult, api_key: str, limit: int, *, animate: bool = True) -> None:
    """Append VirusTotal reputation records for the run's discovered targets."""
    targets = vt.enrichment_targets(result.records)
    if not targets:
        return
    count = min(len(targets), limit)
    console.print(f"[muted]VirusTotal: looking up {count} target(s), throttled to 4/min…[/muted]")
    try:
        # At the free tier's 4/min this can take minutes: a live counter, not silence.
        with motion.Activity(console, "VirusTotal", animate=animate, total=count,
                             detail="free tier: 4 lookups/min") as activity:
            reps = anyio.run(functools.partial(vt.enrich, targets, api_key, limit, progress=activity.advance))
    except Exception as exc:  # noqa: BLE001 - enrichment must never fail the scan
        console.print(f"[warn]VirusTotal enrichment failed: {exc}[/warn]")
        return
    for index, rep in enumerate(reps, 1):
        result.records.append(validate_record("virustotal", json.dumps(rep.as_record()), index))
    flagged = sum(1 for rep in reps if rep.flagged)
    console.print(f"[muted]VirusTotal: {len(reps)} looked up, {flagged} flagged.[/muted]")


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
        if target is not None:
            adapter_class(tool).validate_target(target)
    except ValueError as exc:
        console.print(f"[err]{exc}[/err]")
        raise typer.Exit(2) from exc
    except CyberfwError as exc:
        console.print(f"[err]{exc}[/err]")
        raise typer.Exit(1) from exc
    try:
        # Validate the binary is installed so we can offer a targeted hint.
        manager.binary_path(tool)
    except ToolNotFoundError as exc:
        console.print(f"[err]{exc}[/err]")
        console.print("[warn]Run `cyberfw init` first (or export CYBERFW_GITHUB_TOKEN).[/warn]")
        raise typer.Exit(1) from exc
    except CyberfwError as exc:
        console.print(f"[err]{exc}[/err]")
        raise typer.Exit(1) from exc

    session_id = session or _session_tag("run", tool)
    # Only --save streams into reports/<session>/ as records arrive (crash-safe).
    # Undecided runs write nothing until the user has answered, so an ad-hoc
    # `run` never litters the filesystem with a folder nobody asked for.
    context = SessionContext(settings.reports_dir, session_id) if save else None
    engine = PipelineEngine(settings, manager, context=context)

    hosts = _read_hosts(list_file) if list_file is not None else []
    ctx = ToolContext(
        target=target, inputs=hosts, extra_input=wordlist or settings.wordlist, controls=engine._controls()
    )
    target_label = target or f"{len(hosts)} host(s) from {list_file}"
    console.print(f"[info]tool:[/info] [tool]{tool}[/tool]  [info]target:[/info] {target_label}")

    # Parsing is on by default; disable it via the config `parse:` setting
    # (CYBERFW_PARSE=false) or override per-run with --no-parse.
    do_parse = settings.parse and not no_parse

    # Timed here, around the process, so a saved report's duration is the
    # tool's — not the instant the user answered the save prompt.
    started_at = datetime.now(timezone.utc)
    if not do_parse:
        why = "--no-parse" if no_parse else "config parse=false"
        console.print(f"[muted]{why}: streaming raw stdout/stderr exactly as the tool prints it[/muted]")

        async def _print_stdout(record: ToolRecord) -> None:
            console.print(record.raw)

        async def _print_stderr(line: str) -> None:
            console.print(line, style="dim")

        engine.set_record_callback(_print_stdout)
        engine.set_stderr_callback(_print_stderr)
        try:
            node_result, records = anyio.run(_run_single, engine, ctx, tool, False)
        finally:
            manager.close()
        console.print(f"[info]{len(records)} line(s) captured[/info]")
    else:
        view = PipelineLiveView(
            [Node(tool=tool, stage=tool)], title=f"{tool} · {target_label}", animate=settings.animations
        )
        # The view is a renderable (``__rich__``) on auto-refresh: callbacks only
        # change its state, and the spinner, bars and timer move between them.
        with Live(view, console=console, refresh_per_second=_live_fps(settings), transient=False) as live:

            async def _on_record(record: ToolRecord) -> None:
                view.on_record(record)

            async def _on_stage(event: StageEvent) -> None:
                view.on_stage(event)

            engine.set_record_callback(_on_record)
            engine.set_stage_callback(_on_stage)
            try:
                node_result, records = anyio.run(_run_single, engine, ctx, tool, True)
            finally:
                manager.close()
                view.finish()
                live.refresh()
        _after_live()
        if records:
            console.print(_record_table(records, tool=tool, target=target_label))
        else:
            console.print("[muted]No records found.[/muted]")
    finished_at = datetime.now(timezone.utc)

    if context is not None:
        context.close()
    # --save decided up front (and streamed the records as they came); an
    # undecided run asks now, and only when there is something to keep.
    if save or (save is None and records and _wants_to_save(save, default=False, what=tool)):
        result = PipelineResult(
            nodes=[node_result],
            records=records,
            started_at=started_at,
            finished_at=finished_at,
        )
        if context is None:
            # Nothing was streamed, so archive the records now.
            with SessionContext(settings.reports_dir, session_id) as store:
                for record in records:
                    store.append(tool, record)
        written = _write_reports(
            result,
            session_id=session_id,
            settings=settings,
            run=_run_info(manager, name=tool, seed=target, session_id=session_id, tools={tool}),
        )
        console.print(f"[ok]saved:[/ok] {settings.reports_dir / session_id}")
        for label, path in written:
            console.print(f"[ok]{label}:[/ok] {path}")

    if not node_result.ok:
        console.print(f"[err]{node_result.error or 'stage failed'}[/err]")
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
    include_gowitness = _resolve_gowitness(gowitness, manager, settings.tools_dir)
    try:
        nodes = build(
            name,
            pipelines_dir=settings.pipelines_dir,
            include_ffuf=ffuf,
            include_gowitness=include_gowitness,
            max_httpx=max_httpx,
        )
        for node in nodes:  # a YAML pipeline may name a tool the registry (or the code) lacks
            manager.spec(node.tool)
            adapter_class(node.tool)
    except RegistryError as exc:
        console.print(f"[err]{exc}[/err]")
        manager.close()
        raise typer.Exit(2) from exc

    # Whether the run can happen at all is knowable now, and a scan takes
    # minutes: report what is unavailable up front instead of spending the
    # time only to say that a stage never ran.
    blocking, dep_warnings = _preflight(manager, nodes, settings.tools_dir)
    if plan:
        console.print(_plan_view(manager, name, target, nodes, blocking, dep_warnings, settings.tools_dir))
        manager.close()
        return
    assert target is not None  # a non-plan run required --target above; narrows for the scan path
    for warning in dep_warnings:
        console.print(f"[warn]{warning}[/warn]")
    if blocking and not force_start:
        for stage, tool, reason in blocking:
            console.print(f"[err]{tool}[/err] ({stage}): [err]{reason}[/err]")
        console.print(
            "[warn]Fix the above (`cyberfw init`, `cyberfw status`), "
            "or pass --force-start to run the stages that can.[/warn]"
        )
        manager.close()
        raise typer.Exit(2)

    wordlist = wordlist or settings.wordlist
    if ffuf and not wordlist:
        bundled = default_wordlist()
        if bundled is not None:
            console.print(
                f"[muted]--ffuf: no wordlist given, using the bundled {bundled.name} "
                "(pass --wordlist <path> to override)[/muted]"
            )
        else:
            console.print(
                "[warn]--ffuf needs a wordlist and the bundled default was not found; "
                "the fuzz stage will be skipped. Re-run with --wordlist <path>.[/warn]"
            )
    session_id = session or _session_tag("pipeline", name)
    # Remember whether the directory is ours: declining to save may remove it,
    # and a --session pointing at an earlier run must never be deleted.
    session_dir = settings.reports_dir / session_id
    session_is_new = not session_dir.exists()
    context = SessionContext(settings.reports_dir, session_id)
    # The pre-flight above already reported any missing optional dependency.
    engine = PipelineEngine(settings, manager, context=context, report_missing_deps=False)

    # Verbose view when parsing is disabled (config parse=false or --no-parse):
    # stream each stage's raw stdout/stderr live instead of the quiet spinner.
    # Stages are still parsed internally so results thread from one to the next.
    verbose = no_parse or not settings.parse
    run_engine = functools.partial(engine.run, extra_input=wordlist)
    # The flag overrides the `view` setting for this run; unset falls back to it.
    use_topology = topology if topology is not None else settings.view == "topology"
    if topology is True and verbose:
        # Only when the user explicitly asked: the config default silently yields
        # to the raw stream under --no-parse rather than nagging every run.
        why = "--no-parse" if no_parse else "config parse=false"
        console.print(f"[warn]--topology needs the parsed view; ignored under {why}.[/warn]")
    if verbose:
        why = "--no-parse" if no_parse else "config parse=false"
        console.print(f"[muted]{why}: streaming raw stdout/stderr from every stage[/muted]")

        async def _print_stdout(line: str) -> None:
            console.print(line)

        async def _print_stderr(line: str) -> None:
            console.print(line, style="dim")

        engine.set_stdout_raw_callback(_print_stdout)
        engine.set_stderr_callback(_print_stderr)
        try:
            result = anyio.run(run_engine, nodes, target)
        except CyberfwError as exc:
            console.print(f"[err]{exc}[/err]")
            raise typer.Exit(1) from exc
        finally:
            manager.close()
    else:
        # The live view IS the final frame, so it is not reprinted afterwards:
        # Live leaves its last frame on screen. On a non-TTY (CI, a pipe) Rich
        # prints that final frame once instead of redrawing.
        #
        # Both views are renderable objects (``__rich__``) driven by
        # auto-refresh, so spinners, bars, timers and the growth pulse animate
        # between events — callbacks only mutate state.
        view: PipelineLiveView | TopologyView
        if use_topology:
            view = TopologyView(nodes, seed=target, title=f"{name} · {target}", animate=settings.animations)
        else:
            view = PipelineLiveView(nodes, title=f"pipeline {name} · {target}", animate=settings.animations)
        with Live(view, console=console, refresh_per_second=_live_fps(settings), transient=False) as live:

            async def _on_record(record: ToolRecord) -> None:
                view.on_record(record)

            async def _on_stage(event: StageEvent) -> None:
                view.on_stage(event)

            engine.set_record_callback(_on_record)
            engine.set_stage_callback(_on_stage)
            try:
                result = anyio.run(run_engine, nodes, target)
            except CyberfwError as exc:
                console.print(f"[err]{exc}[/err]")
                raise typer.Exit(1) from exc
            finally:
                manager.close()
                view.finish()
                live.refresh()
        _after_live()

    if result.excluded:
        console.print(f"[muted]scope: {len(result.excluded)} host(s) excluded[/muted]")

    animate = settings.animations
    _check_tls(result)
    if mail:
        _check_mail(result, target, animate=animate)
    if takeover:
        _check_takeover(result, animate=animate)
    if intel:
        _enrich_with_intel(result, settings.cache_dir, animate=animate)
    if vt_key:
        _enrich_with_vt(result, vt_key, vt_limit, animate=animate)

    _apply_triage(result, settings.triage_file)
    run_info = _run_info(manager, name=name, seed=target, session_id=session_id, tools={n.tool for n in nodes})
    changes = None if no_baseline else _compare_with_earlier(result, run_info, settings.reports_dir, baseline)

    if verbose:
        console.print(_node_table(result))

    context.close()
    written: list[tuple[str, Path]] = []
    if _wants_to_save(report, default=True, what=name):
        try:
            written = _write_reports(
                result, session_id=session_id, settings=settings, run=run_info, changes=changes
            )
        except CyberfwError as exc:
            console.print(f"[err]report failed:[/err] {exc}")
            return
    else:
        _discard_session(session_dir, created=session_is_new)

    # A blank line: Live's last frame ends without one, so the panel would
    # otherwise start on the same line as the table's bottom edge.
    console.print()
    motion.play(
        console,
        lambda progress: _run_summary(
            result, name=name, session_id=session_id, reports=written, progress=progress
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


# -- async helpers for anyio --------------------------------------------------------------------
async def _run_single(
    engine: PipelineEngine, ctx: ToolContext, tool: str, parse: bool
) -> tuple[NodeResult, list[ToolRecord]]:
    """Run one tool stage through the engine (handles fan-out and crashes)."""
    return await engine.run_single(Node(tool=tool, stage=tool), ctx, parse=parse)
