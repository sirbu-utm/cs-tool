"""The checks after a scan — TLS, mail, takeover, threat intel, VirusTotal — without printing.

Each step adds its records to the run's result and reports through the
observer: ``start``, then any notes, then ``done`` — sent even when the step
fails or is interrupted. None of them ever fails the scan: a step that cannot
finish sends a warning :class:`~cyberfw.core.events.Note` instead.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import anyio

from cyberfw import threatintel, vt
from cyberfw.config import Settings
from cyberfw.core.events import (
    MailSummary,
    Note,
    RunObserver,
    StepEvent,
    StepName,
    StepSummary,
    TakeoverSummary,
    TlsSummary,
    VtSummary,
)
from cyberfw.pipeline.engine import PipelineResult
from cyberfw.pipeline.schemas import validate_record
from cyberfw.posture import mail as mailcheck
from cyberfw.posture import takeover as takeovercheck
from cyberfw.posture import tls as tlscheck

#: The most subdomains the takeover check looks at in one run.
_TAKEOVER_LIMIT = 300
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _advance(observer: RunObserver, step: StepName, total: int) -> Callable[[int], None]:
    """A ``progress`` callback that reports how many units of ``step`` are finished."""
    return lambda completed: observer.on_step(StepEvent("advance", step, total=total, completed=completed))


def check_tls(result: PipelineResult, observer: RunObserver) -> None:
    """Certificate health from what httpx's -tls-grab already collected (no network)."""
    certs = tlscheck.certificates(result.records)
    if not certs:
        return
    summary: StepSummary | None = None
    observer.on_step(StepEvent("start", "tls"))
    try:
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
        summary = TlsSummary(certificates=len(certs), expired=expired, soon=soon, untrusted=untrusted)
    finally:
        observer.on_step(StepEvent("done", "tls", summary=summary))


def check_mail(result: PipelineResult, seed: str, observer: RunObserver) -> None:
    """Whether mail can be forged as the seed domain (SPF / DMARC over DNS-over-HTTPS)."""
    domain = mailcheck.mail_domain(seed)
    if domain is None:
        return
    summary: StepSummary | None = None
    observer.on_step(StepEvent("start", "mail", subject=domain))
    try:
        record, found = anyio.run(mailcheck.check, domain)
        result.records.append(record)
        result.records.extend(found)
        worst = min(found, key=lambda f: _SEVERITY_RANK.get(f.severity, 4)).name if found else None
        summary = MailSummary(domain=domain, verdict=record.verdict, worst=worst)
    except mailcheck.DnsError as exc:
        observer.on_note(Note("warn", f"Email check skipped — DNS-over-HTTPS unreachable: {exc}"))
    except Exception as exc:  # noqa: BLE001 - a posture check must never fail the scan
        observer.on_note(Note("warn", f"Email check failed: {exc}"))
    finally:
        observer.on_step(StepEvent("done", "mail", summary=summary))


def check_takeover(result: PipelineResult, observer: RunObserver) -> None:
    """Flag subdomains with a dangling CNAME to an unclaimed third-party service."""
    hosts = takeovercheck.candidates(result.records)
    if not hosts:
        return
    total = min(len(hosts), _TAKEOVER_LIMIT)
    summary: StepSummary | None = None
    observer.on_step(StepEvent("start", "takeover", total=total))
    try:
        findings, notes = anyio.run(
            functools.partial(takeovercheck.scan, hosts, progress=_advance(observer, "takeover", total))
        )
        result.records.extend(findings)
        for note in notes:
            observer.on_note(Note("warn", f"Takeover: {note}"))
        hit = tuple(sorted({f.target.split("//", 1)[-1] for f in findings})[:3])
        summary = TakeoverSummary(checked=len(hosts), possible=len(findings), hosts=hit)
    except Exception as exc:  # noqa: BLE001 - a posture check must never fail the scan
        observer.on_note(Note("warn", f"Subdomain-takeover check failed: {exc}"))
    finally:
        observer.on_step(StepEvent("done", "takeover", summary=summary))


def rate_cves(result: PipelineResult, cache_dir: Path, observer: RunObserver) -> None:
    """Rate CVE findings by real-world exploitation (CISA KEV, EPSS, Exploit-DB)."""
    if not any(threatintel.cve_ids(r) for r in result.records if r.kind == "vuln"):
        return
    summary: StepSummary | None = None
    observer.on_step(StepEvent("start", "intel"))
    try:
        rated = anyio.run(threatintel.enrich, result.records, cache_dir)
        for error in rated.errors:
            observer.on_note(Note("warn", f"Threat intel — {error}"))
        summary = rated
    except Exception as exc:  # noqa: BLE001 - intel must never fail the scan
        observer.on_note(Note("warn", f"Threat intel failed: {exc}"))
    finally:
        observer.on_step(StepEvent("done", "intel", summary=summary))


def enrich_vt(result: PipelineResult, api_key: str, limit: int, observer: RunObserver) -> None:
    """Append VirusTotal reputation records for the run's discovered targets."""
    targets = vt.enrichment_targets(result.records)
    if not targets:
        return
    count = min(len(targets), limit)
    summary: StepSummary | None = None
    observer.on_step(StepEvent("start", "vt", total=count))
    try:
        reps = anyio.run(
            functools.partial(vt.enrich, targets, api_key, limit, progress=_advance(observer, "vt", count))
        )
        for index, rep in enumerate(reps, 1):
            result.records.append(validate_record("virustotal", json.dumps(rep.as_record()), index))
        summary = VtSummary(looked_up=len(reps), flagged=sum(1 for rep in reps if rep.flagged))
    except Exception as exc:  # noqa: BLE001 - enrichment must never fail the scan
        observer.on_note(Note("warn", f"VirusTotal enrichment failed: {exc}"))
    finally:
        observer.on_step(StepEvent("done", "vt", summary=summary))


def post_scan(
    result: PipelineResult,
    *,
    seed: str,
    settings: Settings,
    mail: bool,
    takeover: bool,
    intel: bool,
    vt_key: str | None,
    vt_limit: int,
    observer: RunObserver,
) -> None:
    """The checks after the scan, in order: TLS always, the others when asked for
    (VirusTotal only with a key). Each adds its records to ``result``."""
    check_tls(result, observer)
    if mail:
        check_mail(result, seed, observer)
    if takeover:
        check_takeover(result, observer)
    if intel:
        rate_cves(result, settings.cache_dir, observer)
    if vt_key:
        enrich_vt(result, vt_key, vt_limit, observer)
