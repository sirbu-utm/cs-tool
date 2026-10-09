"""Turn cyberfw's ``report.json`` into a :class:`Summary` the bot can send.

The report schema is stable (see ``cyberfw/report/json_report.py``):
``{"ok", "run": {...}, "stages": [...], "records": [...]}``. nuclei findings are
the records with ``kind == "vuln"``; their severity lives in ``info.severity``,
and a finding that names a CVE may carry ``intel`` (CISA KEV / EPSS /
Exploit-DB, added by cyberfw after the scan).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cyberfw_bot.models import SEVERITY_ORDER, Finding, Summary

__all__ = ["ReportError", "load_summary", "summarize"]


class ReportError(RuntimeError):
    """The report file is missing or not the shape we expect."""


def load_summary(report_json: Path) -> Summary:
    """Read and summarise a ``report.json`` written by ``cyberfw pipeline``."""
    try:
        data = json.loads(report_json.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReportError(f"no report at {report_json}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ReportError(f"cannot read report {report_json}: {exc}") from exc
    if not isinstance(data, dict):
        raise ReportError("report is not a JSON object")
    return summarize(data)


def _severity_of(record: dict[str, Any]) -> str:
    info = record.get("info")
    sev = (info or {}).get("severity") if isinstance(info, dict) else None
    sev = str(sev or "unknown").lower()
    return sev if sev in SEVERITY_ORDER else "unknown"


def _intel_of(record: dict[str, Any]) -> tuple[bool, float | None, bool]:
    """``(kev, epss, exploit)`` from a finding's ``intel`` block, if any."""
    intel = record.get("intel")
    if not isinstance(intel, dict):
        return False, None, False
    try:
        epss = float(intel["epss"]) if intel.get("epss") is not None else None
    except (TypeError, ValueError):
        epss = None
    return bool(intel.get("kev")), epss, bool(intel.get("exploits"))


def _rank(finding: Finding) -> tuple[int, int, float, str]:
    """Exploited in the wild first, then by severity, then likelier (higher EPSS) first."""
    return (
        0 if finding.kev else 1,
        SEVERITY_ORDER.index(finding.severity),
        -(finding.epss or 0.0),
        finding.name,
    )


def summarize(report: dict[str, Any]) -> Summary:
    """Reduce a parsed report dict to severity counts and ranked findings."""
    records = report.get("records") or []
    counts: dict[str, int] = dict.fromkeys(SEVERITY_ORDER, 0)
    findings: list[Finding] = []
    subdomains = live_hosts = 0

    for record in records:
        if not isinstance(record, dict):
            continue
        kind = record.get("kind")
        if kind == "host":
            subdomains += 1
        elif kind == "http":
            live_hosts += 1
        elif kind == "vuln":
            severity = _severity_of(record)
            counts[severity] += 1
            info = record.get("info") if isinstance(record.get("info"), dict) else {}
            name = str(info.get("name") or record.get("template_id") or "finding")
            kev, epss, exploit = _intel_of(record)
            findings.append(
                Finding(
                    name=name,
                    severity=severity,
                    target=str(record.get("matched_at") or record.get("target") or ""),
                    template_id=str(record.get("template_id") or ""),
                    kev=kev,
                    epss=epss,
                    exploit=exploit,
                )
            )

    findings.sort(key=_rank)
    run = report.get("run") if isinstance(report.get("run"), dict) else {}
    return Summary(
        ok=bool(report.get("ok")),
        severity_counts=counts,
        findings=findings,
        subdomains=subdomains,
        live_hosts=live_hosts,
        duration_s=run.get("duration_s"),
    )
