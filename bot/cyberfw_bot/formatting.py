"""Render scans and summaries as Telegram-ready HTML text.

Kept apart from the handlers so the wording is unit-testable without a bot. All
dynamic values are HTML-escaped: a finding name or target ultimately comes from
a scanned server's response and must never be trusted as markup.
"""

from __future__ import annotations

from html import escape

from cyberfw_bot.models import SEVERITY_ORDER, Scan, Summary

__all__ = [
    "summary_message",
    "failed_message",
    "queued_message",
    "scan_line",
    "status_message",
    "HELP_TEXT",
]

_SEVERITY_EMOJI = {
    "critical": "🟥",
    "high": "🟧",
    "medium": "🟨",
    "low": "🟦",
    "info": "⬜",
    "unknown": "▫️",
}


def _counts_line(summary: Summary) -> str:
    shown = [
        f"{_SEVERITY_EMOJI[sev]} {sev} <b>{summary.severity_counts.get(sev, 0)}</b>"
        for sev in SEVERITY_ORDER
        if summary.severity_counts.get(sev)
    ]
    return "  ".join(shown) if shown else "no vulnerabilities reported"


def summary_message(scan: Scan, summary: Summary, max_findings: int) -> str:
    """The message sent when a scan finishes: recon totals, severity mix, top findings."""
    lines = [
        f"✅ Scan <code>{escape(scan.id)}</code> finished — <b>{escape(scan.target)}</b>",
        (
            f"recon: {summary.subdomains} subdomain(s), {summary.live_hosts} live host(s)"
            + (f" · {summary.duration_s:.0f}s" if summary.duration_s is not None else "")
        ),
        f"findings: {_counts_line(summary)}",
    ]
    if summary.findings:
        lines.append("")
        lines.append(f"<b>Top {min(max_findings, len(summary.findings))} findings</b>:")
        for finding in summary.findings[:max_findings]:
            emoji = _SEVERITY_EMOJI.get(finding.severity, "▫️")
            lines.append(
                f"{emoji} <b>{escape(finding.severity)}</b> — {escape(finding.name)}\n"
                f"   <code>{escape(finding.target)}</code>"
            )
        extra = len(summary.findings) - max_findings
        if extra > 0:
            lines.append(f"…and {extra} more — see the attached report.")
    return "\n".join(lines)


def failed_message(scan: Scan) -> str:
    """The message for a scan that produced no usable report.

    ``scan.error`` is the scanner's stderr — text a scanned server can influence
    — so it is escaped like every other dynamic value, never trusted as markup.
    """
    error = (scan.error or "unknown error")[:500]
    return (
        f"❌ Scan <code>{escape(scan.id)}</code> failed — {escape(scan.target)}\n"
        f"<code>{escape(error)}</code>"
    )


def queued_message(scan: Scan) -> str:
    """The immediate reply to ``/scan`` once the scan is accepted."""
    return (
        f"🔍 Queued scan <code>{escape(scan.id)}</code> for <b>{escape(scan.target)}</b>. "
        "I'll message you when it's done."
    )


def scan_line(scan: Scan) -> str:
    """One line for the ``/status`` list."""
    icon = {"queued": "⏳", "running": "🔄", "done": "✅", "failed": "❌"}.get(scan.status, "•")
    detail = ""
    if scan.summary is not None:
        crit = scan.summary.severity_counts.get("critical", 0)
        high = scan.summary.severity_counts.get("high", 0)
        detail = f" — {crit} crit / {high} high"
    return f"{icon} <code>{escape(scan.id)}</code> {escape(scan.target)} ({escape(scan.status)}){detail}"


def status_message(scans: list[Scan]) -> str:
    if not scans:
        return "No scans yet. Start one with <code>/scan example.com</code>."
    return "<b>Your recent scans</b>:\n" + "\n".join(scan_line(s) for s in scans)


HELP_TEXT = (
    "<b>CS-TOOL bot</b> — recon + vulnerability scan via cyberfw.\n\n"
    "<b>/scan &lt;target&gt;</b> — scan one domain, http(s) URL or IP you are authorised to test\n"
    "<b>/status</b> — your recent scans and their state\n"
    "<b>/report &lt;scan_id&gt;</b> — re-send a finished scan's summary and report file\n"
    "<b>/help</b> — this message\n\n"
    "⚠️ Only scan assets you own or have explicit written permission to test. "
    "Active scanning of third-party systems without authorisation may be illegal."
)
