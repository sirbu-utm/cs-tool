"""Render scans and summaries as Telegram-ready HTML text.

Kept apart from the handlers so the wording is unit-testable without a bot. All
dynamic values are HTML-escaped: a finding name or target ultimately comes from
a scanned server's response and must never be trusted as markup.
"""

from __future__ import annotations

from html import escape

from cyberfw_bot.models import SEVERITY_ORDER, Finding, Scan, Summary

__all__ = [
    "summary_message",
    "failed_message",
    "queued_message",
    "scan_line",
    "status_message",
    "animation_frame",
    "did_you_mean_text",
    "vt_message",
    "HELP_TEXT",
    "UNKNOWN_COMMAND_TEXT",
    "UNRECOGNIZED_TEXT",
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


#: EPSS worth calling out in a chat (same threshold as cyberfw.threatintel.EPSS_HIGH).
_EPSS_HIGH = 0.1


def _intel_marks(finding: Finding) -> str:
    """A line saying why a finding is urgent (KEV / high EPSS / public exploit), or ""."""
    marks = []
    if finding.kev:
        marks.append("🔥 <b>exploited in the wild</b>")
    if finding.epss is not None and finding.epss >= _EPSS_HIGH:
        pct = finding.epss * 100  # never round up to "100%": EPSS stops short of certainty
        # (&gt; — Telegram's HTML mode rejects a bare ">")
        marks.append("EPSS &gt;99.9%" if pct >= 99.9 else f"EPSS {min(pct, 99.0):.0f}%")
    if finding.exploit:
        marks.append("public exploit")
    return ("\n   " + " · ".join(marks)) if marks else ""


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
    if summary.exploited:
        lines.append(
            f"🔥 <b>{summary.exploited}</b> exploited in the wild (CISA KEV) — fix these first"
        )
    if summary.findings:
        lines.append("")
        lines.append(f"<b>Top {min(max_findings, len(summary.findings))} findings</b>:")
        for finding in summary.findings[:max_findings]:
            emoji = _SEVERITY_EMOJI.get(finding.severity, "▫️")
            lines.append(
                f"{emoji} <b>{escape(finding.severity)}</b> — {escape(finding.name)}\n"
                f"   <code>{escape(finding.target)}</code>{_intel_marks(finding)}"
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
        if scan.summary.exploited:
            detail += f" · 🔥 {scan.summary.exploited} exploited"
    return f"{icon} <code>{escape(scan.id)}</code> {escape(scan.target)} ({escape(scan.status)}){detail}"


def status_message(scans: list[Scan]) -> str:
    if not scans:
        return "No scans yet. Start one with <code>/scan example.com</code>."
    return "<b>Your recent scans</b>:\n" + "\n".join(scan_line(s) for s in scans)


#: Spinner frames cycled while a scan runs (see :func:`animation_frame`).
_SPINNER = ("🛰️", "📡", "🔭", "🔎")


def animation_frame(status: str, target: str, scan_id: str, tick: int, elapsed_s: int) -> str:
    """One frame of the in-chat waiting animation, edited into the queued message.

    ``queued`` shows a steady hourglass; ``running`` cycles a spinner by ``tick``
    and shows elapsed seconds. ``target`` is validated before a scan starts, but
    it is escaped here anyway — every dynamic value in a message is.
    """
    safe_id = escape(scan_id)
    safe_target = escape(target)
    if status == "queued":
        hourglass = ("⏳", "⌛")[tick % 2]
        return f"{hourglass} Queued <code>{safe_id}</code> — <b>{safe_target}</b>…"
    spinner = _SPINNER[tick % len(_SPINNER)]
    return f"{spinner} Scanning <code>{safe_id}</code> — <b>{safe_target}</b> … {elapsed_s}s"


def did_you_mean_text(target: str) -> str:
    """Nudge a plain message that looks like a host toward the real command."""
    safe = escape(target)
    return f"🤔 Did you mean <code>/scan {safe}</code>? Send that to scan <b>{safe}</b>."


def vt_message(data: dict[str, object]) -> str:
    """Render a VirusTotal lookup result (from ``cyberfw vt --json``) for a chat."""
    target = escape(str(data.get("target", "")))
    if not data.get("found", False):
        return f"🔍 <b>{target}</b> — not seen by VirusTotal"
    malicious = int(data.get("malicious", 0) or 0)
    suspicious = int(data.get("suspicious", 0) or 0)
    harmless = int(data.get("harmless", 0) or 0)
    icon, verdict = ("🟥", "malicious") if malicious else ("🟨", "suspicious") if suspicious else ("🟩", "clean")
    lines = [
        f"{icon} <b>{target}</b> — {verdict}",
        f"VT: <b>{malicious}</b> malicious · {suspicious} suspicious · {harmless} harmless "
        f"· reputation {int(data.get('reputation', 0) or 0)}",
    ]
    cats = data.get("categories") or []
    if isinstance(cats, list) and cats:
        lines.append("categories: " + escape(", ".join(str(c) for c in cats[:8])))
    link = str(data.get("permalink", ""))
    if link:
        lines.append(f'<a href="{escape(link)}">open on VirusTotal</a>')
    return "\n".join(lines)


UNKNOWN_COMMAND_TEXT = "🤷 I don't know that command. Send /help for the list of commands."

UNRECOGNIZED_TEXT = (
    "🤔 I only understand commands. Send /help for the list, "
    "or <code>/scan &lt;domain&gt;</code> to scan a host."
)


HELP_TEXT = (
    "<b>CS-TOOL bot</b> — recon + vulnerability scan via cyberfw.\n\n"
    "<b>/scan &lt;target&gt;</b> — scan one domain, http(s) URL or IP you are authorised to test\n"
    "<b>/status</b> — your recent scans and their state\n"
    "<b>/report &lt;scan_id&gt;</b> — re-send a finished scan's summary and report file\n"
    "<b>/vt &lt;target&gt;</b> — VirusTotal reputation of a domain/IP/URL/hash\n"
    "<b>/setvt &lt;key&gt;</b> — save your own VirusTotal API key (in DM); scans then add VT reputation\n"
    "<b>/help</b> — this message\n\n"
    "⚠️ Only scan assets you own or have explicit written permission to test. "
    "Active scanning of third-party systems without authorisation may be illegal."
)
