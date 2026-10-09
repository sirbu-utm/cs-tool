"""Message rendering: severity mix, top findings, and HTML-escaping of hostile text."""

from __future__ import annotations

from _helpers import SAMPLE_REPORT
from cyberfw_bot.formatting import (
    UNKNOWN_COMMAND_TEXT,
    UNRECOGNIZED_TEXT,
    animation_frame,
    did_you_mean_text,
    failed_message,
    queued_message,
    status_message,
    summary_message,
)
from cyberfw_bot.models import Finding, Scan, Summary
from cyberfw_bot.reports import summarize


def _scan() -> Scan:
    return Scan(id="ab12", user_id=1, chat_id=1, target="example.com", status="done")


def test_summary_lists_counts_and_top_findings() -> None:
    text = summary_message(_scan(), summarize(SAMPLE_REPORT), max_findings=10)
    assert "critical <b>1</b>" in text
    assert "Critical RCE" in text
    assert "example.com" in text


def test_summary_caps_the_list_and_says_how_many_more() -> None:
    findings = [Finding(name=f"f{i}", severity="high", target="t", template_id="x") for i in range(15)]
    summary = Summary(ok=True, severity_counts={"high": 15}, findings=findings)
    text = summary_message(_scan(), summary, max_findings=10)
    assert "and 5 more" in text


def test_finding_text_is_html_escaped() -> None:
    evil = Finding(name="<script>alert(1)</script>", severity="high", target="<b>x</b>", template_id="x")
    summary = Summary(ok=True, severity_counts={"high": 1}, findings=[evil])
    text = summary_message(_scan(), summary, max_findings=10)
    assert "<script>" not in text
    assert "&lt;script&gt;" in text


def test_failed_message_escapes_the_scanner_error() -> None:
    """scan.error is scanner stderr — a scanned server can shape it, so it must be escaped."""
    scan = Scan(
        id="ab12",
        user_id=1,
        chat_id=1,
        target="example.com",
        status="failed",
        error="<b>boom</b> <script>x</script>",
    )
    text = failed_message(scan)
    assert "<script>" not in text
    assert "&lt;script&gt;" in text


def test_queued_message_names_the_scan_and_target() -> None:
    text = queued_message(_scan())
    assert "ab12" in text
    assert "example.com" in text


def test_status_lists_scans_or_says_empty() -> None:
    assert "No scans yet" in status_message([])
    assert "ab12" in status_message([_scan()])


def test_did_you_mean_suggests_the_scan_command_and_escapes_target() -> None:
    text = did_you_mean_text("a&b.com")
    assert "/scan a&amp;b.com" in text
    assert "a&b.com" not in text  # raw ampersand must be escaped


def test_fallback_texts_point_at_help() -> None:
    assert "/help" in UNKNOWN_COMMAND_TEXT
    assert "/help" in UNRECOGNIZED_TEXT


def test_animation_frame_queued_names_scan_and_target() -> None:
    text = animation_frame("queued", "example.com", "ab12", tick=0, elapsed_s=0)
    assert "ab12" in text
    assert "example.com" in text


def test_animation_frame_running_shows_elapsed_and_cycles_spinner() -> None:
    first = animation_frame("running", "example.com", "ab12", tick=0, elapsed_s=12)
    second = animation_frame("running", "example.com", "ab12", tick=1, elapsed_s=12)
    assert "12s" in first
    assert first[0] != second[0]  # spinner advances with the tick


def test_animation_frame_spinner_wraps_on_tick() -> None:
    a = animation_frame("running", "example.com", "ab12", tick=0, elapsed_s=0)
    b = animation_frame("running", "example.com", "ab12", tick=4, elapsed_s=0)
    assert a[0] == b[0]  # 4 spinner frames → tick 0 and 4 share the same emoji


def test_animation_frame_escapes_target() -> None:
    text = animation_frame("running", "a&b.com", "ab12", tick=0, elapsed_s=0)
    assert "a&amp;b.com" in text
    assert "a&b.com" not in text


def test_summary_flags_findings_exploited_in_the_wild() -> None:
    findings = [
        Finding(name="Log4Shell", severity="medium", target="t", template_id="CVE-2021-44228",
                kev=True, epss=0.944, exploit=True),
        Finding(name="Unlikely", severity="high", target="t", template_id="x", epss=0.01),
    ]
    summary = Summary(ok=True, severity_counts={"medium": 1, "high": 1}, findings=findings)
    text = summary_message(_scan(), summary, max_findings=10)
    assert "🔥 <b>1</b> exploited in the wild (CISA KEV)" in text
    assert "🔥 <b>exploited in the wild</b> · EPSS 94% · public exploit" in text
    assert "EPSS 1%" not in text  # a low EPSS is noise in a chat
    assert "exploited" not in summary_message(_scan(), summarize(SAMPLE_REPORT), max_findings=10)


def test_epss_near_certainty_is_not_shown_as_100_percent() -> None:
    hot = Finding(name="x", severity="critical", target="t", template_id="CVE-1", epss=0.99999)
    text = summary_message(_scan(), Summary(ok=True, severity_counts={"critical": 1}, findings=[hot]), 10)
    assert "EPSS &gt;99.9%" in text and "EPSS 100%" not in text  # escaped for Telegram HTML


def test_status_line_counts_exploited_findings() -> None:
    hot = Finding(name="x", severity="critical", target="t", template_id="CVE-1", kev=True)
    scan = _scan()
    scan.summary = Summary(ok=True, severity_counts={"critical": 1}, findings=[hot])
    assert "🔥 1 exploited" in status_message([scan])


def test_vt_message_renders_a_malicious_hit() -> None:
    from cyberfw_bot.formatting import vt_message

    text = vt_message({
        "target": "evil.com", "found": True, "malicious": 5, "suspicious": 1,
        "harmless": 60, "reputation": -30, "categories": ["malware", "phishing"],
        "permalink": "https://www.virustotal.com/gui/domain/evil.com",
    })
    assert "evil.com" in text and "malicious" in text and "🟥" in text
    assert "5</b> malicious" in text
    assert "malware, phishing" in text


def test_vt_message_handles_not_found() -> None:
    from cyberfw_bot.formatting import vt_message

    assert "not seen" in vt_message({"target": "clean.com", "found": False})
