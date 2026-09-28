"""Message rendering: severity mix, top findings, and HTML-escaping of hostile text."""

from __future__ import annotations

from _helpers import SAMPLE_REPORT
from cyberfw_bot.formatting import status_message, summary_message
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


def test_status_lists_scans_or_says_empty() -> None:
    assert "No scans yet" in status_message([])
    assert "ab12" in status_message([_scan()])
