"""Summarising cyberfw's report.json into severity counts and ranked findings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from _helpers import SAMPLE_REPORT
from cyberfw_bot.reports import ReportError, load_summary, summarize


def test_counts_by_severity_and_folds_unknown() -> None:
    summary = summarize(SAMPLE_REPORT)
    assert summary.severity_counts["critical"] == 1
    assert summary.severity_counts["medium"] == 1
    assert summary.severity_counts["unknown"] == 1  # "bananas" is not a known severity
    assert summary.total_findings == 3
    assert summary.has_serious is True


def test_recon_totals_and_duration() -> None:
    summary = summarize(SAMPLE_REPORT)
    assert summary.subdomains == 2
    assert summary.live_hosts == 1
    assert summary.duration_s == 12.5


def test_findings_sorted_most_severe_first() -> None:
    summary = summarize(SAMPLE_REPORT)
    assert [f.severity for f in summary.findings] == ["critical", "medium", "unknown"]
    assert summary.findings[0].name == "Critical RCE"
    assert summary.findings[0].target == "https://a.example.com/admin"


def test_load_summary_reads_a_file(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(json.dumps(SAMPLE_REPORT), encoding="utf-8")
    assert load_summary(report).total_findings == 3


def test_load_summary_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ReportError):
        load_summary(tmp_path / "nope.json")


def test_exploited_findings_rank_first_and_carry_their_intel() -> None:
    report = {"ok": True, "records": [
        {"kind": "vuln", "template_id": "crit", "info": {"name": "Plain critical", "severity": "critical"}},
        {"kind": "vuln", "template_id": "CVE-2021-44228", "info": {"name": "Log4Shell", "severity": "medium"},
         "intel": {"kev": True, "epss": 0.944, "exploits": ["50592"]}},
        {"kind": "vuln", "template_id": "y", "info": {"name": "Odd intel", "severity": "low"},
         "intel": {"epss": "not-a-number"}},
    ]}
    summary = summarize(report)
    first = summary.findings[0]
    assert first.name == "Log4Shell"  # KEV outranks a plain critical
    assert first.kev and first.epss == 0.944 and first.exploit
    assert summary.findings[1].name == "Plain critical"
    assert summary.findings[2].epss is None  # junk EPSS is ignored, not a crash
    assert summary.exploited == 1


def test_report_without_findings_is_not_serious() -> None:
    summary = summarize({"ok": True, "records": [{"tool": "httpx", "kind": "http", "target": "x"}]})
    assert summary.total_findings == 0
    assert summary.has_serious is False
