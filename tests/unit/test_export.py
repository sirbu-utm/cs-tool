"""Exporting a saved report.json to SARIF and CSV (cyberfw.report.sarif / csv_report)."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from cyberfw.report.csv_report import to_csv
from cyberfw.report.sarif import to_sarif


def _payload() -> dict[str, Any]:
    return {
        "ok": True,
        "run": {"cyberfw_version": "9.9.9", "pipeline": "recon-to-vuln", "seed": "example.com"},
        "stages": [],
        "total_records": 5,
        "records": [
            {
                "tool": "nuclei", "kind": "vuln", "target": "https://a.example.com/x",
                "template_id": "xss", "matched_at": "https://a.example.com/x",
                "info": {"name": "Reflected XSS", "severity": "critical", "description": "reflected input"},
            },
            {
                "tool": "tlscheck", "kind": "vuln", "target": "https://a.example.com",
                "template_id": "tls-cert-expiring", "matched_at": "https://a.example.com",
                "info": {"name": "Certificate expiring soon", "severity": "medium"},
            },
            {
                "tool": "nuclei", "kind": "vuln", "target": "https://a.example.com/i",
                "template_id": "tech-detect", "matched_at": "https://a.example.com/i",
                "info": {"name": "Tech detect", "severity": "info"}, "muted": {"reason": "false_positive", "rule": "m1"},
            },
            {
                "tool": "gitleaks", "kind": "secret", "target": "/repo/leak.txt",
                "rule_id": "aws-access-key", "description": "AWS access key",
            },
            {"tool": "subfinder", "kind": "host", "target": "a.example.com", "host": "a.example.com"},
        ],
    }


class TestSarif:
    def test_is_valid_sarif_210_with_a_cyberfw_driver(self) -> None:
        doc = to_sarif(_payload())
        # round-trips as JSON (the CLI dumps this to stdout / a file)
        doc = json.loads(json.dumps(doc))

        assert doc["version"] == "2.1.0" and "$schema" in doc
        driver = doc["runs"][0]["tool"]["driver"]
        assert driver["name"] == "cyberfw" and driver["version"] == "9.9.9"

    def test_only_findings_become_results(self) -> None:
        results = to_sarif(_payload())["runs"][0]["results"]
        # the host record is not a problem; the four findings are
        assert len(results) == 4
        assert all("subfinder" not in json.dumps(r) for r in results)

    def test_severity_maps_to_a_sarif_level(self) -> None:
        results = to_sarif(_payload())["runs"][0]["results"]
        by_rule = {r["ruleId"]: r for r in results}
        assert by_rule["xss"]["level"] == "error"  # critical
        assert by_rule["tls-cert-expiring"]["level"] == "warning"  # medium
        assert by_rule["tech-detect"]["level"] == "note"  # info
        assert by_rule["aws-access-key"]["level"] == "error"  # a leaked secret

    def test_result_carries_message_and_location(self) -> None:
        xss = next(r for r in to_sarif(_payload())["runs"][0]["results"] if r["ruleId"] == "xss")
        assert "Reflected XSS" in xss["message"]["text"]
        assert xss["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "https://a.example.com/x"

    def test_rules_are_deduped_by_id(self) -> None:
        driver = to_sarif(_payload())["runs"][0]["tool"]["driver"]
        rule_ids = [rule["id"] for rule in driver["rules"]]
        assert sorted(rule_ids) == ["aws-access-key", "tech-detect", "tls-cert-expiring", "xss"]
        assert len(rule_ids) == len(set(rule_ids))


class TestCsv:
    def test_every_record_is_a_row(self) -> None:
        rows = list(csv.DictReader(io.StringIO(to_csv(_payload()))))
        assert len(rows) == 5  # all records, not just findings
        assert rows[0]["tool"] == "nuclei" and rows[-1]["tool"] == "subfinder"

    def test_columns_cover_severity_detail_and_muted(self) -> None:
        rows = list(csv.DictReader(io.StringIO(to_csv(_payload()))))
        xss = rows[0]
        assert xss["severity"] == "critical" and xss["detail"] == "Reflected XSS"
        assert xss["muted"] == "false"
        muted = next(r for r in rows if r["target"] == "https://a.example.com/i")
        assert muted["muted"] == "true"

    def test_header_is_the_documented_columns(self) -> None:
        header = next(csv.reader(io.StringIO(to_csv(_payload()))))
        assert header == ["tool", "kind", "severity", "target", "detail", "muted"]
