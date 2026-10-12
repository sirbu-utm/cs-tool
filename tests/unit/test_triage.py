"""Triage: muting findings, rule matching, expiry and the YAML round-trip."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from cyberfw import triage
from cyberfw.pipeline.schemas import PostureFinding, ToolRecord, validate_record

TODAY = date(2026, 10, 12)


def _vuln(template: str, where: str, severity: str = "medium") -> ToolRecord:
    raw = {"template-id": template, "matched-at": where, "info": {"name": template, "severity": severity}}
    return validate_record("nuclei", json.dumps(raw), 1)


def _secret(rule: str, path: str) -> ToolRecord:
    raw = {"RuleID": rule, "File": path, "Secret": "AKIAEXAMPLE", "Description": "key"}
    return validate_record("gitleaks", json.dumps(raw), 1)


def _posture(template: str, target: str) -> ToolRecord:
    return PostureFinding.make("tlscheck", template, target, name=template, severity="medium",
                               description="d", remediation="r")


# -- matching ----------------------------------------------------------------------
def test_template_match_is_case_insensitive_and_scoped_by_kind() -> None:
    rule = triage.Rule(id="m1", template="CVE-2021-1234")
    assert rule.matches(_vuln("cve-2021-1234", "https://a.example.com/"))
    assert not rule.matches(_vuln("other", "https://a.example.com/"))
    # a non-finding record (a host, a port) is never muted
    assert not rule.matches(validate_record("subfinder", json.dumps({"host": "a.example.com"}), 1))


def test_target_pattern_matches_host_or_url() -> None:
    rule = triage.Rule(id="m1", template="*", target="*.dev.example.com")
    assert rule.matches(_vuln("x", "https://api.dev.example.com/login"))  # host
    assert not rule.matches(_vuln("x", "https://api.prod.example.com/"))
    url_rule = triage.Rule(id="m2", template="xss", target="https://a.example.com/search*")
    assert url_rule.matches(_vuln("xss", "https://a.example.com/search?q=1"))  # full URL
    assert not url_rule.matches(_vuln("xss", "https://a.example.com/other"))


def test_a_wildcard_template_with_no_target_mutes_every_finding() -> None:
    rule = triage.Rule(id="m1", template="*")
    assert rule.matches(_vuln("anything", "https://a/")) and rule.matches(_secret("aws", "app.py"))


def test_rule_is_inactive_after_its_expiry() -> None:
    rule = triage.Rule(id="m1", template="x", expires="2026-10-12")
    assert rule.active(date(2026, 10, 11)) is True
    assert rule.active(date(2026, 10, 12)) is False  # on/after the date it has lapsed
    assert triage.Rule(id="m2", template="x").active(date(2030, 1, 1)) is True  # no expiry


# -- apply -------------------------------------------------------------------------
def test_apply_marks_findings_and_counts_by_reason() -> None:
    records = [
        _vuln("self-signed", "https://dev.example.com/"),
        _vuln("self-signed", "https://prod.example.com/"),
        _secret("aws-key", "config.py"),
        _posture("tls-old-protocol", "https://dev.example.com"),
    ]
    rules = [
        triage.Rule(id="m1", template="self-signed", target="dev.example.com", reason="accepted_risk", note="dev box"),
        triage.Rule(id="m2", template="aws-key", reason="false_positive"),
    ]
    summary = triage.apply(records, rules, today=TODAY)

    assert records[0].muted == {"reason": "accepted_risk", "rule": "m1", "note": "dev box"}  # type: ignore[attr-defined]
    assert records[1].muted is None  # prod not covered by the dev-only rule  # type: ignore[attr-defined]
    assert records[2].muted == {"reason": "false_positive", "rule": "m2"}  # type: ignore[attr-defined]
    assert records[3].muted is None  # type: ignore[attr-defined]
    assert summary.muted == 2
    assert summary.by_reason == {"accepted_risk": 1, "false_positive": 1}
    assert summary.rules_used == {"m1", "m2"}
    assert "2 finding(s) muted by 2 rule(s)" in summary.line()


def test_apply_skips_expired_rules_and_reports_them() -> None:
    records = [_vuln("x", "https://a/")]
    rules = [triage.Rule(id="m1", template="x", expires="2020-01-01")]
    summary = triage.apply(records, rules, today=TODAY)
    assert records[0].muted is None and summary.muted == 0  # type: ignore[attr-defined]
    assert summary.expired == ["m1"]


def test_apply_first_matching_rule_wins_and_never_double_mutes() -> None:
    record = _vuln("x", "https://a/")
    record.muted = {"reason": "other", "rule": "pre"}  # type: ignore[attr-defined]
    triage.apply([record], [triage.Rule(id="m1", template="x")], today=TODAY)
    assert record.muted["rule"] == "pre"  # an already-muted finding is left alone  # type: ignore[attr-defined]


# -- persistence -------------------------------------------------------------------
def test_rules_round_trip_through_yaml(tmp_path: Path) -> None:
    path = tmp_path / "triage.yaml"
    rules = [
        triage.Rule(id="m1", template="self-signed", target="dev.example.com", reason="accepted_risk",
                    note="internal", added="2026-10-12", expires="2027-01-01"),
        triage.Rule(id="m2", template="aws-key"),  # reason "other" and empty fields are dropped
    ]
    triage.save_rules(path, rules)
    text = path.read_text(encoding="utf-8")
    assert text.startswith("# cyberfw triage") and "reason: other" not in text

    loaded = triage.load_rules(path)
    assert [r.as_dict() for r in loaded] == [r.as_dict() for r in rules]
    assert loaded[1].reason == "other" and loaded[1].target == ""


def test_load_absent_or_empty_file_is_no_rules(tmp_path: Path) -> None:
    assert triage.load_rules(tmp_path / "nope.yaml") == []
    (tmp_path / "empty.yaml").write_text("", encoding="utf-8")
    assert triage.load_rules(tmp_path / "empty.yaml") == []


def test_load_rejects_malformed_files(tmp_path: Path) -> None:
    bad = tmp_path / "triage.yaml"
    bad.write_text("mutes:\n  - target: dev.example.com\n", encoding="utf-8")  # no template
    with pytest.raises(triage.TriageError):
        triage.load_rules(bad)
    bad.write_text("mutes:\n  - {id: m1, template: x}\n  - {id: m1, template: y}\n", encoding="utf-8")
    with pytest.raises(triage.TriageError):  # duplicate id
        triage.load_rules(bad)
    bad.write_text("not: a-list\n", encoding="utf-8")
    with pytest.raises(triage.TriageError):
        triage.load_rules(bad)


def test_new_rule_id_increments() -> None:
    assert triage.new_rule_id([]) == "m1"
    assert triage.new_rule_id([triage.Rule(id="m1", template="a"), triage.Rule(id="m3", template="b")]) == "m4"
    assert triage.new_rule_id([triage.Rule(id="custom", template="a")]) == "m1"  # non-m ids ignored
