"""Comparing two runs: what changed, and when an absence can be trusted."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from cyberfw.report import diff

_STAGES = (("subfinder", True), ("httpx", True), ("nuclei", True))


def _doc(*records: dict[str, Any], stages: tuple[tuple[str, bool], ...] = _STAGES,
         started: str = "2026-10-01T10:00:00+00:00", session: str = "s1",
         seed: str = "example.com", pipeline: str = "recon-to-vuln") -> dict[str, Any]:
    return {
        "ok": True,
        "run": {"pipeline": pipeline, "seed": seed, "session_id": session, "started_at": started},
        "stages": [{"tool": t, "stage": t, "ok": ok, "skipped": False, "count": 0, "error": None} for t, ok in stages],
        "records": list(records),
    }


def _host(name: str) -> dict[str, Any]:
    return {"tool": "subfinder", "kind": "host", "target": name, "host": name}


def _web(url: str, status: int = 200, not_after: str | None = None) -> dict[str, Any]:
    record: dict[str, Any] = {"tool": "httpx", "kind": "http", "target": url, "url": url, "status_code": status}
    if not_after:
        record["tls"] = {"host": url.split("//")[1].split("/")[0], "port": "443", "not_after": not_after}
    return record


def _port(host_port: str) -> dict[str, Any]:
    return {"tool": "naabu", "kind": "port", "target": host_port}


def _vuln(template: str, where: str, severity: str = "medium", *, kev: bool | None = None,
          tool: str = "nuclei", matcher: str = "") -> dict[str, Any]:
    record: dict[str, Any] = {
        "tool": tool, "kind": "vuln", "target": where, "template_id": template, "matched_at": where,
        "info": {"name": template.upper(), "severity": severity},
        "raw": json.dumps({"matcher-name": matcher}) if matcher else "",
    }
    if kev is not None:
        record["intel"] = {"kev": kev}
    return record


def _labels(result: diff.RunDiff) -> list[tuple[str, str]]:
    return [(c.label, c.subject) for c in result.changes]


def test_identical_runs_have_no_changes() -> None:
    records = (_host("a.example.com"), _web("https://a.example.com"), _vuln("xss", "https://a.example.com/q"))
    result = diff.compare(_doc(*records), _doc(*records))
    assert result.changes == [] and result.summary() == [] and result.not_compared == []


def test_new_gone_and_moved_assets_and_findings() -> None:
    old = _doc(_host("a.example.com"), _host("b.example.com"), _web("https://a.example.com"),
               _port("a.example.com:443"), _vuln("xss", "https://a.example.com/q", "medium"),
               stages=(*_STAGES, ("naabu", True)))
    new = _doc(_host("a.example.com"), _host("c.example.com"), _web("https://a.example.com"),
               _web("https://c.example.com"), _port("a.example.com:443"), _port("a.example.com:22"),
               _vuln("sqli", "https://c.example.com/login", "high"), stages=(*_STAGES, ("naabu", True)))
    result = diff.compare(old, new)

    assert set(_labels(result)) == {
        ("new finding", "SQLI"), ("gone", "XSS"), ("port opened", "a.example.com:22"),
        ("new subdomain", "c.example.com"), ("subdomain gone", "b.example.com"),
        ("new web service", "https://c.example.com"),
    }
    assert result.changes[0].label == "new finding" and result.changes[0].tone == diff.BAD  # bad news first
    assert result.changes[-1].label == "gone" and result.changes[-1].tone == diff.GOOD  # good news last
    assert "fixed, or not seen this time" in result.changes[-1].detail
    assert result.summary() == [
        "1 new finding", "1 finding gone", "1 port opened", "1 new subdomain", "1 subdomain gone",
        "1 new web service",
    ]
    assert result.new_findings == 1


def test_new_findings_at_least_counts_added_findings_from_a_severity_up() -> None:
    # One medium is already there (not new); the new run adds one finding of
    # each severity. Only the real ones (low and worse) can ever alert.
    old = _doc(_vuln("kept", "https://a.example.com/x", "medium"))
    new = _doc(
        _vuln("kept", "https://a.example.com/x", "medium"),
        _vuln("crit", "https://a.example.com/c", "critical"),
        _vuln("high", "https://a.example.com/h", "high"),
        _vuln("med", "https://a.example.com/m", "medium"),
        _vuln("low", "https://a.example.com/l", "low"),
        _vuln("note", "https://a.example.com/i", "info"),
    )
    result = diff.compare(old, new)

    assert result.new_findings_at_least("critical") == 1
    assert result.new_findings_at_least("high") == 2
    assert result.new_findings_at_least("medium") == 3
    assert result.new_findings_at_least("low") == 4  # info is not a real finding
    assert result.new_findings_at_least("low") == result.new_findings


def test_a_failed_stage_never_makes_findings_gone_or_new() -> None:
    finding = _vuln("xss", "https://a.example.com/q")
    nuclei_failed = (("subfinder", True), ("httpx", True), ("nuclei", False))

    gone = diff.compare(_doc(finding), _doc(stages=nuclei_failed))
    assert gone.changes == []
    assert gone.not_compared == ["nuclei did not run (or did not finish) in this run, so its results were not compared"]

    new = diff.compare(_doc(stages=nuclei_failed), _doc(finding))
    assert new.changes == [] and "in the earlier run" in new.not_compared[0]


def test_a_check_the_earlier_run_did_not_have_reports_nothing_as_new() -> None:
    """A report from before the TLS / email checks existed: their findings are not 'new'."""
    old = _doc(_web("https://a.example.com"))  # no tls block, no mail record
    new = _doc(
        _web("https://a.example.com", not_after="2026-12-01T00:00:00Z"),
        _vuln("tls-cert-expiring", "https://a.example.com", "low", tool="tlscheck"),
        {"tool": "mailcheck", "kind": "mail", "target": "example.com", "domain": "example.com", "verdict": "spoofable"},
        _vuln("mail-dmarc-missing", "example.com", "medium", tool="mailcheck"),
    )
    result = diff.compare(old, new)
    assert result.changes == []
    assert [note.split()[0] for note in result.not_compared] == ["mailcheck", "tlscheck"]


def test_a_known_finding_that_became_exploited_in_the_wild() -> None:
    before = _vuln("CVE-2021-41773", "https://a.example.com/cgi-bin/", "high", kev=False)
    after = _vuln("CVE-2021-41773", "https://a.example.com/cgi-bin/", "high", kev=True)
    result = diff.compare(_doc(before), _doc(after))
    assert _labels(result) == [("now exploited", "CVE-2021-41773")]
    assert result.changes[0].tone == diff.BAD and "CISA KEV" in result.changes[0].detail
    assert result.summary() == ["1 now exploited in the wild"]


def test_certificate_renewal_and_http_status() -> None:
    old = _doc(_web("https://a.example.com", 200, not_after="2026-11-01T00:00:00Z"))
    new = _doc(_web("https://a.example.com", 503, not_after="2027-02-01T00:00:00Z"))
    result = diff.compare(old, new)
    by_label = {c.label: c for c in result.changes}
    assert by_label["renewed"].detail == "valid until 2026-11-01 → 2027-02-01" and by_label["renewed"].tone == diff.GOOD
    assert by_label["status changed"].detail == "HTTP 200 → 503" and by_label["status changed"].tone == diff.BAD
    assert "1 certificate renewed" in result.summary() and "1 HTTP status change" in result.summary()


def test_email_verdict_and_virustotal_flags() -> None:
    def mail(verdict: str) -> dict[str, Any]:
        return {"tool": "mailcheck", "kind": "mail", "target": "example.com", "domain": "example.com", "verdict": verdict}

    def rep(malicious: int) -> dict[str, Any]:
        return {"tool": "virustotal", "kind": "reputation", "target": "a.example.com", "malicious": malicious, "suspicious": 0}

    result = diff.compare(_doc(mail("spoofable"), rep(0)), _doc(mail("protected"), rep(3)))
    by_area = {c.area: c for c in result.changes}
    assert (by_area["email"].label, by_area["email"].detail, by_area["email"].tone) == ("better", "spoofable → protected", diff.GOOD)
    assert by_area["reputation"].label == "flagged" and by_area["reputation"].tone == diff.BAD
    assert "email example.com: spoofable → protected" in result.summary()


def test_finding_identity() -> None:
    cosmetic = diff.compare(_doc(_vuln("xss", "https://A.example.com:443/q/")), _doc(_vuln("xss", "https://a.example.com/q")))
    assert cosmetic.changes == []  # case, default port and trailing slash do not make it a new finding
    matchers = diff.compare(
        _doc(_vuln("tech-detect", "https://a.example.com", "info", matcher="nginx")),
        _doc(_vuln("tech-detect", "https://a.example.com", "info", matcher="apache")),
    )
    assert sorted(c.status for c in matchers.changes) == ["added", "removed"]  # one template, two matches
    assert all(c.tone == diff.NEUTRAL for c in matchers.changes)  # info-level: listed, not alarming
    assert matchers.summary() == ["2 info-level finding changes"]


def test_a_muted_finding_is_not_counted_as_new_or_gone() -> None:
    new_only = dict(_vuln("self-signed", "https://dev.example.com/"))
    new_only["muted"] = {"reason": "accepted_risk", "rule": "m1"}
    result = diff.compare(_doc(), _doc(new_only))
    assert result.changes == []  # a muted finding appearing is not news

    gone = {**_vuln("self-signed", "https://dev.example.com/"), "muted": {"reason": "accepted_risk", "rule": "m1"}}
    assert diff.compare(_doc(gone), _doc()).changes == []  # nor is it disappearing


def test_a_muted_finding_that_becomes_exploited_still_surfaces() -> None:
    muted = {"reason": "accepted_risk", "rule": "m1"}
    before = {**_vuln("CVE-2021-41773", "https://a/cgi-bin/", "high", kev=False), "muted": muted}
    after = {**_vuln("CVE-2021-41773", "https://a/cgi-bin/", "high", kev=True), "muted": muted}
    result = diff.compare(_doc(before), _doc(after))
    assert _labels(result) == [("now exploited", "CVE-2021-41773")]  # mute silences noise, not a KEV escalation


def test_secrets_are_compared_without_printing_them() -> None:
    secret = {"tool": "gitleaks", "kind": "secret", "target": "app.py", "rule_id": "aws-key",
              "file_path": "app.py", "commit": "abc", "secret": "AKIAEXAMPLE"}
    result = diff.compare(_doc(stages=(("gitleaks", True),)), _doc(secret, stages=(("gitleaks", True),)))
    assert _labels(result) == [("new secret", "aws-key")]
    assert "AKIAEXAMPLE" not in json.dumps(result.as_dict())


# -- finding the earlier run -------------------------------------------------------------
def _save(reports: Path, session: str, doc: dict[str, Any], mtime: float) -> Path:
    path = reports / session / "report.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    os.utime(path, (mtime, mtime))
    return path


def test_find_baseline_picks_the_newest_earlier_run_of_the_same_scan(tmp_path: Path) -> None:
    _save(tmp_path, "old", _doc(started="2026-10-01T10:00:00+00:00", seed="example.com"), 1_000)
    wanted = _save(tmp_path, "mid", _doc(started="2026-10-05T10:00:00+00:00", seed="https://Example.com/"), 2_000)
    _save(tmp_path, "other-target", _doc(started="2026-10-07T10:00:00+00:00", seed="other.com"), 3_000)
    _save(tmp_path, "other-pipeline", _doc(started="2026-10-07T10:00:00+00:00", pipeline="ports-to-vuln"), 3_500)
    _save(tmp_path, "current", _doc(started="2026-10-09T10:00:00+00:00"), 4_000)

    now = diff._parse_time("2026-10-09T10:00:00+00:00")
    assert diff.find_baseline(tmp_path, seed="example.com", pipeline="recon-to-vuln", before=now) == wanted
    assert diff.find_baseline(tmp_path, seed="nobody.com", pipeline="recon-to-vuln", before=now) is None
    assert diff.find_baseline(tmp_path / "missing", seed="example.com", pipeline="recon-to-vuln", before=now) is None


def test_find_baseline_reads_a_run_block_beyond_the_file_head(tmp_path: Path) -> None:
    doc = {"padding": "x" * 40_000, **_doc(started="2026-10-01T10:00:00+00:00")}  # run is past the 16 KiB head
    path = _save(tmp_path, "big", doc, 1_000)
    later = diff._parse_time("2026-10-02T00:00:00+00:00")
    assert diff.find_baseline(tmp_path, seed="example.com", pipeline="recon-to-vuln", before=later) == path


def test_resolve_report_accepts_a_session_a_directory_or_a_file(tmp_path: Path) -> None:
    path = _save(tmp_path, "s1", _doc(), 1_000)
    assert diff.resolve_report("s1", tmp_path) == path
    assert diff.resolve_report(str(path.parent), tmp_path) == path
    assert diff.resolve_report(str(path), tmp_path) == path
    with pytest.raises(FileNotFoundError):
        diff.resolve_report("nope", tmp_path)


def test_load_report_rejects_what_is_not_a_report(tmp_path: Path) -> None:
    bad = tmp_path / "report.json"
    bad.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(ValueError):
        diff.load_report(bad)
    bad.write_text("{oops", encoding="utf-8")
    with pytest.raises(ValueError):
        diff.load_report(bad)


def test_as_dict_is_the_report_json_block() -> None:
    result = diff.compare(_doc(session="s1"), _doc(_host("new.example.com"), session="s2"))
    block = result.as_dict()
    assert block["baseline"] == {"session_id": "s1", "pipeline": "recon-to-vuln", "seed": "example.com",
                                 "started_at": "2026-10-01T10:00:00+00:00"}
    assert block["summary"] == ["1 new subdomain"]
    assert block["changes"][0]["label"] == "new subdomain" and block["not_compared"] == []
