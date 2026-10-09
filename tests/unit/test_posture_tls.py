"""TLS certificate health from httpx's -tls-grab data (offline, fixed clock)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from cyberfw.pipeline.schemas import PostureFinding, ToolRecord, validate_record
from cyberfw.posture import tls

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)


def _httpx(host: str, *, days: float | None = 90, lineno: int = 1, **flags: object) -> ToolRecord:
    """An httpx record whose certificate runs out ``days`` after NOW."""
    block: dict[str, object] = {
        "host": host, "port": "443", "probe_status": True, "tls_version": "tls13",
        "subject_cn": host, "subject_an": [host], "issuer_cn": "R11",
        **flags,
    }
    if days is not None:
        block["not_after"] = (NOW + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = {"url": f"https://{host}", "status_code": 200, "tls": block}
    return validate_record("httpx", json.dumps(raw), lineno)


def _findings_for(record: ToolRecord, *others: ToolRecord) -> list[PostureFinding]:
    records = [record, *others]
    return tls.findings(tls.certificates(records), records, now=NOW)


def _ids(found: list[PostureFinding]) -> dict[str, str]:
    """``{check_id: severity}``."""
    return {finding.template_id: finding.severity for finding in found}


def test_certificates_one_per_host_and_port() -> None:
    plain = validate_record("httpx", json.dumps({"url": "http://plain.example.com", "status_code": 200}), 3)
    failed = _httpx("down.example.com", probe_status=False)
    certs = tls.certificates([_httpx("a.example.com"), _httpx("a.example.com", days=1, lineno=2), plain, failed])
    assert [cert.host for cert in certs] == ["a.example.com"]  # first probe wins; no-TLS / failed skipped
    cert = certs[0]
    assert cert.days_left(NOW) == 90 and cert.issuer == "R11" and cert.version_name == "TLS 1.3"
    assert cert.not_after is not None and cert.not_after.tzinfo is not None  # the Z suffix parsed on 3.10


def test_healthy_certificate_has_no_findings() -> None:
    assert _findings_for(_httpx("ok.example.com", days=120)) == []


def test_expiry_countdown_escalates() -> None:
    assert _ids(_findings_for(_httpx("a.example.com", days=20))) == {"tls-cert-expiring": "low"}
    assert _ids(_findings_for(_httpx("a.example.com", days=3))) == {"tls-cert-expiring": "medium"}
    assert _findings_for(_httpx("a.example.com", days=3))[0].name == "TLS certificate expires in 3 days"
    assert _findings_for(_httpx("a.example.com", days=0.2))[0].name == "TLS certificate expires today"


def test_expired_by_date_or_by_httpx_flag() -> None:
    by_date = _findings_for(_httpx("old.example.com", days=-5))
    assert _ids(by_date) == {"tls-cert-expired": "high"}
    assert by_date[0].name == "TLS certificate expired 5 day(s) ago"
    assert _ids(_findings_for(_httpx("old.example.com", days=None, expired=True))) == {"tls-cert-expired": "high"}


def test_untrusted_mismatched_and_outdated_protocol() -> None:
    record = _httpx(
        "legacy.example.com", self_signed=True, mismatched=True, tls_version="tls10",
        subject_an=["*.hosting.example.net"],
    )
    found = _findings_for(record)
    assert _ids(found) == {
        "tls-cert-self-signed": "medium", "tls-cert-mismatch": "medium", "tls-old-protocol": "medium",
    }
    mismatch = next(f for f in found if f.template_id == "tls-cert-mismatch")
    assert "*.hosting.example.net" in mismatch.info["description"]


def test_a_problem_nuclei_already_reported_is_not_repeated() -> None:
    nuclei = validate_record(
        "nuclei",
        json.dumps({"template-id": "expired-ssl", "matched-at": "old.example.com:443",
                    "info": {"name": "Expired SSL", "severity": "low"}}),
        1,
    )
    found = _findings_for(_httpx("old.example.com", days=-5, self_signed=True), nuclei)
    assert _ids(found) == {"tls-cert-self-signed": "medium"}  # expiry left to nuclei's own finding


def test_findings_look_like_nuclei_findings() -> None:
    data = _findings_for(_httpx("a.example.com", days=2))[0].as_dict()
    assert data["tool"] == tls.TOOL and data["kind"] == "vuln"
    assert data["template_id"] == "tls-cert-expiring"
    assert data["matched_at"] == data["target"] == "https://a.example.com"
    assert data["info"]["severity"] == "medium" and data["info"]["remediation"]
