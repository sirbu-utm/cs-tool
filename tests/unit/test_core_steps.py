"""The steps after a scan, in cyberfw.core.steps: records added, events and notes sent, nothing printed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberfw import threatintel, vt
from cyberfw.config import Settings
from cyberfw.core import steps
from cyberfw.core.events import (
    MailSummary,
    Note,
    RunObserver,
    StepEvent,
    TakeoverSummary,
    TlsSummary,
    VtSummary,
)
from cyberfw.pipeline.engine import PipelineResult
from cyberfw.pipeline.schemas import PostureFinding, ToolRecord, validate_record
from cyberfw.posture import mail, takeover


class Recorder(RunObserver):
    """Keeps every step event and note it is sent."""

    def __init__(self) -> None:
        self.steps: list[StepEvent] = []
        self.notes: list[Note] = []

    def on_step(self, event: StepEvent) -> None:
        self.steps.append(event)

    def on_note(self, note: Note) -> None:
        self.notes.append(note)


def _record(tool: str, payload: dict[str, object]) -> ToolRecord:
    return validate_record(tool, json.dumps(payload), 1)


def _host() -> ToolRecord:
    return _record("subfinder", {"host": "sub.example.com", "source": "stub"})


def _finding() -> ToolRecord:
    return _record("nuclei", {"template-id": "xss", "matched-at": "https://sub.example.com/",
                              "info": {"name": "XSS", "severity": "medium"}})


pytestmark = pytest.mark.usefixtures("prints_nothing")


@pytest.fixture
def seen() -> Recorder:
    return Recorder()


def test_tls_reports_expired_and_untrusted_certificates(seen: Recorder) -> None:
    result = PipelineResult(records=[_record("httpx", {
        "url": "https://sub.example.com/", "status_code": 200, "title": "Home",
        "tls": {"host": "sub.example.com", "port": "443", "probe_status": True, "tls_version": "tls13",
                "issuer_cn": "R11", "not_after": "2001-01-01T00:00:00Z", "self_signed": True},
    })])

    steps.check_tls(result, seen)

    assert [event.kind for event in seen.steps] == ["start", "done"]
    assert seen.steps[-1].summary == TlsSummary(certificates=1, expired=1, soon=0, untrusted=1)
    added = {getattr(record, "template_id", "") for record in result.records[1:]}
    assert {"tls-cert-expired", "tls-cert-self-signed"} <= added


def test_a_step_with_nothing_to_do_sends_nothing(seen: Recorder) -> None:
    result = PipelineResult(records=[_finding()])

    steps.check_tls(result, seen)
    steps.check_takeover(result, seen)

    assert seen.steps == [] and seen.notes == []


def test_mail_reports_the_verdict_and_the_worst_finding(seen: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_check(domain: str, **_kw: object) -> object:
        return mail.assess(domain, mx=[], null_mx=False, spf=[], spf_policy="", dmarc=[], dmarc_domain="")

    monkeypatch.setattr(mail, "check", fake_check)
    result = PipelineResult()

    steps.check_mail(result, "https://www.example.com/", seen)

    start, done = seen.steps
    assert start == StepEvent("start", "mail", subject="example.com")
    assert done.summary == MailSummary("example.com", "spoofable", "No DMARC record — the domain can be spoofed")
    assert [record.kind for record in result.records][0] == "mail"


def test_an_unreachable_dns_is_a_note_not_a_failure(seen: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    async def offline(domain: str, **_kw: object) -> object:
        raise mail.DnsError("no resolver answered")

    monkeypatch.setattr(mail, "check", offline)

    steps.check_mail(PipelineResult(), "example.com", seen)

    assert seen.notes == [Note("warn", "Email check skipped — DNS-over-HTTPS unreachable: no resolver answered")]
    assert [(event.kind, event.summary) for event in seen.steps] == [("start", None), ("done", None)]


def test_an_interrupted_step_still_ends(seen: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    # A caller showing a live line for the step must get its "done" to take it down.
    async def interrupted(domain: str, **_kw: object) -> object:
        raise KeyboardInterrupt

    monkeypatch.setattr(mail, "check", interrupted)

    with pytest.raises(KeyboardInterrupt):
        steps.check_mail(PipelineResult(), "example.com", seen)

    assert [event.kind for event in seen.steps] == ["start", "done"]


def test_takeover_reports_progress_findings_and_notes(seen: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_scan(hosts: list[str], **kw: object) -> object:
        progress = kw["progress"]
        assert callable(progress)
        progress(1)
        finding = PostureFinding.make(
            takeover.TOOL, "subdomain-takeover", "https://blog.example.com",
            name="Subdomain takeover possible — GitHub Pages", severity="high",
            description="blog.example.com → user.github.io, unclaimed", remediation="remove the record",
        )
        return [finding], ["DNS for x.example.com timed out"]

    monkeypatch.setattr(takeover, "scan", fake_scan)
    result = PipelineResult(records=[_host()])

    steps.check_takeover(result, seen)

    assert [(event.kind, event.total, event.done) for event in seen.steps] == [
        ("start", 1, 0), ("advance", 1, 1), ("done", None, 0),
    ]
    assert seen.notes == [Note("warn", "Takeover: DNS for x.example.com timed out")]
    assert seen.steps[-1].summary == TakeoverSummary(checked=1, possible=1, hosts=("blog.example.com",))
    assert result.records[-1].tool == takeover.TOOL


def test_intel_passes_source_errors_on_as_notes(
    seen: Recorder, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rated = threatintel.IntelSummary(cves=1, findings=1, exploited=1, errors=["EPSS feed stale"])

    async def fake_enrich(records: object, cache_dir: Path, **_kw: object) -> threatintel.IntelSummary:
        return rated

    monkeypatch.setattr(threatintel, "cve_ids", lambda record: ["CVE-2024-0001"])
    monkeypatch.setattr(threatintel, "enrich", fake_enrich)

    steps.rate_cves(PipelineResult(records=[_finding()]), tmp_path, seen)

    assert seen.notes == [Note("warn", "Threat intel — EPSS feed stale")]
    assert seen.steps[-1] == StepEvent("done", "intel", summary=rated)


def test_virustotal_adds_reputation_records(seen: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_enrich(targets: list[str], api_key: str, limit: int = 20, **kw: object) -> list[vt.Reputation]:
        progress = kw["progress"]
        assert callable(progress)
        for done in range(1, len(targets) + 1):
            progress(done)
        return [vt.Reputation(target=t, kind="domain", found=True, malicious=i % 2) for i, t in enumerate(targets)]

    monkeypatch.setattr(vt, "enrichment_targets", lambda records: ["a.example.com", "b.example.com"])
    monkeypatch.setattr(vt, "enrich", fake_enrich)
    result = PipelineResult(records=[_host()])

    steps.enrich_vt(result, "key", 20, seen)

    assert [(event.kind, event.done) for event in seen.steps] == [("start", 0), ("advance", 1), ("advance", 2), ("done", 0)]
    assert seen.steps[0].total == 2
    assert seen.steps[-1].summary == VtSummary(looked_up=2, flagged=1)
    assert [record.tool for record in result.records[1:]] == ["virustotal", "virustotal"]


@pytest.mark.parametrize(
    ("step", "patch", "message"),
    [
        ("mail", (mail, "check"), "Email check failed: upstream [down]"),
        ("takeover", (takeover, "scan"), "Subdomain-takeover check failed: upstream [down]"),
        ("intel", (threatintel, "enrich"), "Threat intel failed: upstream [down]"),
        ("vt", (vt, "enrich"), "VirusTotal enrichment failed: upstream [down]"),
    ],
)
def test_a_failing_step_never_fails_the_scan(
    step: str, patch: tuple[object, str], message: str,
    seen: Recorder, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    async def broken(*_a: object, **_k: object) -> object:
        raise RuntimeError("upstream [down]")

    monkeypatch.setattr(*patch, broken)
    monkeypatch.setattr(threatintel, "cve_ids", lambda record: ["CVE-2024-0001"])
    monkeypatch.setattr(vt, "enrichment_targets", lambda records: ["a.example.com"])
    result = PipelineResult(records=[_host(), _finding()])

    steps.post_scan(
        result, seed="example.com", settings=Settings(root_dir=tmp_path), observer=seen,
        mail=step == "mail", takeover=step == "takeover", intel=step == "intel",
        vt_key="key" if step == "vt" else None, vt_limit=20,
    )

    assert seen.notes == [Note("warn", message)]
    assert [(event.step, event.kind, event.summary) for event in seen.steps if event.kind != "advance"] == [
        (step, "start", None), (step, "done", None),
    ]
    assert len(result.records) == 2  # nothing added, nothing lost


def test_post_scan_runs_the_steps_in_order_and_skips_what_is_off(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[str] = []
    for name, label in [("check_tls", "tls"), ("check_mail", "mail"), ("check_takeover", "takeover"),
                        ("rate_cves", "intel"), ("enrich_vt", "vt")]:
        monkeypatch.setattr(steps, name, lambda *_a, label=label: calls.append(label))
    settings = Settings(root_dir=tmp_path)

    def run(**flags: object) -> list[str]:
        calls.clear()
        options: dict[str, object] = {"mail": True, "takeover": True, "intel": True, "vt_key": "key", "vt_limit": 20}
        options.update(flags)
        steps.post_scan(PipelineResult(), seed="example.com", settings=settings, observer=RunObserver(), **options)  # type: ignore[arg-type]
        return list(calls)

    assert run() == ["tls", "mail", "takeover", "intel", "vt"]
    assert run(mail=False, intel=False, vt_key=None) == ["tls", "takeover"]
