"""Post-scan takeover probes must respect the scan's hostname exclusions."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from cyberfw.config import Settings
from cyberfw.core.events import RunObserver, StepEvent, TakeoverSummary
from cyberfw.core.steps import post_scan
from cyberfw.pipeline.engine import PipelineResult
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.posture import takeover


class Recorder(RunObserver):
    def __init__(self) -> None:
        self.steps: list[StepEvent] = []

    def on_step(self, event: StepEvent) -> None:
        self.steps.append(event)


@pytest.fixture
def probes(monkeypatch: pytest.MonkeyPatch) -> tuple[list[str], list[str]]:
    dns: list[str] = []
    http: list[str] = []

    async def resolve(_client: httpx.AsyncClient, name: str, rtype: str) -> tuple[int, list[str]]:
        assert rtype == "CNAME"
        dns.append(name)
        return 0, ["unclaimed.github.io"]

    async def fetch(_client: httpx.AsyncClient, host: str) -> str:
        http.append(host)
        return "There isn't a GitHub Pages site here."

    monkeypatch.setattr(takeover, "doh", resolve)
    monkeypatch.setattr(takeover, "http_body", fetch)
    return dns, http


def _post_scan(result: PipelineResult, settings: Settings, seen: Recorder, *, enabled: bool = True) -> None:
    post_scan(
        result, seed="example.com", settings=settings, observer=seen,
        mail=False, takeover=enabled, intel=False, vt_key=None, vt_limit=20,
    )


@pytest.mark.parametrize(
    ("target", "kind", "pattern"),
    [
        ("private.example.com", "host", "private.example.com"),
        ("api.private.example.com", "host", "*.private.example.com"),
        ("https://PRIVATE.example.com:8443/path", "http", "Private.Example.Com"),
        ("private.example.com:8080", "port", "private.example.com"),
    ],
    ids=["exact", "wildcard", "case-insensitive-url", "host-port"],
)
def test_excluded_discovery_records_never_reach_dns_or_http(
    target: str, kind: str, pattern: str, tmp_path: Path, probes: tuple[list[str], list[str]]
) -> None:
    original = [
        ToolRecord(tool="subfinder", kind=kind, target=target),
        ToolRecord(tool="subfinder", kind="host", target="public.example.com"),
    ]
    result = PipelineResult(records=list(original))
    seen = Recorder()

    _post_scan(result, Settings(root_dir=tmp_path, exclude=[pattern]), seen)

    assert probes == (["public.example.com"], ["public.example.com"])
    assert result.records[:2] == original
    assert [record.target for record in result.records[2:]] == ["https://public.example.com"]
    assert seen.steps[0] == StepEvent("start", "takeover", total=1)
    assert seen.steps[-1].summary == TakeoverSummary(checked=1, possible=1, hosts=("public.example.com",))


def test_a_fully_excluded_run_has_no_takeover_work_or_events(
    tmp_path: Path, probes: tuple[list[str], list[str]]
) -> None:
    record = ToolRecord(tool="subfinder", kind="host", target="private.example.com")
    result = PipelineResult(records=[record], excluded=[record.target])
    seen = Recorder()

    _post_scan(result, Settings(root_dir=tmp_path, exclude=["*.example.com"]), seen)

    assert probes == ([], [])
    assert seen.steps == []
    assert result.records == [record]
    assert result.excluded == [record.target]


def test_no_exclusions_still_checks_all_discovered_hosts(
    tmp_path: Path, probes: tuple[list[str], list[str]]
) -> None:
    hosts = ["private.example.com", "public.example.com"]
    result = PipelineResult(records=[ToolRecord(tool="subfinder", kind="host", target=host) for host in hosts])
    seen = Recorder()

    _post_scan(result, Settings(root_dir=tmp_path), seen)

    assert probes == (hosts, hosts)
    assert seen.steps[-1].summary == TakeoverSummary(checked=2, possible=2, hosts=tuple(hosts))


def test_exclusions_are_applied_before_the_takeover_host_limit(
    tmp_path: Path, probes: tuple[list[str], list[str]]
) -> None:
    hosts = [f"host-{index}.private.example.com" for index in range(301)] + ["public.example.com"]
    result = PipelineResult(records=[ToolRecord(tool="subfinder", kind="host", target=host) for host in hosts])
    seen = Recorder()

    _post_scan(result, Settings(root_dir=tmp_path, exclude=["*.private.example.com"]), seen)

    assert probes == (["public.example.com"], ["public.example.com"])
    assert seen.steps[0].total == 1


def test_disabled_takeover_still_makes_no_probes(tmp_path: Path, probes: tuple[list[str], list[str]]) -> None:
    result = PipelineResult(records=[ToolRecord(tool="subfinder", kind="host", target="public.example.com")])
    seen = Recorder()

    _post_scan(result, Settings(root_dir=tmp_path), seen, enabled=False)

    assert probes == ([], [])
    assert seen.steps == []
