"""End-to-end orchestration with a fake runner: authorise, validate, run, notify."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from _helpers import SAMPLE_REPORT, make_config
from cyberfw_bot.models import Scan
from cyberfw_bot.runner import ScanOutcome
from cyberfw_bot.service import AuthorizationError, ScanService
from cyberfw_bot.storage import ScanStore
from cyberfw_bot.validation import ValidationError

pytestmark = pytest.mark.asyncio


class _FakeRunner:
    """Stands in for CyberfwRunner; writes a report and returns a chosen outcome."""

    def __init__(self, tmp_path: Path, *, ok: bool = True) -> None:
        self._tmp = tmp_path
        self._ok = ok
        self.calls: list[tuple[str, str]] = []

    async def run(self, target: str, session: str) -> ScanOutcome:
        self.calls.append((target, session))
        if not self._ok:
            return ScanOutcome(1, False, None, None, "", "boom")
        session_dir = self._tmp / "reports" / session
        session_dir.mkdir(parents=True, exist_ok=True)
        report = session_dir / "report.json"
        report.write_text(json.dumps(SAMPLE_REPORT), encoding="utf-8")
        html = session_dir / "report.html"
        html.write_text("<html></html>", encoding="utf-8")
        return ScanOutcome(0, False, report, html, "", "")


async def _service(tmp_path: Path, runner: _FakeRunner) -> tuple[ScanService, ScanStore]:
    store = ScanStore(tmp_path / "scans.sqlite3")
    await store.init()
    return ScanService(make_config(tmp_path), store, runner=runner), store  # type: ignore[arg-type]


async def test_unauthorised_user_is_rejected_before_anything_runs(tmp_path: Path) -> None:
    runner = _FakeRunner(tmp_path)
    service, _ = await _service(tmp_path, runner)

    with pytest.raises(AuthorizationError):
        await service.submit(user_id=999, chat_id=1, raw_target="example.com", notify=_noop)
    assert runner.calls == []


async def test_bad_target_is_rejected_before_anything_runs(tmp_path: Path) -> None:
    runner = _FakeRunner(tmp_path)
    service, _ = await _service(tmp_path, runner)

    with pytest.raises(ValidationError):
        await service.submit(user_id=42, chat_id=1, raw_target="example.com; id", notify=_noop)
    assert runner.calls == []


async def test_successful_scan_notifies_with_a_summary(tmp_path: Path) -> None:
    runner = _FakeRunner(tmp_path)
    service, store = await _service(tmp_path, runner)
    delivered: list[Scan] = []

    async def notify(scan: Scan) -> None:
        delivered.append(scan)

    queued = await service.submit(user_id=42, chat_id=1, raw_target="example.com", notify=notify)
    assert queued.status == "queued"
    await service.wait_for_all()

    assert len(delivered) == 1
    done = delivered[0]
    assert done.status == "done"
    assert done.summary is not None and done.summary.severity_counts["critical"] == 1
    assert runner.calls == [("example.com", f"bot-{queued.id}")]

    persisted = await store.get(queued.id)
    assert persisted is not None and persisted.status == "done"


async def test_failed_scan_is_recorded_and_notified(tmp_path: Path) -> None:
    runner = _FakeRunner(tmp_path, ok=False)
    service, store = await _service(tmp_path, runner)
    delivered: list[Scan] = []

    async def notify(scan: Scan) -> None:
        delivered.append(scan)

    queued = await service.submit(user_id=42, chat_id=1, raw_target="example.com", notify=notify)
    await service.wait_for_all()

    assert delivered[0].status == "failed"
    persisted = await store.get(queued.id)
    assert persisted is not None and persisted.status == "failed" and persisted.error


async def _noop(_scan: Scan) -> None:
    return None
