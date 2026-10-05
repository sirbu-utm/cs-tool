"""The sqlite scan store round-trips a scan and its summary across operations."""

from __future__ import annotations

from pathlib import Path

import pytest
from _helpers import SAMPLE_REPORT
from cyberfw_bot.models import Scan
from cyberfw_bot.reports import summarize
from cyberfw_bot.storage import ScanStore

pytestmark = pytest.mark.asyncio


async def _store(tmp_path: Path) -> ScanStore:
    store = ScanStore(tmp_path / "scans.sqlite3")
    await store.init()
    return store


async def test_create_and_fetch(tmp_path: Path) -> None:
    store = await _store(tmp_path)
    await store.create(Scan(id="ab12", user_id=42, chat_id=7, target="example.com"))

    scan = await store.get("ab12")
    assert scan is not None
    assert scan.status == "queued"
    assert scan.created_at is not None


async def test_finish_persists_summary(tmp_path: Path) -> None:
    store = await _store(tmp_path)
    await store.create(Scan(id="cd34", user_id=42, chat_id=7, target="example.com"))
    await store.mark_running("cd34")
    summary = summarize(SAMPLE_REPORT)

    await store.finish(
        "cd34",
        status="done",
        exit_code=0,
        error=None,
        report_json=tmp_path / "report.json",
        report_html=tmp_path / "report.html",
        summary=summary,
    )

    scan = await store.get("cd34")
    assert scan is not None
    assert scan.status == "done"
    assert scan.summary is not None
    assert scan.summary.severity_counts["critical"] == 1
    assert scan.report_html == str(tmp_path / "report.html")


async def test_recent_is_scoped_to_the_user_and_ordered(tmp_path: Path) -> None:
    store = await _store(tmp_path)
    await store.create(Scan(id="one", user_id=42, chat_id=7, target="a.com"))
    await store.create(Scan(id="two", user_id=42, chat_id=7, target="b.com"))
    await store.create(Scan(id="other", user_id=99, chat_id=7, target="c.com"))

    recent = await store.recent_for_user(42, limit=10)
    ids = {s.id for s in recent}
    assert ids == {"one", "two"}
    assert all(s.user_id == 42 for s in recent)
