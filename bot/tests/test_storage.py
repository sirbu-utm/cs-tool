"""The sqlite scan store round-trips a scan and its summary across operations."""

from __future__ import annotations

import sqlite3
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


async def test_username_is_persisted(tmp_path: Path) -> None:
    store = await _store(tmp_path)
    await store.create(Scan(id="u1", user_id=42, chat_id=7, target="a.com", username="alice"))

    scan = await store.get("u1")
    assert scan is not None and scan.username == "alice"


async def test_init_adds_the_username_column_to_an_old_db(tmp_path: Path) -> None:
    """A DB created before the username column must gain it on init, keeping rows."""
    path = tmp_path / "old.sqlite3"
    con = sqlite3.connect(path)
    # The original schema (everything except the username column added later).
    con.execute(
        "CREATE TABLE scans (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, "
        "chat_id INTEGER NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, "
        "finished_at TEXT, exit_code INTEGER, error TEXT, report_json TEXT, report_html TEXT, summary_json TEXT)"
    )
    con.execute(
        "INSERT INTO scans (id, user_id, chat_id, target, status, created_at) "
        "VALUES ('old1', 1, 7, 'old.com', 'done', '2026-01-01T00:00:00+00:00')"
    )
    con.commit()
    con.close()

    store = ScanStore(path)
    await store.init()  # must ALTER TABLE to add username
    await store.create(Scan(id="new1", user_id=2, chat_id=7, target="new.com", username="bob"))

    old = await store.get("old1")
    assert old is not None and old.username is None  # pre-existing row survives
    new = await store.get("new1")
    assert new is not None and new.username == "bob"


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


async def test_reclaim_orphans_marks_unfinished_as_failed_and_returns_them(tmp_path: Path) -> None:
    store = await _store(tmp_path)
    await store.create(Scan(id="q1", user_id=1, chat_id=7, target="a.com"))  # queued
    await store.create(Scan(id="r1", user_id=1, chat_id=7, target="b.com"))
    await store.mark_running("r1")  # running

    reclaimed = await store.reclaim_orphans("interrupted by a restart")

    assert {s.id for s in reclaimed} == {"q1", "r1"}
    assert all(s.status == "failed" and s.error == "interrupted by a restart" for s in reclaimed)
    for sid in ("q1", "r1"):
        scan = await store.get(sid)
        assert scan is not None
        assert scan.status == "failed"
        assert scan.error == "interrupted by a restart"
        assert scan.finished_at is not None


async def test_allowed_users_round_trip(tmp_path: Path) -> None:
    store = await _store(tmp_path)
    await store.add_allowed(111, "alice")
    await store.add_allowed(222, None)

    rows = await store.list_allowed()
    assert {r["user_id"] for r in rows} == {111, 222}
    assert next(r["username"] for r in rows if r["user_id"] == 111) == "alice"

    assert await store.remove_allowed(111) is True
    assert {r["user_id"] for r in await store.list_allowed()} == {222}
    assert await store.remove_allowed(999) is False  # removing an absent id is a no-op


async def test_recent_lists_scans_across_all_users(tmp_path: Path) -> None:
    store = await _store(tmp_path)
    await store.create(Scan(id="a", user_id=1, chat_id=7, target="a.com"))
    await store.create(Scan(id="b", user_id=2, chat_id=7, target="b.com"))

    recent = await store.recent(limit=10)

    assert {s.id for s in recent} == {"a", "b"}  # not scoped to one user


async def test_reclaim_orphans_leaves_finished_scans_untouched(tmp_path: Path) -> None:
    store = await _store(tmp_path)
    await store.create(Scan(id="d1", user_id=1, chat_id=7, target="c.com"))
    await store.finish(
        "d1", status="done", exit_code=0, error=None,
        report_json=None, report_html=None, summary=None,
    )

    reclaimed = await store.reclaim_orphans("interrupted by a restart")

    assert reclaimed == []
    done = await store.get("d1")
    assert done is not None
    assert done.status == "done"
