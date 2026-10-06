"""SQLite persistence for scan history.

The store keeps the whole scan lifecycle so ``/status`` and ``/report`` work
across restarts. It uses the stdlib ``sqlite3`` driver behind
``asyncio.to_thread`` and opens a fresh connection per operation — sqlite makes
that cheap, and it sidesteps the driver's one-thread-per-connection rule without
a shared lock. The summary is stored as JSON in one column.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cyberfw_bot.models import Finding, Scan, Summary

__all__ = ["ScanStore"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL,
    chat_id      INTEGER NOT NULL,
    target       TEXT NOT NULL,
    status       TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    finished_at  TEXT,
    exit_code    INTEGER,
    error        TEXT,
    report_json  TEXT,
    report_html  TEXT,
    summary_json TEXT
);
CREATE INDEX IF NOT EXISTS scans_by_user ON scans (user_id, created_at DESC);
"""


class ScanStore:
    """Async-friendly CRUD over the ``scans`` table."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = Path(db_path)

    # -- lifecycle -----------------------------------------------------------
    async def init(self) -> None:
        await asyncio.to_thread(self._init_sync)

    def _init_sync(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    # -- writes --------------------------------------------------------------
    async def create(self, scan: Scan) -> None:
        scan.created_at = scan.created_at or datetime.now(timezone.utc)
        await asyncio.to_thread(self._create_sync, scan)

    def _create_sync(self, scan: Scan) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scans (id, user_id, chat_id, target, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (scan.id, scan.user_id, scan.chat_id, scan.target, scan.status, _iso(scan.created_at)),
            )

    async def mark_running(self, scan_id: str) -> None:
        await asyncio.to_thread(self._set_status_sync, scan_id, "running")

    def _set_status_sync(self, scan_id: str, status: str) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE scans SET status = ? WHERE id = ?", (status, scan_id))

    async def finish(
        self,
        scan_id: str,
        *,
        status: str,
        exit_code: int | None,
        error: str | None,
        report_json: Path | None,
        report_html: Path | None,
        summary: Summary | None,
    ) -> None:
        await asyncio.to_thread(
            self._finish_sync, scan_id, status, exit_code, error, report_json, report_html, summary
        )

    def _finish_sync(
        self,
        scan_id: str,
        status: str,
        exit_code: int | None,
        error: str | None,
        report_json: Path | None,
        report_html: Path | None,
        summary: Summary | None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET status = ?, finished_at = ?, exit_code = ?, error = ?, "
                "report_json = ?, report_html = ?, summary_json = ? WHERE id = ?",
                (
                    status,
                    _iso(datetime.now(timezone.utc)),
                    exit_code,
                    error,
                    str(report_json) if report_json else None,
                    str(report_html) if report_html else None,
                    json.dumps(_summary_to_dict(summary)) if summary else None,
                    scan_id,
                ),
            )

    async def reclaim_orphans(self, reason: str) -> list[Scan]:
        """Mark every still-``queued``/``running`` scan failed and return them.

        Meant to run at startup: a scan can only be unfinished in the table if a
        crash or restart killed the in-process task driving it, so there is no
        live work to disturb. Returning the affected scans lets the bot tell those
        chats the truth instead of leaving a request forever "queued".
        """
        return await asyncio.to_thread(self._reclaim_orphans_sync, reason)

    def _reclaim_orphans_sync(self, reason: str) -> list[Scan]:
        finished_at = _iso(datetime.now(timezone.utc))
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans WHERE status IN ('queued', 'running')"
            ).fetchall()
            conn.execute(
                "UPDATE scans SET status = 'failed', error = ?, finished_at = ? "
                "WHERE status IN ('queued', 'running')",
                (reason, finished_at),
            )
        scans: list[Scan] = []
        for row in rows:
            scan = _row_to_scan(row)
            scan.status = "failed"
            scan.error = reason
            scan.finished_at = _parse_iso(finished_at)
            scans.append(scan)
        return scans

    # -- reads ---------------------------------------------------------------
    async def get(self, scan_id: str) -> Scan | None:
        return await asyncio.to_thread(self._get_sync, scan_id)

    def _get_sync(self, scan_id: str) -> Scan | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return _row_to_scan(row) if row else None

    async def recent_for_user(self, user_id: int, limit: int = 10) -> list[Scan]:
        return await asyncio.to_thread(self._recent_sync, user_id, limit)

    def _recent_sync(self, user_id: int, limit: int) -> list[Scan]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()
        return [_row_to_scan(row) for row in rows]

    async def recent(self, limit: int = 50) -> list[Scan]:
        """Newest scans across every user — the web UI's view of all activity."""
        return await asyncio.to_thread(self._recent_all_sync, limit)

    def _recent_all_sync(self, limit: int) -> list[Scan]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_row_to_scan(row) for row in rows]


# -- (de)serialisation ----------------------------------------------------------
def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat(timespec="seconds") if moment else None


def _parse_iso(text: str | None) -> datetime | None:
    return datetime.fromisoformat(text) if text else None


def _summary_to_dict(summary: Summary) -> dict[str, Any]:
    return {
        "ok": summary.ok,
        "severity_counts": summary.severity_counts,
        "subdomains": summary.subdomains,
        "live_hosts": summary.live_hosts,
        "duration_s": summary.duration_s,
        "findings": [
            {"name": f.name, "severity": f.severity, "target": f.target, "template_id": f.template_id}
            for f in summary.findings
        ],
    }


def _summary_from_dict(data: dict[str, Any]) -> Summary:
    return Summary(
        ok=bool(data.get("ok")),
        severity_counts=dict(data.get("severity_counts") or {}),
        findings=[
            Finding(
                name=str(f.get("name", "")),
                severity=str(f.get("severity", "unknown")),
                target=str(f.get("target", "")),
                template_id=str(f.get("template_id", "")),
            )
            for f in data.get("findings") or []
        ],
        subdomains=int(data.get("subdomains") or 0),
        live_hosts=int(data.get("live_hosts") or 0),
        duration_s=data.get("duration_s"),
    )


def _row_to_scan(row: sqlite3.Row) -> Scan:
    summary_json = row["summary_json"]
    return Scan(
        id=row["id"],
        user_id=row["user_id"],
        chat_id=row["chat_id"],
        target=row["target"],
        status=row["status"],
        created_at=_parse_iso(row["created_at"]),
        finished_at=_parse_iso(row["finished_at"]),
        exit_code=row["exit_code"],
        error=row["error"],
        report_json=row["report_json"],
        report_html=row["report_html"],
        summary=_summary_from_dict(json.loads(summary_json)) if summary_json else None,
    )
