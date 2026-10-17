"""Render a saved ``report.json`` payload as CSV — a flat table of every record.

For triage in a spreadsheet; tool-agnostic (every column is read with ``.get``),
so a new record type needs no change here. Consumed by ``cyberfw export --csv``.
"""

from __future__ import annotations

import csv
import io
from typing import Any

__all__ = ["to_csv", "COLUMNS"]

COLUMNS = ["tool", "kind", "severity", "target", "detail", "muted"]


def _row(record: dict[str, Any]) -> dict[str, str]:
    info = record.get("info") or {}
    severity = info.get("severity") or record.get("severity") or ""
    detail = info.get("name") or record.get("description") or record.get("title") or ""
    return {
        "tool": str(record.get("tool") or ""),
        "kind": str(record.get("kind") or ""),
        "severity": str(severity),
        "target": str(record.get("target") or ""),
        "detail": str(detail),
        "muted": "true" if record.get("muted") else "false",
    }


def to_csv(payload: dict[str, Any]) -> str:
    """CSV text (header + one row per record) for a saved report payload."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS)
    writer.writeheader()
    for record in payload.get("records") or []:
        writer.writerow(_row(record))
    return buffer.getvalue()
