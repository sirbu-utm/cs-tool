"""JSON report generation from a pipeline result.

Writes a machine-readable summary and per-record listing to ``reports/<session>/<name>.json``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cyberfw.exceptions import ReportError
from cyberfw.logging import get_logger
from cyberfw.pipeline.engine import PipelineResult

LOG = get_logger("report.json")

__all__ = ["generate_json_report"]


def generate_json_report(
    result: PipelineResult,
    output_path: Path | None = None,
    *,
    session_id: str | None = None,
    reports_dir: Path | None = None,
) -> Path:
    """Write the JSON report and return its path.

    ``output_path`` takes priority; otherwise ``reports_dir / session_id /
    report.json`` is used (creating directories as needed).
    """
    path = _resolve_path(output_path, session_id, reports_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "ok": result.succeeded(),
        "stages": [
            {
                "tool": nr.node.tool,
                "stage": nr.node.stage,
                "ok": nr.ok,
                "count": nr.count,
                "error": nr.error,
            }
            for nr in result.nodes
        ],
        "total_records": len(result.records),
        "records": [r.as_dict() for r in result.records],
    }
    try:
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"cannot write {path}: {exc}") from exc
    LOG.info("JSON report written to %s", path)
    return path


def _resolve_path(output_path: Path | None, session_id: str | None, reports_dir: Path | None) -> Path:
    if output_path is not None:
        return output_path
    base = reports_dir or Path.cwd() / "reports"
    session = session_id or "default"
    return base / session / "report.json"
