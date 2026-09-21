"""HTML report generation from a pipeline result.

Writes a self-contained, dependency-free ``report.html`` under
``reports/<session>/`` that renders stage totals and the validated records in a
readable table. No external assets — everything is inline so the file can be
opened offline or emailed.
"""

from __future__ import annotations

import html
from pathlib import Path

from cyberfw.exceptions import ReportError
from cyberfw.logging import get_logger
from cyberfw.pipeline.engine import PipelineResult
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.report.run_info import RunInfo

LOG = get_logger("report.html")

__all__ = ["generate_html_report"]

#: Ordered human-facing headers for a record row.
_HEADERS = ["#", "tool", "kind", "target", "detail"]


def generate_html_report(
    result: PipelineResult,
    output_path: Path | None = None,
    *,
    session_id: str | None = None,
    reports_dir: Path | None = None,
    run: RunInfo | None = None,
) -> Path:
    """Write the HTML report and return its path.

    ``output_path`` takes priority; otherwise ``reports_dir / session_id /
    report.html`` is used (creating directories as needed). ``run`` supplies
    the provenance rows (pipeline, seed, timing, tool versions).
    """
    path = _resolve_path(output_path, session_id, reports_dir)
    path.parent.mkdir(parents=True, exist_ok=True)

    stages_rows = _render_stages(result)
    records_rows = _render_records(result.records)
    headers_row = "".join(f"<th>{h}</th>" for h in _HEADERS)

    page = _PAGE_TEMPLATE.format(
        ok="success" if result.succeeded() else "failed",
        totals=_totals_summary(result),
        total_records=len(result.records),
        run_rows=_render_run(result, run or RunInfo()),
        headers_row=headers_row,
        stages_rows=stages_rows,
        records_rows=records_rows,
    )
    try:
        path.write_text(page, encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"cannot write {path}: {exc}") from exc
    LOG.info("HTML report written to %s", path)
    return path


def _totals_summary(result: PipelineResult) -> str:
    """Comma-joined ``tool: count`` for the header line."""
    parts = [f"{tool}: {count}" for tool, count in result.totals_by_tool.items()]
    return " · ".join(parts) if parts else "no records"


def _render_run(result: PipelineResult, run: RunInfo) -> str:
    """Rows of the provenance table; every value is escaped (the seed is user input,
    tool versions come from install records)."""
    info = run.as_dict(result)
    versions = " · ".join(
        f"{tool} {version or '—'}" for tool, version in sorted(run.tool_versions.items())
    )
    duration = info["duration_s"]
    rows = [
        ("pipeline", info["pipeline"]),
        ("seed", info["seed"]),
        ("session", info["session_id"]),
        ("platform", info["platform"]),
        ("started (UTC)", info["started_at"]),
        ("duration", None if duration is None else f"{duration:.1f} s"),
        ("tools", versions or None),
        ("cyberfw", info["cyberfw_version"]),
    ]
    return "\n".join(f"<tr><th>{html.escape(label)}</th><td>{_cell(value)}</td></tr>" for label, value in rows)


def _cell(value: object) -> str:
    return '<span class="dim">—</span>' if value is None else html.escape(str(value))


def _render_stages(result: PipelineResult) -> str:
    """Rows for the per-stage summary table."""
    rows: list[str] = []
    for node_result in result.nodes:
        node = node_result.node
        status = "ok" if node_result.ok else "err"
        error = html.escape(node_result.error or "")
        error_cell = f'<td class="dim">{error}</td>' if node_result.error else "<td class=\"dim\">—</td>"
        rows.append(
            f'<tr><td>{html.escape(node.tool)}</td><td>{html.escape(node.stage)}</td>'
            f"<td>{node_result.count}</td><td class=\"{status}\">{status}</td>{error_cell}</tr>"
        )
    return "\n".join(rows) if rows else '<tr><td colspan="5" class="dim">no stages ran</td></tr>'


def _render_records(records: list[ToolRecord]) -> str:
    """Rows for the full record listing."""
    rows: list[str] = []
    for index, record in enumerate(records, start=1):
        rendered = _render_record(index, record)
        rows.append(rendered)
    return "\n".join(rows) if rows else '<tr><td colspan="5" class="dim">no records</td></tr>'


def _render_record(index: int, record: ToolRecord) -> str:
    detail = html.escape(_format_detail(record.as_dict()))
    return (
        f"<tr><td>{index}</td><td>{html.escape(record.tool)}</td>"
        f"<td>{html.escape(record.kind)}</td><td>{html.escape(record.target)}</td>"
        f"<td class=\"detail\">{detail}</td></tr>"
    )


def _format_detail(as_dict: dict[str, object]) -> str:
    """Flatten a record dict into a short, readable substring (first field wins)."""
    skip = {"tool", "line_number", "raw", "target", "kind", "stage"}
    seen: list[str] = []
    for key, value in as_dict.items():
        if key in skip or value in ("", None):
            continue
        seen.append(f"{key}={value if not isinstance(value, list) else ','.join(map(str, value))}")
    return " ".join(seen)


def _resolve_path(output_path: Path | None, session_id: str | None, reports_dir: Path | None) -> Path:
    if output_path is not None:
        return output_path
    base = reports_dir or Path.cwd() / "reports"
    session = session_id or "default"
    return base / session / "report.html"


#: Standalone, self-contained page. ``{...}`` placeholders are filled above; any
#: literal braces in the template would need escaping, so CSS uses no ``{}``.
_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>cyberfw report</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         margin: 0; padding: 24px; background: #f6f7f9; color: #1c1e21; }}
  .wrap {{ max-width: 1000px; margin: 0 auto; }}
  h1 {{ margin: 0 0 4px; font-size: 22px; }}
  .meta {{ color: #6b7380; margin-bottom: 20px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
          border-radius: 8px; overflow: hidden; margin-bottom: 28px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #e5e7eb;
          font-size: 13px; vertical-align: top; }}
  th {{ background: #eceef1; font-size: 11px; text-transform: uppercase;
       letter-spacing: .04em; }}
  .detail {{ word-break: break-word; }}
  table.run th {{ width: 160px; text-transform: none; letter-spacing: 0; font-size: 13px; }}
  .dim {{ color: #8a919c; }}
  .ok {{ color: #15803d; background: #f0fdf4; }}
  .err {{ color: #b91c1c; background: #fef2f2; }}
  .pill {{ display: inline-block; padding: 2px 10px; border-radius: 999px;
          font-size: 12px; font-weight: 600; }}
  .pill.success {{ background: #dcfce7; color: #15803d; }}
  .pill.failed {{ background: #fee2e2; color: #b91c1c; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #121417; color: #e4e6ea; }}
    table {{ background: #1b1f24; }}
    th {{ background: #262b31; }}
    th, td {{ border-bottom-color: #2c3138; }}
    .dim {{ color: #7d8590; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <h1>cyberfw report</h1>
  <div class="meta"><span class="pill {ok}">{ok}</span> · {totals} · {total_records} records</div>
  <h2>Run</h2>
  <table class="run"><tbody>
  {run_rows}
  </tbody></table>
  <h2>Stages</h2>
  <table><thead><tr><th>tool</th><th>stage</th><th>count</th><th>status</th><th>error</th></tr></thead>
  <tbody>
  {stages_rows}
  </tbody></table>
  <h2>Records</h2>
  <table><thead><tr>{headers_row}</tr></thead>
  <tbody>
  {records_rows}
  </tbody></table>
</div>
</body>
</html>
"""
