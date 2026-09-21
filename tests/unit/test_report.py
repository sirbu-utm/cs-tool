"""Unit tests for report generation (HTML + JSON) and the report package surface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberfw.exceptions import ReportError
from cyberfw.pipeline.engine import Node, NodeResult, PipelineResult
from cyberfw.pipeline.schemas import NucleiResult, SubfinderResult
from cyberfw.report import generate_html_report, generate_json_report
from cyberfw.report.html_report import generate_html_report as html_report_gen
from cyberfw.report.json_report import generate_json_report as json_report_gen


def _ok_result() -> PipelineResult:
    records = [
        SubfinderResult.from_json("subfinder", '{"host": "api.example.com", "source": "stub"}', 1),
        NucleiResult.from_json(
            "nuclei",
            '{"template-id": "t1", "matched-at": "https://api.example.com/", '
            '"info": {"name": "Chk", "severity": "low"}}',
            1,
        ),
    ]
    nodes = [
        NodeResult(node=Node(tool="subfinder", stage="subfinder"), ok=True, count=1),
        NodeResult(node=Node(tool="nuclei", stage="nuclei"), ok=True, count=1),
    ]
    return PipelineResult(nodes=nodes, records=records)


def _failed_result() -> PipelineResult:
    nodes = [NodeResult(node=Node(tool="subfinder", stage="subfinder"), ok=False, count=0, error="boom")]
    return PipelineResult(nodes=nodes, records=[])


class TestPackageSurface:
    def test_report_exports_both_generators(self) -> None:
        assert html_report_gen is generate_html_report
        assert json_report_gen is generate_json_report


class TestJsonReport:
    def test_writes_valid_report(self, tmp_path: Path) -> None:
        path = json_report_gen(_ok_result(), session_id="sess1", reports_dir=tmp_path)
        assert path == tmp_path / "sess1" / "report.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["ok"] is True
        assert payload["total_records"] == 2
        assert len(payload["stages"]) == 2
        assert any(r["target"] == "api.example.com" for r in payload["records"])

    def test_explicit_output_path_wins(self, tmp_path: Path) -> None:
        out = tmp_path / "custom" / "r.json"
        path = json_report_gen(_ok_result(), output_path=out)
        assert path == out
        assert out.exists()

    def test_unwritable_target_raises(self, tmp_path: Path) -> None:
        blocked = tmp_path / "is-a-dir"
        blocked.mkdir()
        with pytest.raises(ReportError):
            json_report_gen(_ok_result(), output_path=blocked)


class TestHtmlReport:
    def test_writes_self_contained_page(self, tmp_path: Path) -> None:
        path = html_report_gen(_ok_result(), session_id="s", reports_dir=tmp_path)
        text = path.read_text(encoding="utf-8")
        assert "<title>cyberfw report</title>" in text
        assert "success" in text
        assert "api.example.com" in text
        assert "Chk" in text
        assert "Stages" in text and "Records" in text

    def test_failed_status_pill(self, tmp_path: Path) -> None:
        text = html_report_gen(_failed_result(), output_path=tmp_path / "r.html").read_text(encoding="utf-8")
        assert "class=\"pill failed\">failed" in text

    def test_empty_result_renders_placeholders(self, tmp_path: Path) -> None:
        empty = PipelineResult(nodes=[], records=[])
        text = html_report_gen(empty, output_path=tmp_path / "e.html").read_text(encoding="utf-8")
        assert "no stages ran" in text
        assert "no records" in text

    def test_target_is_html_escaped(self, tmp_path: Path) -> None:
        result = PipelineResult(
            nodes=[NodeResult(node=Node(tool="subfinder", stage="subfinder"), ok=True, count=1)],
            records=[SubfinderResult.from_json("subfinder", '{"host": "<script>x</script>"}', 1)],
        )
        text = html_report_gen(result, output_path=tmp_path / "x.html").read_text(encoding="utf-8")
        assert "<script>" not in text
        assert "&lt;script&gt;" in text
