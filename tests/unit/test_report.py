"""Unit tests for report generation (HTML + JSON) and the report package surface."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cyberfw import __version__
from cyberfw.exceptions import ReportError
from cyberfw.pipeline.engine import Node, NodeResult, PipelineResult
from cyberfw.pipeline.schemas import NucleiResult, SubfinderResult
from cyberfw.report import generate_html_report, generate_json_report
from cyberfw.report.html_report import generate_html_report as html_report_gen
from cyberfw.report.json_report import generate_json_report as json_report_gen
from cyberfw.report.run_info import RunInfo


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

    def test_stages_carry_outcome_not_just_node_config(self, tmp_path: Path) -> None:
        """Each stage entry must expose the *run* outcome (ok/count/error), not only the Node config."""
        path = json_report_gen(_failed_result(), output_path=tmp_path / "r.json")
        stage = json.loads(path.read_text(encoding="utf-8"))["stages"][0]
        assert stage == {
            "tool": "subfinder",
            "stage": "subfinder",
            "ok": False,
            "skipped": False,
            "count": 0,
            "error": "boom",
        }

    def test_skipped_stages_are_marked_as_such(self, tmp_path: Path) -> None:
        """A consumer reading the report must be able to tell "this tool found nothing"
        from "this stage never ran because its source failed"."""
        nodes = [
            NodeResult(node=Node(tool="naabu", stage="ports"), ok=False, error="not installed"),
            NodeResult(node=Node(tool="httpx", stage="live_http"), ok=False, skipped=True, error="skipped: ..."),
        ]
        path = json_report_gen(PipelineResult(nodes=nodes, records=[]), output_path=tmp_path / "r.json")

        stages = json.loads(path.read_text(encoding="utf-8"))["stages"]
        assert stages[0]["skipped"] is False
        assert stages[1]["skipped"] is True

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


class TestRunProvenance:
    """A security report must say what was scanned, with which tool versions and when —
    otherwise a finding cannot be reproduced or attributed to a scanner release."""

    @staticmethod
    def _run_info() -> RunInfo:
        return RunInfo(
            pipeline="recon-to-vuln",
            seed="example.com",
            session_id="pipeline-recon-to-vuln-20260922-120000",
            platform="windows/amd64",
            tool_versions={"subfinder": "2.6.6", "nuclei": None},
        )

    def test_json_report_carries_the_run_block(self, tmp_path: Path) -> None:
        result = _ok_result()
        result.started_at = datetime(2026, 9, 22, 12, 0, 0, tzinfo=timezone.utc)
        result.finished_at = datetime(2026, 9, 22, 12, 0, 42, tzinfo=timezone.utc)

        path = json_report_gen(result, output_path=tmp_path / "r.json", run=self._run_info())

        run = json.loads(path.read_text(encoding="utf-8"))["run"]
        assert run["pipeline"] == "recon-to-vuln"
        assert run["seed"] == "example.com"
        assert run["session_id"] == "pipeline-recon-to-vuln-20260922-120000"
        assert run["platform"] == "windows/amd64"
        assert run["tool_versions"] == {"subfinder": "2.6.6", "nuclei": None}
        assert run["started_at"] == "2026-09-22T12:00:00+00:00"
        assert run["finished_at"] == "2026-09-22T12:00:42+00:00"
        assert run["duration_s"] == 42.0
        assert run["cyberfw_version"] == __version__
        assert run["generated_at"].endswith("+00:00")

    def test_json_report_without_run_info_still_has_the_block(self, tmp_path: Path) -> None:
        path = json_report_gen(_ok_result(), output_path=tmp_path / "r.json")

        run = json.loads(path.read_text(encoding="utf-8"))["run"]
        assert run["cyberfw_version"] == __version__
        assert run["pipeline"] is None and run["duration_s"] is None

    def test_html_report_shows_the_provenance(self, tmp_path: Path) -> None:
        result = _ok_result()
        result.started_at = datetime(2026, 9, 22, 12, 0, 0, tzinfo=timezone.utc)
        result.finished_at = datetime(2026, 9, 22, 12, 0, 42, tzinfo=timezone.utc)

        text = html_report_gen(result, output_path=tmp_path / "r.html", run=self._run_info()).read_text(
            encoding="utf-8"
        )

        assert "recon-to-vuln" in text
        assert "example.com" in text
        assert "subfinder 2.6.6" in text
        assert "windows/amd64" in text
        assert "42" in text and "2026-09-22" in text

    def test_html_seed_is_escaped(self, tmp_path: Path) -> None:
        run = RunInfo(pipeline="p", seed="<script>alert(1)</script>")
        text = html_report_gen(_ok_result(), output_path=tmp_path / "r.html", run=run).read_text(encoding="utf-8")
        assert "<script>alert(1)</script>" not in text
        assert "&lt;script&gt;" in text
