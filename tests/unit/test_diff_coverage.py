"""Repeated tool stages must all finish before an absence can be trusted."""

from __future__ import annotations

from typing import Any

import pytest

from cyberfw.report.diff import compare, coverage


def _stage(name: str, *, tool: str = "nuclei", ok: bool = True, skipped: bool = False) -> dict[str, Any]:
    return {"tool": tool, "stage": name, "ok": ok, "skipped": skipped}


def _finding() -> dict[str, Any]:
    return {
        "tool": "nuclei",
        "kind": "vuln",
        "template_id": "exposed-admin",
        "target": "https://example.com/admin",
        "info": {"name": "Exposed admin", "severity": "high"},
    }


def _report(stages: list[dict[str, Any]], *, finding: bool = False) -> dict[str, Any]:
    return {"stages": stages, "records": [_finding()] if finding else []}


@pytest.mark.parametrize(
    ("ok", "skipped"),
    [(False, False), (False, True), (True, True)],
    ids=["failed", "skipped", "skipped-with-ok"],
)
@pytest.mark.parametrize("incomplete_first", [False, True], ids=["incomplete-last", "incomplete-first"])
def test_any_incomplete_stage_removes_only_its_tools_coverage(
    ok: bool, skipped: bool, incomplete_first: bool
) -> None:
    stages = [_stage("cve"), _stage("exposure", ok=ok, skipped=skipped)]
    if incomplete_first:
        stages.reverse()
    stages.append(_stage("live", tool="httpx"))

    assert coverage(_report(stages)) == {"httpx"}


def test_all_successful_stages_keep_their_tools_coverage() -> None:
    report = _report([_stage("cve"), _stage("exposure"), _stage("live", tool="httpx")])

    assert coverage(report) == {"nuclei", "httpx"}


@pytest.mark.parametrize("incomplete_side", ["old", "new"])
@pytest.mark.parametrize("skipped", [False, True], ids=["failed", "skipped"])
def test_incomplete_repeated_stage_does_not_invent_added_or_removed_findings(
    incomplete_side: str, skipped: bool
) -> None:
    complete = [_stage("cve"), _stage("exposure")]
    incomplete = [_stage("cve"), _stage("exposure", ok=False, skipped=skipped)]
    if incomplete_side == "new":
        old, new = _report(complete, finding=True), _report(incomplete)
        expected_side = "this run"
    else:
        old, new = _report(incomplete), _report(complete, finding=True)
        expected_side = "the earlier run"

    changes = compare(old, new)

    assert changes.changes == []
    assert changes.not_compared == [
        f"nuclei did not run (or did not finish) in {expected_side}, so its results were not compared"
    ]
    assert changes.new_findings_at_least("low") == 0


def test_complete_repeated_stages_still_report_a_removed_finding() -> None:
    stages = [_stage("cve"), _stage("exposure")]

    changes = compare(_report(stages, finding=True), _report(stages))

    assert [(change.area, change.status, change.subject) for change in changes.changes] == [
        ("finding", "removed", "Exposed admin")
    ]
    assert changes.not_compared == []


def test_incomplete_httpx_coverage_does_not_imply_complete_tls_checks() -> None:
    report = _report([_stage("live", tool="httpx"), _stage("alternate", tool="httpx", ok=False)])
    report["records"] = [{"tool": "httpx", "kind": "http", "tls": {"host": "example.com"}}]

    assert "httpx" not in coverage(report)
    assert "tlscheck" not in coverage(report)


def test_incomplete_tool_does_not_remove_independent_post_scan_coverage() -> None:
    report = _report([_stage("cve"), _stage("exposure", ok=False)])
    report["records"] = [
        {"tool": "mailcheck", "kind": "mail"},
        {"tool": "virustotal", "kind": "reputation"},
    ]

    assert coverage(report) == {"mailcheck", "virustotal"}
