"""Tests for the live pipeline view and the semantic styling of records."""

from __future__ import annotations

from rich.console import Console

from cyberfw.live_view import PipelineLiveView, TopologyView
from cyberfw.logging import THEME
from cyberfw.motion import SPINNER
from cyberfw.pipeline.engine import Node, NodeResult, StageEvent
from cyberfw.pipeline.schemas import (
    FfufResult,
    HttpxResult,
    NaabuResult,
    NucleiResult,
    RustscanResult,
    SubfinderResult,
    ToolRecord,
)
from cyberfw.ui import record_detail, record_style


def _render(view: PipelineLiveView, width: int = 110) -> str:
    console = Console(theme=THEME, record=True, width=width, force_terminal=False)
    console.print(view.render())
    return console.export_text()


def _node(tool: str, stage: str) -> Node:
    return Node(tool=tool, stage=stage)


def _nuclei(severity: str) -> NucleiResult:
    return NucleiResult.from_json(
        "nuclei",
        '{"template-id": "t", "matched-at": "https://a.example.com/", '
        f'"info": {{"name": "Check", "severity": "{severity}"}}}}',
        1,
    )


def _httpx(status: int) -> HttpxResult:
    return HttpxResult.from_json("httpx", f'{{"url": "https://a.example.com/", "status_code": {status}}}', 1)


class TestRecordStyle:
    """Severity and HTTP status carry meaning; the table should show it at a glance."""

    def test_nuclei_severity_scales_from_muted_to_alarming(self) -> None:
        styles = {level: record_style(_nuclei(level)) for level in ("info", "low", "medium", "high", "critical")}
        assert styles["critical"] != styles["high"] != styles["medium"]
        assert "red" in styles["critical"]
        assert "yellow" in styles["medium"]
        assert styles["info"] == styles["low"]

    def test_unknown_severity_is_not_special_cased(self) -> None:
        assert record_style(_nuclei("bogus")) == record_style(SubfinderResult(tool="subfinder", target="a.example.com"))

    def test_http_status_classes(self) -> None:
        assert "green" in record_style(_httpx(200))
        assert "cyan" in record_style(_httpx(301))
        assert "yellow" in record_style(_httpx(404))
        assert "red" in record_style(_httpx(500))

    def test_a_record_without_either_signal_gets_a_neutral_style(self) -> None:
        assert record_style(SubfinderResult(tool="subfinder", target="a.example.com", kind="host")) == "white"


class TestRecordDetail:
    def test_severity_is_the_detail_for_nuclei(self) -> None:
        assert record_detail(_nuclei("high")) == "high"

    def test_ffuf_falls_back_to_its_status(self) -> None:
        detail = record_detail(FfufResult.from_json("ffuf", '{"url": "https://a/x", "status": 200, "length": 5}', 1))
        assert "200" in detail

    def test_empty_when_nothing_is_interesting(self) -> None:
        assert record_detail(ToolRecord(tool="x", target="t")) == ""


class TestStageTable:
    def test_pending_stages_are_listed_before_they_run(self) -> None:
        view = PipelineLiveView([_node("subfinder", "sub"), _node("httpx", "live")])

        text = _render(view)

        assert "subfinder" in text and "httpx" in text
        assert text.count("pending") == 2

    def test_running_stage_is_marked_and_counts_records(self) -> None:
        view = PipelineLiveView([_node("subfinder", "sub")])
        view.on_stage(StageEvent(kind="start", stage="sub", tool="subfinder", total=1))
        view.on_record(SubfinderResult(tool="subfinder", target="a.example.com", kind="host"))
        view.on_record(SubfinderResult(tool="subfinder", target="b.example.com", kind="host"))

        text = _render(view)

        assert "running" in text
        assert "2" in text

    def test_fan_out_progress_is_shown_as_done_of_total(self) -> None:
        view = PipelineLiveView([_node("gowitness", "shots")])
        view.on_stage(StageEvent(kind="start", stage="shots", tool="gowitness", total=12))
        view.on_stage(StageEvent(kind="progress", stage="shots", tool="gowitness", done=5, total=12))

        assert "5/12" in _render(view)

    def test_finished_stage_shows_its_outcome(self) -> None:
        view = PipelineLiveView([_node("subfinder", "sub")])
        view.on_stage(StageEvent(kind="start", stage="sub", tool="subfinder", total=1))
        view.on_stage(
            StageEvent(
                kind="done",
                stage="sub",
                tool="subfinder",
                result=NodeResult(node=_node("subfinder", "sub"), ok=True, count=3),
            )
        )

        text = _render(view)

        assert "ok" in text
        assert "running" not in text

    def test_failed_stage_shows_the_reason(self) -> None:
        view = PipelineLiveView([_node("nuclei", "vulns")])
        view.on_stage(StageEvent(kind="start", stage="vulns", tool="nuclei", total=1))
        view.on_stage(
            StageEvent(
                kind="done",
                stage="vulns",
                tool="nuclei",
                result=NodeResult(node=_node("nuclei", "vulns"), ok=False, error="nuclei timed out after 30s"),
            )
        )

        text = _render(view)

        assert "failed" in text
        assert "timed out" in text

    def test_a_skipped_stage_reads_as_skipped_not_failed(self) -> None:
        """"Skipped" tells the user to look upstream; "failed" would send them hunting
        for a fault in a tool that never ran."""
        view = PipelineLiveView([_node("httpx", "live_http")])
        view.on_stage(
            StageEvent(
                kind="done",
                stage="live_http",
                tool="httpx",
                result=NodeResult(node=_node("httpx", "live_http"), ok=False, skipped=True),
            )
        )

        text = _render(view)

        assert "skipped" in text
        assert "failed" not in text

    def test_a_long_note_does_not_squeeze_the_other_columns(self) -> None:
        """The skip reason is a sentence; letting it take the width turns the tool
        column into "nucl…" — the one thing the row is identified by."""
        view = PipelineLiveView([_node("nuclei", "vulns")])
        view.on_stage(
            StageEvent(
                kind="done",
                stage="vulns",
                tool="nuclei",
                result=NodeResult(
                    node=_node("nuclei", "vulns"),
                    ok=False,
                    skipped=True,
                    error="skipped: stage 'live_http' failed, so it produced no targets",
                ),
            )
        )

        text = _render(view, width=100)

        assert "nuclei" in text and "vulns" in text
        assert "skipped" in text

    def test_a_stage_not_in_the_plan_is_added_on_the_fly(self) -> None:
        """`run <tool>` drives a single node the view was not constructed with."""
        view = PipelineLiveView([])
        view.on_stage(StageEvent(kind="start", stage="adhoc", tool="ffuf", total=1))

        assert "ffuf" in _render(view)

    def test_elapsed_time_is_shown_for_a_running_stage(self) -> None:
        clock = iter([100.0, 107.5])
        view = PipelineLiveView([_node("nuclei", "vulns")], clock=lambda: next(clock))
        view.on_stage(StageEvent(kind="start", stage="vulns", tool="nuclei", total=1))

        assert "7.5s" in _render(view)

    def test_elapsed_time_freezes_when_the_stage_finishes(self) -> None:
        clock = iter([0.0, 3.0, 99.0])
        view = PipelineLiveView([_node("nuclei", "vulns")], clock=lambda: next(clock))
        view.on_stage(StageEvent(kind="start", stage="vulns", tool="nuclei", total=1))
        view.on_stage(
            StageEvent(
                kind="done", stage="vulns", tool="nuclei", result=NodeResult(node=_node("nuclei", "vulns"), ok=True)
            )
        )

        text = _render(view)

        assert "3.0s" in text
        assert "99" not in text


class TestRecordTail:
    def test_latest_records_are_shown(self) -> None:
        view = PipelineLiveView([_node("subfinder", "sub")])
        view.on_record(SubfinderResult(tool="subfinder", target="fresh.example.com", kind="host"))

        assert "fresh.example.com" in _render(view)

    def test_tail_is_bounded_to_the_most_recent(self) -> None:
        view = PipelineLiveView([_node("subfinder", "sub")], tail=3)
        for index in range(10):
            view.on_record(SubfinderResult(tool="subfinder", target=f"h{index}.example.com", kind="host"))

        text = _render(view)

        assert "h9.example.com" in text and "h7.example.com" in text
        assert "h6.example.com" not in text

    def test_placeholder_until_the_first_record(self) -> None:
        assert "no records yet" in _render(PipelineLiveView([_node("subfinder", "sub")]))

    def test_a_long_target_does_not_wrap_the_table(self) -> None:
        view = PipelineLiveView([_node("httpx", "live")], tail=1)
        view.on_record(HttpxResult(tool="httpx", target="https://" + "x" * 300 + ".example.com/", kind="http"))

        for line in _render(view, width=100).splitlines():
            assert len(line) <= 100


def _render_topology(view: TopologyView, width: int = 110) -> str:
    console = Console(theme=THEME, record=True, width=width, force_terminal=False)
    console.print(view.render())
    return console.export_text()


class _Clock:
    """A monotonic clock the test advances by hand, for deterministic animation."""

    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class TestTopologyView:
    def _nodes(self) -> list[Node]:
        return [_node("subfinder", "subdomains"), _node("httpx", "live_http"), _node("nuclei", "vulns")]

    def test_seed_is_the_root(self) -> None:
        view = TopologyView(self._nodes(), seed="example.com", title="topology")
        assert "example.com" in _render_topology(view)

    def test_a_discovered_host_becomes_a_branch(self) -> None:
        view = TopologyView(self._nodes(), seed="example.com")
        view.on_record(SubfinderResult.from_json("subfinder", '{"host": "a.example.com", "source": "crtsh"}', 1))

        text = _render_topology(view)

        assert "a.example.com" in text
        assert "crtsh" in text  # source shown until the host is proven live
        assert "1 hosts" in text

    def test_findings_attach_under_the_same_host_by_hostname(self) -> None:
        """subfinder finds the bare host; nuclei's URL finding must hang off the same node."""
        view = TopologyView(self._nodes(), seed="example.com")
        view.on_record(SubfinderResult.from_json("subfinder", '{"host": "a.example.com"}', 1))
        view.on_record(HttpxResult.from_json("httpx", '{"url": "https://a.example.com/", "status_code": 200, "title": "Home"}', 1))
        view.on_record(
            NucleiResult.from_json(
                "nuclei",
                '{"template-id": "rce", "matched-at": "https://a.example.com/x", '
                '"info": {"name": "Critical RCE", "severity": "critical"}}',
                1,
            )
        )

        text = _render_topology(view)

        # One host node carrying its live status and the finding — not three nodes.
        assert text.count("a.example.com") == 1
        assert "200" in text and "Home" in text
        assert "critical" in text and "Critical RCE" in text
        assert "1 live" in text and "1 vulns" in text

    def test_ports_from_naabu_and_rustscan(self) -> None:
        view = TopologyView(self._nodes(), seed="example.com")
        view.on_record(NaabuResult.from_json("naabu", '{"host": "a.example.com", "port": 443}', 1))
        view.on_record(RustscanResult.from_json("rustscan", '{"host": "a.example.com", "ports_list": "22,80"}', 2))

        text = _render_topology(view)

        assert "ports" in text
        for port in ("22", "80", "443"):
            assert port in text

    def test_hosts_are_capped_with_a_more_line(self) -> None:
        view = TopologyView(self._nodes(), seed="example.com")
        for i in range(45):
            view.on_record(SubfinderResult(tool="subfinder", target=f"h{i}.example.com", kind="host"))

        text = _render_topology(view)

        assert "more host(s)" in text  # 45 > _MAX_HOSTS (40)

    def test_vulns_per_host_are_capped(self) -> None:
        view = TopologyView(self._nodes(), seed="example.com")
        for i in range(9):
            view.on_record(
                NucleiResult.from_json(
                    "nuclei",
                    f'{{"template-id": "t{i}", "matched-at": "https://a.example.com/{i}", '
                    '"info": {"name": "Issue", "severity": "low"}}',
                    i,
                )
            )

        text = _render_topology(view)

        assert "more finding(s)" in text  # 9 > _MAX_VULNS_PER_HOST (6)

    def test_spinner_animates_while_a_stage_runs_and_settles_when_idle(self) -> None:
        clock = _Clock()
        view = TopologyView(self._nodes(), seed="example.com", clock=clock)

        # Idle before anything starts: a steady bullet, no spinner frame.
        assert "•" in _render_topology(view)

        view.on_stage(StageEvent(kind="start", stage="subdomains", tool="subfinder", total=1))
        clock.t = 1000.0
        frame_a = _render_topology(view)
        clock.t = 1000.25  # advance time → the spinner frame must change
        frame_b = _render_topology(view)
        spinner = set(SPINNER)
        assert any(ch in spinner for ch in frame_a)
        assert frame_a != frame_b

        view.on_stage(
            StageEvent(kind="done", stage="subdomains", tool="subfinder", result=NodeResult(node=_node("subfinder", "subdomains"), ok=True)),
        )
        assert "•" in _render_topology(view)
