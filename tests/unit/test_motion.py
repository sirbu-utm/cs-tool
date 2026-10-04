"""Terminal motion: the shared effects, the banner intro, the animated live views
and the rule that a pipe or CI only ever sees the final frame."""

from __future__ import annotations

import io

import pytest
from rich.console import Console
from rich.text import Text

from cyberfw import motion
from cyberfw.live_view import PipelineLiveView, TopologyView
from cyberfw.logging import THEME
from cyberfw.pipeline.engine import Node, NodeResult, PipelineResult, StageEvent
from cyberfw.pipeline.schemas import SubfinderResult
from cyberfw.ui import PIP, RULE_CHAR, GradientRule, banner


def _tty(height: int = 60, width: int = 100) -> tuple[Console, io.StringIO]:
    """A console that believes it is a real terminal (conftest exports TERM=dumb)."""
    buffer = io.StringIO()
    console = Console(
        file=buffer,
        theme=THEME,
        width=width,
        height=height,
        force_terminal=True,
        color_system="truecolor",
        _environ={"TERM": "xterm-256color"},
    )
    return console, buffer


def _text(renderable: object, width: int = 100) -> str:
    console = Console(theme=THEME, width=width, record=True, force_terminal=False)
    console.print(renderable)
    return console.export_text()


class _Clock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class TestWhenToAnimate:
    def test_only_a_real_terminal_animates(self) -> None:
        console, _ = _tty()
        assert motion.enabled(console)
        assert not motion.enabled(console, wanted=False)
        assert not motion.enabled(Console(file=io.StringIO(), force_terminal=False))
        assert not motion.enabled(Console(file=io.StringIO(), force_terminal=True, _environ={"TERM": "dumb"}))

    def test_without_animation_only_the_final_frame_is_rendered(self) -> None:
        asked: list[float] = []

        def frame(progress: float) -> Text:
            asked.append(progress)
            return Text(f"frame {progress:.2f}")

        buffer = io.StringIO()
        motion.play(Console(file=buffer, force_terminal=False), frame, duration=1.0)

        assert asked == [1.0]
        assert buffer.getvalue() == "frame 1.00\n"

    def test_animation_plays_forward_and_ends_on_the_final_frame(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(motion.time, "sleep", lambda _s: None)
        asked: list[float] = []

        def frame(progress: float) -> Text:
            asked.append(progress)
            return Text(f"frame {progress:.2f}")

        console, buffer = _tty()
        motion.play(console, frame, duration=0.5, fps=10)

        final, played = asked[0], asked[1:]  # the final frame is built first, then reused
        assert final == 1.0
        assert played == sorted(played) and played[0] == 0.0 and len(played) >= 5
        output = buffer.getvalue()
        assert output.rindex("frame 1.00") > output.rindex(f"frame {played[-1]:.2f}")

    def test_a_frame_taller_than_the_terminal_is_not_animated(self) -> None:
        """Live crops an overflowing frame to an ellipsis; print it whole instead."""
        asked: list[float] = []

        def frame(progress: float) -> Text:
            asked.append(progress)
            return Text("\n".join(["row"] * 30))

        console, _ = _tty(height=20)
        motion.play(console, frame, duration=0.5)

        assert asked == [1.0]


class TestEffects:
    def test_bar_fills_to_the_fraction_and_clamps(self) -> None:
        assert _text(motion.bar(0.5, 10, style="ok")).strip() == motion.BAR_FULL * 5 + motion.BAR_EMPTY * 5
        assert _text(motion.bar(2.0, 4, style="ok")).strip() == motion.BAR_FULL * 4
        assert _text(motion.bar(-1, 4, style="ok")).strip() == motion.BAR_EMPTY * 4

    def test_bar_shine_lights_one_filled_cell(self) -> None:
        bar = motion.bar(1.0, 10, style="ok", shine=0.5)
        bright = [span for span in bar.spans if "bright_white" in str(span.style)]
        assert len(bright) == 1 and bright[0].start == 5

    def test_scanner_is_a_three_cell_stroke_that_moves(self) -> None:
        frames = [motion.scanner(t / 10, 12, style="info") for t in range(14)]
        for frame in frames:
            assert frame.plain.count(motion.BAR_FULL) == 3
            assert len(frame.plain) == 12
        assert len({frame.plain for frame in frames}) > 3

    def test_fade_mark_cools_down_to_blank(self) -> None:
        marks = [motion.fade_mark(age / 10) for age in range(0, 12, 2)]
        assert marks[0] == "█" and marks[-1] == " "
        assert [m for m in marks if m != " "] == sorted((m for m in marks if m != " "), key=motion.FADE.index)

    def test_spinner_turns_with_time(self) -> None:
        assert len({motion.spinner(t / 8) for t in range(4)}) == 4

    def test_every_glyph_survives_the_classic_windows_console(self) -> None:
        """Code page 437 is what Consolas and Lucida Console carry; ▬ and ■ are
        checked against their cmaps in test_cli. Braille or ✓ would draw boxes."""
        checked_in_both_fonts = {"▬", "■"}
        glyphs = set(motion.SPINNER + motion.FADE + motion.NOISE + motion.BAR_FULL + motion.BAR_EMPTY + PIP)
        for glyph in glyphs - checked_in_both_fonts:
            glyph.encode("cp437")


class TestBannerIntro:
    STATES = ["ready", "ready", "blocked", "not installed"]

    def test_the_last_frame_is_the_banner(self) -> None:
        assert _text(banner(self.STATES, "linux/amd64", 1.0)) == _text(banner(self.STATES, "linux/amd64"))

    def test_every_frame_has_the_banners_height(self) -> None:
        """Nothing below the banner may jump while it plays."""
        height = _text(banner(self.STATES, "linux/amd64")).count("\n")
        for step in range(11):
            assert _text(banner(self.STATES, "linux/amd64", step / 10)).count("\n") == height

    def test_the_wordmark_starts_blank_and_materialises(self) -> None:
        first = _text(banner(self.STATES, "linux/amd64", 0.0))
        middle = _text(banner(self.STATES, "linux/amd64", 0.3))
        final = _text(banner(self.STATES, "linux/amd64"))
        wordmark_rows = slice(0, 8)

        def ink(text: str) -> int:
            return sum(len(line.strip()) for line in text.splitlines()[wordmark_rows])

        assert ink(first) == 0
        assert 0 < ink(middle) < ink(final) + 1

    def test_pips_light_up_and_the_counter_counts(self) -> None:
        start = _text(banner(self.STATES, "linux/amd64", 0.0))
        assert "0/4 ready" in start
        assert "2/4 ready" in _text(banner(self.STATES, "linux/amd64"))

    def test_the_rule_draws_itself_from_the_left(self) -> None:
        console = Console(theme=THEME, width=120, record=True, force_terminal=False)
        console.print(GradientRule(0.5))
        drawn = console.export_text().count(RULE_CHAR)
        console.print(GradientRule())
        full = console.export_text().count(RULE_CHAR)
        assert 0 < drawn < full


class TestAnimatedStageTable:
    def _view(self, clock: _Clock, **kwargs: object) -> PipelineLiveView:
        return PipelineLiveView([Node(tool="subfinder", stage="sub")], clock=clock, **kwargs)  # type: ignore[arg-type]

    def test_running_stage_spins_and_its_scanner_sweeps(self) -> None:
        clock = _Clock()
        view = self._view(clock)
        view.on_stage(StageEvent(kind="start", stage="sub", tool="subfinder", total=1))
        frame_a = _text(view.render())
        clock.t += 0.3
        frame_b = _text(view.render())

        assert any(glyph in frame_a for glyph in motion.SPINNER)
        assert frame_a != frame_b

    def test_without_animation_the_frame_holds_still(self) -> None:
        clock = _Clock()
        view = self._view(clock, animate=False)
        view.on_stage(StageEvent(kind="start", stage="sub", tool="subfinder", total=1))
        frame_a = _text(view.render())
        clock.t += 0.3
        frame_b = _text(view.render())

        assert not any(glyph in frame_a for glyph in motion.SPINNER)
        assert frame_a.replace("0.0s", "") == frame_b.replace("0.3s", "")

    def test_a_new_finding_gets_a_fading_mark(self) -> None:
        clock = _Clock()
        view = self._view(clock)
        view.on_stage(StageEvent(kind="start", stage="sub", tool="subfinder", total=1))
        view.on_record(SubfinderResult(tool="subfinder", target="a.example.com", kind="host"))

        assert "█" in _text(view.render())
        clock.t += 5
        assert not any(shade in _text(view.render()) for shade in motion.FADE)

    def test_finish_settles_the_frame_left_on_screen(self) -> None:
        clock = _Clock()
        view = self._view(clock)
        view.on_stage(StageEvent(kind="start", stage="sub", tool="subfinder", total=1))
        view.on_record(SubfinderResult(tool="subfinder", target="a.example.com", kind="host"))
        view.finish()

        text = _text(view.render())
        assert not any(glyph in text for glyph in motion.SPINNER + motion.FADE)

    def test_outcomes_share_the_banners_pip_and_bar(self) -> None:
        clock = _Clock()
        view = PipelineLiveView([Node(tool="gowitness", stage="shots")], clock=clock)
        view.on_stage(StageEvent(kind="start", stage="shots", tool="gowitness", total=4))
        view.on_stage(StageEvent(kind="progress", stage="shots", tool="gowitness", done=2, total=4))
        running = _text(view.render())
        view.on_stage(
            StageEvent(kind="done", stage="shots", tool="gowitness", result=NodeResult(node=Node("gowitness", "shots")))
        )
        done = _text(view.render())

        assert "2/4" in running and motion.BAR_EMPTY in running
        assert f"{PIP} ok" in done and motion.BAR_FULL * 10 in done


class TestAnimatedTopology:
    def test_the_header_carries_a_pip_per_stage(self) -> None:
        clock = _Clock()
        nodes = [Node("subfinder", "subs"), Node("httpx", "live"), Node("nuclei", "vulns")]
        view = TopologyView(nodes, seed="example.com", clock=clock)
        view.on_stage(StageEvent(kind="start", stage="subs", tool="subfinder", total=1))
        view.on_stage(StageEvent(kind="done", stage="subs", tool="subfinder", result=NodeResult(node=nodes[0])))
        view.on_stage(
            StageEvent(
                kind="done", stage="live", tool="httpx", result=NodeResult(node=nodes[1], ok=False, skipped=True)
            )
        )

        header = view.render().renderables[0]  # type: ignore[attr-defined]
        pips = [span for span in header.spans if header.plain[span.start : span.end] == PIP]
        assert [str(span.style) for span in pips] == ["ok", "warn", "muted"]

    def test_a_fresh_host_glows_then_cools(self) -> None:
        clock = _Clock()
        view = TopologyView([Node("subfinder", "subs")], seed="example.com", clock=clock)
        view.on_record(SubfinderResult(tool="subfinder", target="a.example.com", kind="host"))

        def host_style() -> str:
            tree = view.render().renderables[2]  # type: ignore[attr-defined]
            label = tree.children[0].label
            return next(str(s.style) for s in label.spans if label.plain[s.start : s.end] == "a.example.com")

        assert "on green" in host_style()
        clock.t += 5
        assert host_style() == "muted"


class TestCountingSummary:
    def test_numbers_count_up_to_the_result(self) -> None:
        from cyberfw.cli import _run_summary

        records = [SubfinderResult(tool="subfinder", target=f"h{i}.example.com", kind="host") for i in range(40)]
        result = PipelineResult(nodes=[NodeResult(node=Node("subfinder", "subs"), count=40)], records=records)

        def frame(progress: float) -> str:
            return _text(_run_summary(result, name="p", session_id="s", reports=[], progress=progress))

        assert "0 record(s)" in frame(0.0)
        assert "40 record(s)" in frame(1.0)
        assert "40 record(s)" not in frame(0.3)


class TestInstallProgress:
    def test_the_table_grows_over_a_progress_line(self) -> None:
        from cyberfw.cli import _InstallProgress

        progress = _InstallProgress(4, animate=True, clock=_Clock())
        progress.update("[info]checking[/info] nuclei ...")
        assert "0/4" in _text(progress) and "checking nuclei" in _text(progress)

        progress.add_row("subfinder", "2.6.6", "installed", "subfinder/subfinder")
        progress.advance()
        text = _text(progress)
        assert "subfinder" in text and "1/4" in text


class TestRenderingFromTheRefreshThread:
    """``Live`` renders on its own thread while the engine adds records; a deque or
    dict growing mid-iteration used to raise inside that thread and freeze the view."""

    @staticmethod
    def _hammer(view: PipelineLiveView | TopologyView) -> list[str]:
        import sys
        import threading

        errors: list[str] = []
        stop = threading.Event()
        console = Console(file=io.StringIO(), theme=THEME, width=100)

        def render() -> None:
            while not stop.is_set():
                try:
                    console.print(view.render())
                except RuntimeError as exc:  # pragma: no cover - the regression
                    errors.append(str(exc))
                    return
                console.file = io.StringIO()

        interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        thread = threading.Thread(target=render)
        try:
            view.on_stage(StageEvent(kind="start", stage="s", tool="subfinder", total=1))
            thread.start()
            for index in range(6000):
                view.on_record(SubfinderResult(tool="subfinder", target=f"h{index}.example.com", kind="host"))
        finally:
            stop.set()
            thread.join()
            sys.setswitchinterval(interval)
        return errors

    def test_the_stage_table(self) -> None:
        assert self._hammer(PipelineLiveView([Node("subfinder", "s")], tail=50)) == []

    def test_the_topology_map(self) -> None:
        assert self._hammer(TopologyView([Node("subfinder", "s")])) == []
