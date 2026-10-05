"""The HUD frame language and the screens built from it: what they show, that
they stay inside the classic Windows console's glyphs and the window's width,
and that they stay readable in 16 colours and on a pipe."""

from __future__ import annotations

import io
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from rich.cells import cell_len
from rich.color import Color, ColorSystem
from rich.console import Console, RenderableType
from rich.segment import Segment
from rich.text import Text

import cyberfw.logging
from cyberfw import __version__, cli
from cyberfw.config import Settings
from cyberfw.hud import BRAND, KEY, ByWidth, HudFrame, Pane, PathText, hud_table, keycap
from cyberfw.live_view import PipelineLiveView
from cyberfw.logging import THEME
from cyberfw.pipeline.engine import Node, NodeResult, PipelineResult, StageEvent
from cyberfw.pipeline.schemas import NucleiResult, RustscanResult, SubfinderResult, ToolRecord
from cyberfw.ui import Masthead, banner, tool_guide

#: Outside code page 437, but checked against Consolas and Lucida Console (▬ ■)
#: or already drawn by the app before this redesign (● ○ ▲ — → …).
_ALLOWED = set("▬■●○▲—→…")

_ROWS = [
    cli._ToolRow("ffuf", "2.1.0", "ready", "ffuf/ffuf"),
    cli._ToolRow("gitleaks", "8.21.2", "blocked", "gitleaks/gitleaks"),
    cli._ToolRow("naabu", "", "not installed", "projectdiscovery/naabu"),
    cli._ToolRow("nuclei", "3.3.7", "ready", "projectdiscovery/nuclei"),
]


def _settings(tmp_path: Path) -> Settings:
    return Settings(root_dir=tmp_path)


def _nuclei(severity: str, name: str = "Finding") -> NucleiResult:
    return NucleiResult.from_json(
        "nuclei",
        f'{{"template-id": "t", "matched-at": "https://a.example.com/x", "info": {{"name": "{name}", "severity": "{severity}"}}}}',
        1,
    )


def _failed_run() -> PipelineResult:
    nodes = [
        NodeResult(node=Node("subfinder", "subs"), ok=True, count=2),
        NodeResult(node=Node("httpx", "live_http"), ok=False, error="httpx exited with code 7"),
        NodeResult(node=Node("nuclei", "vulns"), ok=False, skipped=True, error="skipped: stage 'live_http' failed"),
    ]
    records = [SubfinderResult(tool="subfinder", target=f"h{i}.example.com", kind="host") for i in range(2)]
    start = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
    return PipelineResult(nodes=nodes, records=records, started_at=start, finished_at=start + timedelta(seconds=754.2))


def _screens(tmp_path: Path) -> dict[str, RenderableType]:
    settings = _settings(tmp_path)
    reports = [("json", tmp_path / "reports" / "pipeline-x-20261005-120000" / "report.json")]
    view = PipelineLiveView([Node("subfinder", "subs"), Node("nuclei", "vulns")], title="pipeline x · example.com")
    view.on_stage(StageEvent(kind="start", stage="subs", tool="subfinder", total=1))
    view.on_record(SubfinderResult(tool="subfinder", target="a.example.com", kind="host"))
    states = [row.state for row in _ROWS]
    return {
        "banner": banner(states, "windows/amd64"),
        "masthead": Masthead(states, "windows/amd64", subtitle="status"),
        "launcher": cli._LauncherView(_ROWS, settings),
        "guide": tool_guide("nuclei", state="ready", version="3.3.7", repo="projectdiscovery/nuclei"),
        "status": cli._status_view(_ROWS, settings, chrome=r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        "summary-failed": cli._run_summary(_failed_run(), name="recon", session_id="s1", reports=reports),
        "records": cli._record_table([_nuclei("critical"), _nuclei("high"), _nuclei("info")], tool="nuclei", target="x"),
        "live": view.render(),
    }


def _render(renderable: RenderableType, *, width: int, colors: str | None = None) -> tuple[str, list[Segment]]:
    """Plain text and the segments the terminal would get."""
    buffer = io.StringIO()
    console = Console(
        file=buffer,
        theme=THEME,
        width=width,
        force_terminal=colors is not None,
        color_system=colors,  # type: ignore[arg-type]
        no_color=colors is None,
        _environ={"TERM": "xterm-256color"},
    )
    segments = list(console.render(renderable))
    console.print(renderable)
    plain = re.sub(r"\x1b\[[0-9;]*m", "", buffer.getvalue())
    return plain, segments


def _assert_joints_meet(lines: list[str]) -> None:
    """Every ``│`` in a body has a ``╤`` / ``╧`` / ``╪`` in the borders above
    and below it: no tag, meta or footer sits on a joint."""
    borders = [i for i, line in enumerate(lines) if line[:1] in ("╔", "╠", "╚")]
    for row, line in enumerate(lines):
        for x, char in enumerate(line):
            if char != "│":
                continue
            above = max(i for i in borders if i < row)
            below = min(i for i in borders if i > row)
            assert lines[above][x] in "╤╪", f"no joint above column {x}: {lines[above]!r}"
            assert lines[below][x] in "╧╪", f"no joint below column {x}: {lines[below]!r}"


class TestEveryScreen:
    """Rendered the way a pipe and an old console get them."""

    @pytest.mark.parametrize("width", [80, 110])
    def test_glyphs_stay_inside_code_page_437(self, tmp_path: Path, width: int) -> None:
        for name, screen in _screens(tmp_path).items():
            plain, _ = _render(screen, width=width)
            for char in set(plain) - _ALLOWED - {"\n"}:
                try:
                    char.encode("cp437")
                except UnicodeEncodeError:  # pragma: no cover - the regression
                    pytest.fail(f"{name}: {char!r} (U+{ord(char):04X}) is not in code page 437")

    @pytest.mark.parametrize("width", [80, 110])
    def test_no_line_is_wider_than_the_window(self, tmp_path: Path, width: int) -> None:
        for name, screen in _screens(tmp_path).items():
            plain, _ = _render(screen, width=width)
            widest = max(len(line) for line in plain.splitlines())
            assert widest <= width, f"{name} is {widest} columns wide at {width}"

    @pytest.mark.parametrize("colors", ["truecolor", "256", "standard"])
    def test_no_bold_text_on_a_coloured_background(self, tmp_path: Path, colors: str) -> None:
        """Bold black turns grey on conhost and most terminals: the first
        prototype's tags, header band and keycaps were unreadable."""
        for name, screen in _screens(tmp_path).items():
            _, segments = _render(screen, width=110, colors=colors)
            for segment in segments:
                style = segment.style
                if style and style.bgcolor and style.color and style.color.name == "black":
                    assert not style.bold, f"{name}: bold black on a colour in {segment.text!r}"


class TestFrame:
    def test_tags_name_the_sections_in_the_border(self) -> None:
        frame = HudFrame([Pane(Text("body"), title="Tools"), Pane(Text("more"), title="Keys")], footer="hint")
        plain, _ = _render(frame, width=40)
        lines = plain.splitlines()

        assert lines[0].startswith("╔═ Tools ═") and lines[0].endswith("╗")
        assert lines[2].startswith("╠═ Keys ═") and lines[2].endswith("╣")
        assert lines[-1].startswith("╚") and lines[-1].endswith(" hint ═╝")
        assert frame.title == "Tools"

    def test_a_too_long_tag_is_shortened_not_dropped(self) -> None:
        plain, _ = _render(HudFrame([Pane(Text("x"), title="An extremely long section name")]), width=20)
        assert "An extre" in plain.splitlines()[0] and "…" in plain.splitlines()[0]

    def test_side_by_side_panes_join_the_borders(self) -> None:
        frame = HudFrame([[Pane(Text("left")), Pane(Text("right"), width=10)], Pane(Text("below"))])
        plain, _ = _render(frame, width=50)
        lines = plain.splitlines()

        assert "╤" in lines[0] and "│" in lines[1] and "╧" in lines[2]

    def test_side_by_side_panes_stack_when_the_shared_one_would_be_too_narrow(self) -> None:
        frame = HudFrame([[Pane(Text("left")), Pane(Text("right"), width=10)], Pane(Text("below"))])
        plain, _ = _render(frame, width=40)
        lines = plain.splitlines()

        assert "│" not in plain and lines[1].startswith("║ left") and lines[3].startswith("║ right")
        assert all(cell_len(line) == 40 for line in lines)

    @pytest.mark.parametrize("title", ["例え.jp scan", "scan 🔥 done", "café menu"])
    def test_wide_and_combining_characters_keep_the_frame_whole(self, title: str) -> None:
        """A tag, meta or footer is laid out per screen cell, not per character."""
        frame = HudFrame([Pane(Text("body"), title=title, meta="メタ")], footer="フッター")
        plain, _ = _render(frame, width=40)
        lines = plain.splitlines()

        assert all(cell_len(line) == 40 for line in lines), [cell_len(line) for line in lines]
        assert lines[0].endswith("╗") and lines[-1].endswith("╝")
        assert title in lines[0] and "メタ" in lines[0] and "フッター" in lines[-1]

    def test_tags_never_cover_a_joint(self) -> None:
        frame = HudFrame(
            [
                [Pane(Text("a"), title="Alpha", width=8), Pane(Text("b"), title="Gamma")],
                Pane(Text("c"), title="Example long tag"),
            ]
        )
        plain, _ = _render(frame, width=40)
        lines = plain.splitlines()

        assert "│" in lines[1]
        _assert_joints_meet(lines)
        assert "Alpha" in lines[0] and "Gamma" in lines[0]
        divider = lines[2]
        assert "Example long tag" in divider, "the tag moves past the joint, it is not dropped"
        assert divider.index("╧") < divider.index("Example long tag")

    def test_a_footer_that_would_cover_a_joint_is_left_out(self) -> None:
        row = [Pane(Text("left")), Pane(Text("right"), width=8)]
        covering, _ = _render(HudFrame([row], footer="everything is nominal here"), width=40)
        clear, _ = _render(HudFrame([row], footer="ok"), width=40)

        assert "nominal" not in covering and "╧" in covering.splitlines()[-1]
        _assert_joints_meet(covering.splitlines())
        assert clear.splitlines()[-1].endswith(" ok ═╝")

    def test_border_runs_are_merged(self) -> None:
        """One segment per cell costs a console write each on conhost."""
        _, segments = _render(HudFrame([Pane(Text("x"))]), width=100, colors="standard")
        top = []
        for segment in segments:
            if segment.text == "\n":
                break
            top.append(segment)
        assert len(top) <= 6

    def test_the_header_band_is_one_colour_below_truecolor(self) -> None:
        """A word in the band must not straddle two hard colour blocks."""
        table = hud_table()
        table.add_column("tool")
        table.add_column("capability")
        table.add_row("ffuf", "Web fuzzing")
        frame = HudFrame([Pane(table, pad=0)])

        def header_backgrounds(colors: str) -> set[str]:
            _, segments = _render(frame, width=60, colors=colors)
            header = Segment.split_lines(segments)
            return {str(s.style.bgcolor) for s in list(header)[1] if s.style and s.style.bgcolor}

        assert len(header_backgrounds("standard")) == 1
        assert len(header_backgrounds("256")) == 1
        assert len(header_backgrounds("truecolor")) > 10

    def test_a_head_band_outside_a_frame_still_prints(self) -> None:
        table = hud_table()
        table.add_column("tool")
        table.add_row("ffuf")
        _, segments = _render(table, width=20, colors="truecolor")
        header = [s for s in segments if s.style and s.style.bgcolor]
        assert header and all(s.style.color == Color.parse("black") for s in header if s.style and s.text.strip())

    def test_without_colour_tags_are_plain_words(self) -> None:
        frame = HudFrame([Pane(Text("x"), title="Tools")], palette=BRAND)
        plain, _ = _render(frame, width=30)
        assert plain.splitlines()[0].startswith("╔═ Tools ═")
        mono = Console(file=io.StringIO(), width=30, color_system=None)
        tag = [s for s in mono.render(frame) if "Tools" in s.text]
        assert tag and tag[0].style and tag[0].style.reverse, "a tag still stands out without colour"


class TestParts:
    def test_keycap_reads_like_the_old_sidebar(self) -> None:
        assert keycap("1-9", "select tool").plain == " 1-9  select tool"
        assert keycap("r", "run pipeline").plain == " r    run pipeline"

    def test_keycaps_never_stack_in_a_column(self, tmp_path: Path) -> None:
        """Terminal rows have no gap: keys drawn under keys fuse into a stripe."""
        _, segments = _render(cli._LauncherView(_ROWS, _settings(tmp_path)), width=110, colors="truecolor")
        lines: list[list[Segment]] = [[]]
        for segment in segments:
            if segment.text == "\n":
                lines.append([])
            else:
                lines[-1].append(segment)
        with_keys = [i for i, line in enumerate(lines) if any(s.style and s.style.bgcolor == KEY.bgcolor for s in line)]
        assert len(with_keys) == 2
        assert with_keys[1] - with_keys[0] > 1

    def test_paths_wrap_after_a_separator(self) -> None:
        path = r"C:\Users\student\cs-tool\reports\pipeline-recon-to-vuln-20261005-101500\report.json"
        plain, _ = _render(PathText(path), width=40)
        lines = plain.splitlines()

        assert len(lines) > 1
        assert all(line.endswith("\\") for line in lines[:-1])
        assert lines[-1].endswith("report.json")

    def test_a_part_longer_than_the_column_is_folded(self) -> None:
        plain, _ = _render(PathText("x" * 30), width=12)
        assert [len(line) for line in plain.splitlines()] == [12, 12, 6]

    def test_by_width_lays_out_for_the_width_it_gets(self) -> None:
        renderable = ByWidth(lambda width: Text("wide" if width >= 100 else "narrow"))
        assert _render(renderable, width=120)[0].strip() == "wide"
        assert _render(renderable, width=80)[0].strip() == "narrow"


class TestScreens:
    def test_masthead_is_three_rows_with_the_ramp(self) -> None:
        plain, _ = _render(Masthead(["ready", "blocked"], "linux/amd64", subtitle="status"), width=110)
        lines = plain.splitlines()

        assert len(lines) == 3
        assert "1/2 ready" in lines[0] and "1 blocked" in lines[0]
        assert "linux/amd64" in lines[1] and "status" in lines[1]
        assert "▄▄▄▄" in lines[2]

    def test_masthead_leaves_out_the_attention_words_when_narrow(self) -> None:
        plain, _ = _render(Masthead(["ready", "blocked"], "linux/amd64"), width=80)
        assert "1/2 ready" in plain and "1 blocked" not in plain

    @pytest.mark.parametrize("tools", [4, 8, 20])
    def test_masthead_drops_art_rather_than_clip_it(self, tools: int) -> None:
        states = (["ready", "blocked", "not installed", "ready"] * 5)[:tools]
        count = f"{states.count('ready')}/{tools} ready"
        for width in range(30, 121):
            plain, _ = _render(Masthead(states, "windows/amd64", subtitle="status"), width=width)

            assert "…" not in plain, f"clipped at {width}"
            assert max(cell_len(line) for line in plain.splitlines()) <= width, f"too wide at {width}"
            assert count in plain and f"v{__version__}" in plain, f"readout lost at {width}"

    @pytest.mark.parametrize("width", [40, 44, 50, 60, 80])
    def test_tool_card_holds_its_frame_in_a_narrow_window(self, width: int) -> None:
        card = tool_guide("subfinder", state="ready", version="v2.6.3", repo="projectdiscovery/subfinder")
        plain, _ = _render(card, width=width)
        lines = plain.splitlines()

        assert all(cell_len(line) == width for line in lines), [cell_len(line) for line in lines]
        assert all(line[-1] in "║╗╝╣" for line in lines)
        assert "Subdomain" in plain, "the description wraps between words"
        assert "v2.6.3" in plain and "projectdiscovery/subfinder" in plain

    def test_banner_plate_says_what_needs_attention(self) -> None:
        plain, _ = _render(banner(["ready", "blocked", "not installed"], "linux/amd64"), width=110)
        assert "1/3 ready" in plain and "1 blocked · 1 not installed" in plain

    def test_launcher_shows_capabilities_only_when_wide(self, tmp_path: Path) -> None:
        wide, _ = _render(cli._LauncherView(_ROWS, _settings(tmp_path)), width=110)
        narrow, _ = _render(cli._LauncherView(_ROWS, _settings(tmp_path)), width=80)

        assert "capability" in wide and "Web fuzzing" in wide
        assert "capability" not in narrow
        for text in (wide, narrow):
            assert "1-4  select tool" in text and "r    run pipeline" in text
            assert "animations" in text and "type a key, then Enter" in text

    def test_launcher_entrance_keeps_the_columns_still(self, tmp_path: Path) -> None:
        final, _ = _render(cli._LauncherView(_ROWS, _settings(tmp_path)), width=110)
        halfway, _ = _render(cli._LauncherView(_ROWS, _settings(tmp_path), progress=0.4), width=110)

        assert final.splitlines()[1] == halfway.splitlines()[1], "the header row does not move"
        assert "nuclei" in final and "nuclei" not in halfway
        assert len(final.splitlines()) == len(halfway.splitlines())

    def test_unavailable_tools_are_greyed_with_a_real_grey(self, tmp_path: Path) -> None:
        """The classic console ignores dim, and Solarized Dark draws bright black
        in its background colour: muted is a grey, which Rich lowers to bright
        black (colour 8) on the classic console."""
        muted = THEME.styles["muted"]
        assert not muted.dim and muted.color is not None and muted.color != Color.parse("bright_black")
        # Downgraded directly: a theme style caches its first rendering's codes.
        assert muted.color.downgrade(ColorSystem.WINDOWS).number == 8, "bright black on the classic console"
        assert muted.color.downgrade(ColorSystem.EIGHT_BIT).number == 246

        table = cli._tools_table(_ROWS, numbered=True, capability=False)
        name_cells = list(table.columns[1].cells)
        assert str(name_cells[1].style) == "muted" and str(name_cells[0].style) == "tool"

    def test_tool_card_carries_the_facts(self) -> None:
        plain, _ = _render(tool_guide("nuclei", state="blocked", version=None, repo="projectdiscovery/nuclei"), width=110)

        assert "Vulnerability scanning" in plain
        assert "■ blocked" in plain and "—" in plain and "projectdiscovery/nuclei" in plain
        assert "$ nuclei -u https://example.com -jsonl" in plain

    def test_tool_card_without_facts_is_just_the_card(self) -> None:
        plain, _ = _render(tool_guide("nuclei"), width=110)
        assert "Vulnerability scanning" in plain and "state" not in plain

    def test_status_view_has_its_three_sections(self, tmp_path: Path) -> None:
        plain, _ = _render(cli._status_view(_ROWS, _settings(tmp_path), chrome=None), width=80)

        for words in ("Tools", "External dependencies", "Effective settings", "tools dir", "■ missing", "stage_timeout"):
            assert words in plain

    def test_failed_summary_names_the_reason_and_the_skipped_stage(self) -> None:
        plain, _ = _render(cli._run_summary(_failed_run(), name="recon", session_id="s1", reports=[]), width=110)

        assert "failed" in plain and "2 record(s)" in plain and "elapsed 754.2s (12m34s)" in plain
        issues = plain[plain.index("Issues") :]
        assert "■ failed" in issues and "live_http (httpx)" in issues and "exited with code 7" in issues
        assert "httpx exited" not in issues, "the tool is not named twice"
        assert "■ skipped" in issues and "vulns (nuclei)" in issues
        assert "live_http" in plain.split("failed")[-1]

    def test_failed_summary_wears_the_alert_ramp(self) -> None:
        assert cli._run_summary(_failed_run(), name="r", session_id="s", reports=[]).palette is not BRAND

    def test_failed_summary_tags_are_not_on_dark_red_in_16_colours(self) -> None:
        """Black on dark red is about 2:1 on the classic console palette."""
        summary = cli._run_summary(_failed_run(), name="recon", session_id="s1", reports=[])
        _, segments = _render(summary, width=80, colors="standard")
        tags = [s for s in segments if s.style and s.style.bgcolor and s.style.color == Color.parse("black")]

        assert {s.text.strip() for s in tags} >= {"recon", "Issues", "Output"}
        assert all(s.style and s.style.bgcolor and s.style.bgcolor.name != "red" for s in tags)

    @pytest.mark.parametrize("width", [20, 36, 40])
    def test_narrow_summary_keeps_every_count(self, width: int) -> None:
        plain, _ = _render(cli._run_summary(_failed_run(), name="recon", session_id="s1", reports=[]), width=width)
        lines = plain.splitlines()

        assert all(cell_len(line) == width for line in lines)
        for tool, count in (("subfinder", 2), ("httpx", 0), ("nuclei", 0)):
            line = next(line for line in lines if line.startswith(f"║  {tool} "))
            assert line.rstrip("║ ").endswith(f" {count}"), line

    def test_summary_paths_keep_the_file_name_whole(self, tmp_path: Path) -> None:
        report = tmp_path / ("very-long-directory-name-" * 3) / "pipeline-x-20261005-120000" / "report.html"
        result = PipelineResult(nodes=[NodeResult(node=Node("subfinder", "s"))])
        plain, _ = _render(cli._run_summary(result, name="r", session_id="s", reports=[("html", report)]), width=80)
        assert "report.html" in plain

    def test_record_table_tallies_severities(self) -> None:
        frame = cli._record_table([_nuclei("critical", "RCE"), _nuclei("high"), _nuclei("high")], tool="nuclei", target="x")
        plain, _ = _render(frame, width=110)

        assert "severity" in plain and " critical " in plain and "RCE" in plain
        assert "critical 1  high 2" in plain.splitlines()[-1]
        assert "kind vuln" in plain.splitlines()[0]

    def test_record_table_lists_kinds_only_when_they_differ(self) -> None:
        records: list[ToolRecord] = [
            SubfinderResult(tool="subfinder", target="a.example.com", kind="host"),
            RustscanResult.from_json("rustscan", '{"host": "10.0.0.1", "ports_list": "22,80"}', 1),
        ]
        plain, _ = _render(cli._record_table(records), width=110)

        assert "10.0.0.1:22" in plain and "10.0.0.1:80" in plain and "22,80" not in plain
        assert "kind" in plain.splitlines()[1] and "3 record(s)" in plain

    def test_live_frame_keeps_to_the_window_height(self) -> None:
        view = PipelineLiveView([Node("subfinder", "subs")], tail=30)
        view.on_stage(StageEvent(kind="start", stage="subs", tool="subfinder", total=1))
        for i in range(30):
            view.on_record(SubfinderResult(tool="subfinder", target=f"h{i}.example.com", kind="host"))
        plain, _ = _render(view.render(height=20), width=110)

        assert len(plain.splitlines()) < 20
        assert "h29.example.com" in plain and "h0.example.com" not in plain

    def test_the_settled_live_frame_keeps_every_finding(self) -> None:
        """``Live`` prints its last frame in full; with ``--no-report`` the tail
        is the only place the findings are shown."""
        view = PipelineLiveView([Node("subfinder", "subs")])
        view.on_stage(StageEvent(kind="start", stage="subs", tool="subfinder", total=1))
        for i in range(8):
            view.on_record(SubfinderResult(tool="subfinder", target=f"h{i}.example.com", kind="host"))

        def shown() -> str:
            buffer = io.StringIO()
            short = Console(file=buffer, theme=THEME, width=110, height=12, force_terminal=True, color_system=None)
            short.print(view)
            return buffer.getvalue()

        assert "h0.example.com" not in shown(), "a running frame keeps to the window"
        view.finish()
        settled = shown()
        assert all(f"h{i}.example.com" in settled for i in range(8))


class TestPrompts:
    def test_questions_open_with_the_lead_in(self) -> None:
        assert cli.Prompt("Target").make_prompt("").plain.startswith("» Target")
        assert cli.Confirm("Save?").make_prompt(True).plain.startswith("» Save?")

    def test_questions_are_asked_on_the_themed_console(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Rich's global console has no theme: the lead-in's style would drop."""
        assert cli.Prompt("x").console is cyberfw.logging.console
        assert cli.Confirm("x").console is cyberfw.logging.console

        buffer = io.StringIO()
        themed = Console(file=buffer, theme=THEME, force_terminal=True, color_system="truecolor", no_color=False)
        monkeypatch.setattr(cli, "console", themed)
        prompt = cli.Prompt("x")
        assert prompt.console is themed, "looked up when asked, not at import"
        prompt.console.print(prompt.make_prompt(None), end="")
        assert re.match(r"\x1b\[[0-9;]+m» ", buffer.getvalue()), repr(buffer.getvalue())


class TestStartScreen:
    @staticmethod
    def _play(monkeypatch: pytest.MonkeyPatch, height: int, tmp_path: Path) -> str:
        buffer = io.StringIO()
        console = Console(file=buffer, theme=THEME, width=110, height=height, force_terminal=False)
        monkeypatch.setattr(cli, "console", console)
        cli._start_screen(_ROWS, "linux/amd64", _settings(tmp_path))
        return buffer.getvalue()

    def test_a_tall_window_gets_the_big_banner(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        out = self._play(monkeypatch, 60, tmp_path)
        assert "▄▄▄▄▄▄▄▄▄▄▄" in out.splitlines()[0] and "╔═ Tools" in out

    def test_a_short_window_gets_the_masthead(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        out = self._play(monkeypatch, 24, tmp_path)
        assert out.splitlines()[0].startswith("█▀▀ █▀▀") and "╔═ Tools" in out

    def test_a_tiny_window_still_gets_both(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        out = self._play(monkeypatch, 10, tmp_path)
        assert out.splitlines()[0].startswith("█▀▀ █▀▀") and "╔═ Tools" in out
