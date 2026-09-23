"""Typer CLI unit tests — end-to-end commands through CliRunner.

Uses a temporary workspace with fake tool binaries and a local registry.yaml,
so the whole code path runs without network and without real precompiled tools.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from cyberfw.cli import _prompt_choice, _tool_menu, app
from cyberfw.logging import THEME
from cyberfw.ui import TOOL_GUIDES, banner, tool_guide

runner = CliRunner()

#: JSONL each fake tool prints, keyed by its argv[0] role.
_FAKE_OUTPUT = {
    "subfinder": '{"host": "sub.example.com", "source": "stub"}\n',
    "httpx": '{"url": "https://sub.example.com/", "status_code": 200, "title": "Home"}\n',
    "nuclei": (
        '{"template-id": "xss", "matched-at": "https://sub.example.com/", '
        '"info": {"name": "XSS check", "severity": "medium"}}\n'
    ),
    "ffuf": '{"url": "https://sub.example.com/admin", "status": 200, "length": 12}\n',
}


def _write_fake_binaries(tools_dir: Path) -> None:
    tools_dir.mkdir(parents=True, exist_ok=True)
    for name, payload in _FAKE_OUTPUT.items():
        binary = tools_dir / name
        binary.write_text(
            "#!/usr/bin/env bash\n" f'printf "%s" \'{payload}\'\n',
            encoding="utf-8",
        )
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)


def _silence_tool(root: Path, tool: str) -> None:
    """Replace a workspace binary with one that succeeds but prints nothing."""
    binary = root / "tools_bin" / tool
    binary.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)


def _break_tool(root: Path, tool: str, exit_code: int = 7) -> None:
    """Replace a workspace binary with one that exits non-zero."""
    binary = root / "tools_bin" / tool
    binary.write_text(f"#!/usr/bin/env bash\nexit {exit_code}\n", encoding="utf-8")
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)


def _write_registry(root: Path) -> None:
    lines = [
        f"{name}:\n  repo: org/{name}\n  asset_patterns: []\n  binary: {name}\n"
        for name in _FAKE_OUTPUT
    ]
    (root / "registry.yaml").write_text("\n".join(lines), encoding="utf-8")


@pytest.fixture(autouse=True)
def _workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_fake_binaries(tmp_path / "tools_bin")
    _write_registry(tmp_path)
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def fake_github(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> object:
    """Serve one release of ``pinme`` without the network by swapping ToolManager.client."""
    import io
    import zipfile

    from cyberfw.manager import ToolManager
    from cyberfw.manager.github_client import GitHubRelease, ReleaseAsset

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("pinme", "#!/usr/bin/env bash\necho hi\n")
    archive = buffer.getvalue()

    class FakeClient:
        downloads = 0

        def release(self, owner: str, repo: str, tag: str) -> GitHubRelease:
            return GitHubRelease(
                tag="v1.2.3",
                assets=[ReleaseAsset("pinme_1.2.3_windows_amd64.zip", "http://x", len(archive)),
                        ReleaseAsset("pinme_1.2.3_linux_amd64.zip", "http://x", len(archive)),
                        ReleaseAsset("pinme_1.2.3_darwin_amd64.zip", "http://x", len(archive)),
                        ReleaseAsset("pinme_1.2.3_darwin_arm64.zip", "http://x", len(archive)),
                        ReleaseAsset("pinme_1.2.3_linux_arm64.zip", "http://x", len(archive))],
                checksums_url=None,
            )

        def download(self, url: str, destination: Path, *, expected_size: int | None = None) -> None:
            FakeClient.downloads += 1
            destination.write_bytes(archive)

        def fetch_text(self, url: str) -> str:
            return ""

        def close(self) -> None:
            pass

    fake = FakeClient()
    monkeypatch.setattr(ToolManager, "client", property(lambda self: fake))
    with (tmp_path / "registry.yaml").open("a", encoding="utf-8") as handle:
        handle.write("pinme:\n  repo: org/pinme\n  asset_patterns: ['pinme_*']\n  binary: pinme\n  needs_checksum: false\n")
    return FakeClient


class TestHelpAndUnknown:
    def test_root_help(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Integrated Cybersecurity Framework" in result.stdout

    def test_unknown_pipeline(self) -> None:
        result = runner.invoke(app, ["pipeline", "nope", "-t", "x.com"])
        assert result.exit_code == 2

    def test_no_args_opens_interactive_launcher(self, monkeypatch: pytest.MonkeyPatch) -> None:
        opened = False

        def fake_menu() -> None:
            nonlocal opened
            opened = True

        monkeypatch.setattr("cyberfw.cli.interactive_menu", fake_menu)
        result = runner.invoke(app, [])

        assert result.exit_code == 0
        assert opened

    def test_tool_menu_numbers_registered_tools(self, tmp_path: Path) -> None:
        from cyberfw.config import Settings
        from cyberfw.manager import ToolManager, load_registry

        settings = Settings(root_dir=tmp_path, tools_dir=tmp_path / "tools_bin")
        registry_path = tmp_path / "registry.yaml"
        _write_registry(tmp_path)
        manager = ToolManager(settings, load_registry(registry_path))
        try:
            rendered = _tool_menu(manager)
        finally:
            manager.close()

        assert rendered.columns[0].header == "#"
        assert len(rendered.rows) == len(_FAKE_OUTPUT)

    def test_every_tool_has_usage_guide(self) -> None:
        assert set(TOOL_GUIDES) == {
            "ffuf",
            "gitleaks",
            "gowitness",
            "httpx",
            "naabu",
            "nuclei",
            "rustscan",
            "subfinder",
        }
        assert "gitleaks" in str(tool_guide("gitleaks").title)


class TestBanner:
    """The startup banner: wordmarks, a gradient rule and a status strip whose pips
    show, at a glance, how much of the toolbox is actually usable."""

    @staticmethod
    def _render(states: list[str], platform: str = "windows/amd64") -> str:
        output = Console(theme=THEME, record=True, width=100)
        output.print(banner(states, platform))
        return output.export_text()

    @staticmethod
    def _segments(renderable: object) -> list:
        """Rendered segments, styles resolved through the theme (what the terminal gets)."""
        console = Console(theme=THEME, width=100, color_system="truecolor")
        return list(console.render(renderable))  # type: ignore[arg-type]

    @pytest.mark.parametrize("logo_name", ["CS_TOOL_LOGO", "UNIV_LOGO"])
    def test_each_wordmark_is_kept(self, logo_name: str) -> None:
        """Checked per logo: a substring both logos share would pass with either missing."""
        from rich.text import Text

        import cyberfw.ui as ui

        rendered = self._render(["ready"] * 8)
        own_lines = [line for line in Text.from_ansi(getattr(ui, logo_name)).plain.splitlines() if line.strip()]

        assert own_lines
        assert all(line.rstrip() in rendered for line in own_lines)

    def test_the_byline_is_gone(self) -> None:
        rendered = self._render(["ready"] * 8)

        assert "Integrated Cybersecurity Framework" not in rendered
        assert "workspace ready" not in rendered

    def test_one_pip_per_tool(self) -> None:
        from cyberfw.ui import PIP

        rendered = self._render(["ready"] * 8)

        assert rendered.count(PIP) == 8
        assert "8/8 ready" in rendered

    def test_only_the_runnable_tools_are_counted(self) -> None:
        from cyberfw.ui import PIP

        rendered = self._render(["ready", "ready", "blocked", "not installed", "ready"], "linux/arm64")

        assert rendered.count(PIP) == 5
        assert "3/5 ready" in rendered

    def test_platform_and_version_are_shown(self) -> None:
        from cyberfw import __version__

        rendered = self._render(["ready"], "darwin/arm64")

        assert "darwin/arm64" in rendered
        assert f"v{__version__}" in rendered

    def test_a_gradient_rule_separates_the_wordmark(self) -> None:
        from cyberfw.ui import RULE_CHAR

        rendered = self._render(["ready"])

        assert RULE_CHAR * 20 in rendered, "a continuous rule, not a dotted one"

    def test_an_empty_registry_reads_0_of_0(self) -> None:
        """An empty registry is a state worth showing, not the absence of one."""
        rendered = self._render([])

        assert "0/0 ready" in rendered

    def test_each_state_gets_its_own_colour(self) -> None:
        """Compared as a set: a chained != never compares the first and the last."""
        from cyberfw.ui import state_style

        assert len({state_style(s) for s in ("ready", "blocked", "not installed")}) == 3
        assert state_style("who knows") != state_style("ready"), "unknown must not pass for ready"

    def test_pips_keep_their_own_colour(self) -> None:
        """The separator's muted style used to become the whole strip's base style,
        so every pip and the counter came out dim."""
        from cyberfw.ui import PIP

        segments = self._segments(banner(["ready", "blocked", "not installed"], "windows/amd64"))
        pips = [seg for seg in segments if seg.text == PIP or PIP in seg.text]

        assert pips, "the pips were rendered"
        assert not any(seg.style and seg.style.dim for seg in pips)

    def test_pips_and_the_inventory_table_share_one_style_map(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One state, one colour: change the map and both views follow."""
        import cyberfw.ui as ui
        from cyberfw.cli import _inventory_table
        from cyberfw.config import Settings
        from cyberfw.manager import ToolManager, load_registry

        monkeypatch.setitem(ui.STATE_STYLES, "ready", "magenta")
        settings = Settings(root_dir=tmp_path)
        manager = ToolManager(settings, load_registry(tmp_path / "registry.yaml"))
        try:
            table, states = _inventory_table(manager, settings.tools_dir)
        finally:
            manager.close()
        state_column = next(column for column in table.columns if column.header == "state")
        cell_styles = {str(cell.style) for cell in state_column._cells}

        assert set(states) == {"ready"}
        assert cell_styles == {"magenta"}
        assert ui.state_style("ready") == "magenta"

    @staticmethod
    def _rule_colour_runs(color_system: str, width: int = 100) -> dict[str, int]:
        """Cells per SGR colour code, as the terminal receives the rule.

        Parsed from real output: console.render() hands back the colours before
        Rich downgrades them to the terminal's palette, which is exactly where a
        truecolor ramp falls apart.
        """
        import io
        import re

        from cyberfw.ui import RULE_CHAR, gradient_rule

        buffer = io.StringIO()
        # no_color=False: conftest exports NO_COLOR, which would strip every code.
        console = Console(
            file=buffer,
            theme=THEME,
            width=width,
            force_terminal=True,
            color_system=color_system,  # type: ignore[arg-type]
            no_color=False,
        )
        console.print(gradient_rule())
        runs: dict[str, int] = {}
        for code, cells in re.findall(r"\x1b\[([0-9;]*)m(" + re.escape(RULE_CHAR) + "+)", buffer.getvalue()):
            runs[code] = runs.get(code, 0) + len(cells)
        return runs

    @staticmethod
    def _wordmark_width() -> int:
        from rich.cells import cell_len
        from rich.text import Text

        import cyberfw.ui as ui

        return max(cell_len(line) for line in Text.from_ansi(ui.CS_TOOL_LOGO).plain.splitlines())

    def test_truecolor_draws_a_smooth_ramp(self) -> None:
        assert len(self._rule_colour_runs("truecolor")) > 20

    @pytest.mark.parametrize("color_system", ["standard", "windows", "256"])
    def test_the_gradient_survives_a_limited_palette(self, color_system: str) -> None:
        """Downgraded cell by cell, the ramp came out as 10 green cells and 68 cyan
        ones on a 16-colour terminal: a seam near one end, not a gradient."""
        runs = self._rule_colour_runs(color_system)
        total = sum(runs.values())

        assert len(runs) >= 3, runs
        assert max(runs.values()) <= total / 2, f"one colour takes over the rule: {runs}"

    def test_the_rule_is_exactly_as_wide_as_the_wordmark(self) -> None:
        assert sum(self._rule_colour_runs("truecolor", width=120).values()) == self._wordmark_width()

    def test_the_rule_reports_its_real_width(self) -> None:
        """Measured as (0, max_width), it made a Panel(expand=False) around it fill the
        whole terminal with blank cells."""
        from rich.measure import Measurement
        from rich.panel import Panel

        from cyberfw.ui import gradient_rule

        console = Console(theme=THEME, width=120)
        measured = Measurement.get(console, console.options, gradient_rule())
        panel = Console(theme=THEME, width=120, record=True)
        panel.print(Panel(gradient_rule(), expand=False))

        assert measured.maximum == self._wordmark_width()
        assert max(len(line) for line in panel.export_text().splitlines()) <= self._wordmark_width() + 4

    def test_every_glyph_exists_in_the_classic_windows_console_fonts(self) -> None:
        """Checked against the cmaps of consola.ttf and lucon.ttf: ▰ is in neither, and
        ━ and the rounded corners ╭╮╰╯ are missing from Lucida Console, so a conhost
        window drew boxes. These are present in both."""
        from cyberfw.ui import PIP, RULE_CHAR

        in_both_fonts = set("■▬█▄▀─═┌┐└┘│")
        rendered = self._render(["ready", "blocked"])

        assert PIP in in_both_fonts
        assert RULE_CHAR in in_both_fonts
        assert not set("╭╮╰╯") & set(rendered)


class TestPromptChoice:
    """Regression coverage: a typo/slash-command must not crash the launcher.

    There is no slash-command navigation in the interactive menu — only the
    numbers under SHORTCUTS are valid. Typing e.g. ``/settings`` (a feature
    that does not exist) must show a helpful hint and re-prompt, not raise.
    """

    def test_invalid_input_reprompts_with_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        answers = iter(["/settings", "notanumber", "3"])
        monkeypatch.setattr("cyberfw.cli.Prompt.ask", lambda *_a, **_k: next(answers))

        result = _prompt_choice(["a", "b", "c"])

        assert result == "3"

    def test_valid_choice_returned_immediately(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("cyberfw.cli.Prompt.ask", lambda *_a, **_k: "0")

        assert _prompt_choice(["a", "b"]) == "0"

    def test_settings_hotkeys_are_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key in ("p", "l", "f", "P", "L", "F"):
            monkeypatch.setattr("cyberfw.cli.Prompt.ask", lambda *_a, _k=key, **_kw: _k)
            assert _prompt_choice(["a", "b"]) == key.lower()


class TestSettingsToggle:
    """The p/l/f hotkeys flip settings by exporting CYBERFW_* env vars."""

    @pytest.fixture(autouse=True)
    def _isolate_env(self) -> Iterator[None]:
        keys = ("CYBERFW_PARSE", "CYBERFW_LOG_TO_FILE", "CYBERFW_LOG_LEVEL")
        saved = {k: os.environ.get(k) for k in keys}
        for k in keys:
            os.environ.pop(k, None)
        yield
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _settings(self, tmp_path: Path, **overrides: object) -> object:
        from cyberfw.config import Settings

        return Settings(root_dir=tmp_path, **overrides)

    def test_p_toggles_parse_off(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyberfw.cli import _toggle_setting

        monkeypatch.delenv("CYBERFW_PARSE", raising=False)
        _toggle_setting("p", self._settings(tmp_path, parse=True))
        assert os.environ["CYBERFW_PARSE"] == "false"

    def test_f_toggles_log_to_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyberfw.cli import _toggle_setting

        monkeypatch.delenv("CYBERFW_LOG_TO_FILE", raising=False)
        _toggle_setting("f", self._settings(tmp_path, log_to_file=True))
        assert os.environ["CYBERFW_LOG_TO_FILE"] == "false"

    def test_l_cycles_log_level(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyberfw.cli import _toggle_setting

        monkeypatch.delenv("CYBERFW_LOG_LEVEL", raising=False)
        _toggle_setting("l", self._settings(tmp_path, log_level="INFO"))
        assert os.environ["CYBERFW_LOG_LEVEL"] == "WARNING"


class TestRunCommand:
    def test_run_subfinder_streams_record(self) -> None:
        result = runner.invoke(app, ["run", "subfinder", "-t", "example.com"])
        assert result.exit_code == 0
        assert "CYBERFW" not in result.stdout
        assert "sub.example.com" in result.stdout

    def test_run_without_target_exits_2(self) -> None:
        result = runner.invoke(app, ["run", "subfinder"])
        assert result.exit_code == 2

    def test_run_unknown_tool_exits_1(self) -> None:
        result = runner.invoke(app, ["run", "bogus", "-t", "x"])
        assert result.exit_code == 1

    def test_gitleaks_rejects_url_target(self) -> None:
        result = runner.invoke(app, ["run", "gitleaks", "-t", "https://utm.md/"])
        assert result.exit_code == 2
        assert "local repository directory" in result.stdout

    def test_no_parse_streams_raw_stdout_and_stderr(self, tmp_path: Path) -> None:
        """--no-parse must pass through every line verbatim, schema or not."""
        binary = tmp_path / "tools_bin" / "subfinder"
        binary.write_text(
            "#!/usr/bin/env bash\n"
            'echo "banner: subfinder v2.6.0 (not JSON)" >&2\n'
            'printf "%s\\n" \'not-json-either\'\n'
            'printf "%s\\n" \'{"host": "sub.example.com", "source": "stub"}\'\n',
            encoding="utf-8",
        )
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)

        result = runner.invoke(app, ["run", "subfinder", "-t", "example.com", "--no-parse"])

        assert result.exit_code == 0
        # a line that would be silently dropped by schema parsing must survive
        assert "not-json-either" in result.stdout
        # stderr diagnostics are streamed too, not just captured for error tails
        assert "banner: subfinder v2.6.0" in result.stdout
        # the raw JSON line still comes through as plain text, unparsed
        assert '{"host": "sub.example.com", "source": "stub"}' in result.stdout

    def test_run_httpx_streams_record(self) -> None:
        result = runner.invoke(app, ["run", "httpx", "-t", "example.com"])
        assert result.exit_code == 0
        assert "sub.example.com" in result.stdout

    def test_plain_run_creates_no_session_folder(self, tmp_path: Path) -> None:
        """Without --save, run must not litter reports/ with an empty session dir."""
        result = runner.invoke(app, ["run", "subfinder", "-t", "example.com"])
        assert result.exit_code == 0
        assert not (tmp_path / "reports").exists() or not any((tmp_path / "reports").iterdir())

    def test_save_flag_persists_session_folder(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["run", "subfinder", "-t", "example.com", "--save"])
        assert result.exit_code == 0
        assert "saved:" in result.stdout
        sessions = list((tmp_path / "reports").iterdir())
        assert len(sessions) == 1
        assert (sessions[0] / "subfinder.jsonl").exists()

    def test_empty_result_prints_explicit_message(self, tmp_path: Path) -> None:
        binary = tmp_path / "tools_bin" / "subfinder"
        binary.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)

        result = runner.invoke(app, ["run", "subfinder", "-t", "example.com"])

        assert result.exit_code == 0
        assert "No records found." in result.stdout

    def test_header_echoes_the_target_the_user_typed(self) -> None:
        result = runner.invoke(app, ["run", "subfinder", "-t", "example.com"])
        assert result.exit_code == 0
        assert "target: example.com" in result.stdout

    def test_rustscan_ports_list_expands_to_one_row_per_port(self, tmp_path: Path) -> None:
        """A dozen ports crammed into one greppable line must render as a real table."""
        (tmp_path / "registry.yaml").write_text(
            "rustscan:\n  repo: RustScan/RustScan\n  asset_patterns: []\n  binary: rustscan\n",
            encoding="utf-8",
        )
        binary = tmp_path / "tools_bin" / "rustscan"
        binary.write_text(
            "#!/usr/bin/env bash\nprintf '%s\\n' '185.199.175.191 -> [443,80,21]'\n",
            encoding="utf-8",
        )
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)

        result = runner.invoke(app, ["run", "rustscan", "-t", "https://ltnvg.buiucanidets.md/"])

        assert result.exit_code == 0
        # one row per port, numerically sorted, not a comma blob in one cell
        assert "185.199.175.191:21" in result.stdout
        assert "185.199.175.191:80" in result.stdout
        assert "185.199.175.191:443" in result.stdout
        assert "21,80,443" not in result.stdout
        # the header still shows what the user actually asked to scan
        assert "target: https://ltnvg.buiucanidets.md/" in result.stdout


class TestPipelineCommand:
    def test_pipeline_recon_to_vuln_ok(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com"])
        assert result.exit_code == 0
        assert "report.json" in result.stdout
        assert "report.html" in result.stdout
        # Verify the report files were actually written
        matches = list((tmp_path / "reports").rglob("report.html"))
        assert len(matches) == 1
        assert "sub.example.com" in matches[0].read_text(encoding="utf-8")

    def test_pipeline_no_report_flag(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "x.com", "--no-report"])
        assert result.exit_code == 0
        assert "report.json" not in result.stdout

    def test_pipeline_ffuf_without_wordlist_warns_and_does_not_crash(self, tmp_path: Path) -> None:
        """--ffuf with no wordlist warns upfront and the fuzz stage skips cleanly."""
        result = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--ffuf", "--no-report"]
        )
        assert "needs a wordlist" in result.stdout
        assert "Traceback" not in result.stdout

    def test_pipeline_no_parse_streams_raw_stage_output(self, tmp_path: Path) -> None:
        """--no-parse shows each stage's raw stdout (incl. non-JSON) AND still threads."""
        subfinder = tmp_path / "tools_bin" / "subfinder"
        subfinder.write_text(
            "#!/usr/bin/env bash\n"
            "echo 'subfinder progress chatter (not json)'\n"
            'printf "%s\\n" \'{"host": "sub.example.com", "source": "stub"}\'\n',
            encoding="utf-8",
        )
        subfinder.chmod(subfinder.stat().st_mode | stat.S_IEXEC)

        result = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-parse", "--no-report"]
        )

        assert result.exit_code == 0
        # raw non-JSON chatter that parsing would drop is shown verbatim
        assert "subfinder progress chatter (not json)" in result.stdout
        # threading still worked: httpx/nuclei ran off subfinder's parsed host
        assert "sub.example.com" in result.stdout


class TestInitCommand:
    def test_init_empty_registry_exits_0(self) -> None:
        """An empty registry (``{}``) should succeed with zero tools installed."""
        (Path.cwd() / "registry.yaml").write_text("{}\n", encoding="utf-8")
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "0 tool" in result.stdout

    def test_second_init_reports_up_to_date_and_skips_the_download(self, fake_github: object) -> None:
        first = runner.invoke(app, ["init", "pinme"])
        second = runner.invoke(app, ["init", "pinme"])

        # Presentation is a table now: tool and version are separate cells.
        assert first.exit_code == 0 and "pinme" in first.stdout and "1.2.3" in first.stdout
        assert second.exit_code == 0
        assert "up to date" in second.stdout
        assert fake_github.downloads == 1  # type: ignore[attr-defined]

    def test_force_reinstalls(self, fake_github: object) -> None:
        runner.invoke(app, ["init", "pinme"])
        result = runner.invoke(app, ["init", "pinme", "--force"])

        assert result.exit_code == 0
        assert "up to date" not in result.stdout
        assert fake_github.downloads == 2  # type: ignore[attr-defined]


class TestStatusCommand:
    def test_status_shows_tools_deps_and_settings(self) -> None:
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        # the fake-binary workspace tools resolve as ready
        assert "subfinder" in result.stdout and "ready" in result.stdout
        assert "External dependencies" in result.stdout
        assert "Effective settings" in result.stdout
        assert "log_level" in result.stdout
        assert "stage_timeout" in result.stdout

    def test_doctor_is_an_alias_for_status(self) -> None:
        assert runner.invoke(app, ["doctor"]).exit_code == 0

    def test_status_flags_a_present_but_unreadable_binary_as_blocked(self, tmp_path: Path) -> None:
        """A downloaded-but-unreadable binary (e.g. Defender-blocked) shows 'blocked'."""
        binary = tmp_path / "tools_bin" / "subfinder"
        binary.write_bytes(b"not-a-real-executable")  # no MZ/#! signature (Windows check)
        binary.chmod(0o644)  # and no +x (POSIX check) — write_bytes keeps the fixture's mode
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "blocked" in result.stdout

    def test_status_reports_missing_binary_as_not_installed(self, tmp_path: Path) -> None:
        (tmp_path / "tools_bin" / "subfinder").unlink()
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "not installed" in result.stdout


class TestRedirectedOutput:
    def test_status_survives_a_non_utf8_stdout(self, tmp_path: Path) -> None:
        """``cyberfw status > out.txt`` on Windows hands Python a cp125x stdout; the banner's
        block art (and init's tick marks) must not raise UnicodeEncodeError — init used to
        abort after installing the first tool."""
        import subprocess
        import sys

        repo_root = Path(__file__).resolve().parents[2]
        env = {
            **os.environ,
            "PYTHONIOENCODING": "cp1252",
            "PYTHONUTF8": "0",
            "PYTHONPATH": str(repo_root),
            "CYBERFW_LOG_TO_FILE": "false",
        }
        proc = subprocess.run(
            [sys.executable, "-m", "cyberfw.cli", "status"],
            cwd=tmp_path,
            capture_output=True,
            env=env,
            timeout=120,
            check=False,
        )

        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")[-600:]
        assert "▄▄▄▄" in proc.stdout.decode("utf-8")


class TestLauncherScalesWithRegistry:
    """The launcher must not hard-code eight tools: a ninth entry in registry.yaml used
    to collide with the pipeline shortcut (``9``) and the sidebar still said ``1-8``."""

    NINE = [f"tool{i}" for i in range(1, 10)]

    def test_ninth_tool_is_selectable_by_number(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyberfw.cli import _dispatch_choice

        ran: list[str] = []
        monkeypatch.setattr("cyberfw.cli._interactive_run", ran.append)
        monkeypatch.setattr("cyberfw.cli._interactive_pipeline", lambda: ran.append("<pipeline>"))

        assert _dispatch_choice("9", self.NINE) is True
        assert ran == ["tool9"]

    def test_pipeline_has_its_own_hotkey(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyberfw.cli import _dispatch_choice

        ran: list[str] = []
        monkeypatch.setattr("cyberfw.cli._interactive_run", ran.append)
        monkeypatch.setattr("cyberfw.cli._interactive_pipeline", lambda: ran.append("<pipeline>"))

        assert _dispatch_choice("r", self.NINE) is True
        assert ran == ["<pipeline>"]

    @pytest.mark.parametrize("key", ["0", "q"])
    def test_exit_keys(self, key: str) -> None:
        from cyberfw.cli import _dispatch_choice

        assert _dispatch_choice(key, self.NINE) is False

    def test_prompt_accepts_pipeline_hotkey(self, monkeypatch: pytest.MonkeyPatch) -> None:
        answers = iter(["r", "0"])
        monkeypatch.setattr("cyberfw.cli.Prompt.ask", lambda *_a, **_k: next(answers))

        assert _prompt_choice(["a", "b"]) == "r"

    def test_sidebar_counts_the_registered_tools(self, tmp_path: Path) -> None:
        from cyberfw.cli import _launcher_view
        from cyberfw.config import Settings
        from cyberfw.manager import ToolManager, load_registry

        registry_path = tmp_path / "nine.yaml"
        registry_path.write_text(
            "".join(f"{name}:\n  repo: org/{name}\n  asset_patterns: []\n  binary: {name}\n" for name in self.NINE),
            encoding="utf-8",
        )
        settings = Settings(root_dir=tmp_path)
        manager = ToolManager(settings, load_registry(registry_path))
        output = Console(theme=THEME, record=True, width=120)
        try:
            output.print(_launcher_view(manager, settings))
        finally:
            manager.close()
        rendered = output.export_text()

        assert "1-9  select tool" in rendered
        assert "r    run pipeline" in rendered


class TestLauncherPromptsComeFromTheAdapter:
    @staticmethod
    def _capture(monkeypatch: pytest.MonkeyPatch, answers: list[str]) -> tuple[list[str], list[tuple]]:
        prompts: list[str] = []
        calls: list[tuple] = []
        replies = iter(answers)

        def fake_ask(prompt: str, *_a, **_k) -> str:
            prompts.append(prompt)
            return next(replies)

        monkeypatch.setattr("cyberfw.cli.Prompt.ask", fake_ask)
        monkeypatch.setattr("cyberfw.cli.run_cmd", lambda tool, **kw: calls.append((tool, kw)))
        return prompts, calls

    def test_gitleaks_asks_for_a_repository_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyberfw.cli import _interactive_run

        prompts, calls = self._capture(monkeypatch, ["C:/repo"])
        _interactive_run("gitleaks")

        assert prompts == ["Local repository path"]
        assert calls == [("gitleaks", {"target": "C:/repo", "wordlist": None})]

    def test_ffuf_also_asks_for_its_wordlist(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyberfw.cli import _interactive_run

        prompts, calls = self._capture(monkeypatch, ["https://example.com", "words.txt"])
        _interactive_run("ffuf")

        assert prompts == ["Target (domain, URL or host)", "Wordlist path"]
        assert calls == [("ffuf", {"target": "https://example.com", "wordlist": "words.txt"})]

    def test_a_tool_without_extra_input_gets_one_question(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyberfw.cli import _interactive_run

        prompts, _calls = self._capture(monkeypatch, ["example.com"])
        _interactive_run("subfinder")

        assert prompts == ["Target (domain, URL or host)"]

    def test_a_new_adapter_brings_its_own_prompt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No per-tool branch in the CLI: registering an adapter is all a new tool needs."""
        from cyberfw.cli import _interactive_run
        from cyberfw.tools import ADAPTERS
        from cyberfw.tools.base import BaseTool

        class PlanetScan(BaseTool):
            target_prompt = "Which planet?"

            def build_cmd(self, ctx):  # pragma: no cover - never run here
                return [str(self.binary)]

        monkeypatch.setitem(ADAPTERS, "planetscan", PlanetScan)
        prompts, calls = self._capture(monkeypatch, ["mars"])
        _interactive_run("planetscan")

        assert prompts == ["Which planet?"]
        assert calls == [("planetscan", {"target": "mars", "wordlist": None})]


class TestYamlPipelines:
    """A pipeline defined in pipelines/<name>.yaml runs exactly like a built-in one."""

    @staticmethod
    def _write_pipeline(root: Path, name: str, text: str) -> None:
        (root / "pipelines").mkdir(exist_ok=True)
        (root / "pipelines" / f"{name}.yaml").write_text(text, encoding="utf-8")

    def test_yaml_pipeline_runs_end_to_end(self, tmp_path: Path) -> None:
        self._write_pipeline(
            tmp_path,
            "web-check",
            "description: probe then scan\n"
            "nodes:\n"
            "  - tool: subfinder\n    stage: subdomains\n"
            "  - tool: httpx\n    stage: live_http\n"
            "  - tool: nuclei\n    stage: vulns\n    input_from: live_http\n",
        )

        result = runner.invoke(app, ["pipeline", "web-check", "-t", "example.com"])

        assert result.exit_code == 0, result.stdout
        assert "report.json" in result.stdout
        report = next((tmp_path / "reports").rglob("report.json")).read_text(encoding="utf-8")
        assert '"stage": "vulns"' in report

    def test_yaml_pipeline_with_an_unregistered_tool_is_a_usage_error(self, tmp_path: Path) -> None:
        self._write_pipeline(tmp_path, "typo", "nodes:\n  - tool: httpxx\n    stage: live\n")

        result = runner.invoke(app, ["pipeline", "typo", "-t", "example.com"])

        assert result.exit_code == 2
        assert "httpxx" in result.stdout
        assert "Traceback" not in result.stdout

    def test_broken_yaml_pipeline_is_a_usage_error(self, tmp_path: Path) -> None:
        self._write_pipeline(tmp_path, "bad", "nodes:\n  - tool: httpx\n    stage: a\n    input_from: nope\n")

        result = runner.invoke(app, ["pipeline", "bad", "-t", "example.com"])

        assert result.exit_code == 2
        assert "input_from" in result.stdout

    def test_launcher_offers_yaml_pipelines(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyberfw.cli import _interactive_pipeline

        self._write_pipeline(tmp_path, "web-check", "nodes:\n  - tool: httpx\n    stage: live\n")
        seen: dict[str, object] = {}

        def fake_ask(prompt: str, *_a, **kw) -> str:
            if prompt == "Pipeline":
                seen["choices"] = kw.get("choices")
                return "web-check"
            return "example.com"

        monkeypatch.setattr("cyberfw.cli.Prompt.ask", fake_ask)
        monkeypatch.setattr("cyberfw.cli.Confirm.ask", lambda *_a, **_k: pytest.fail("no recon options for a YAML pipeline"))
        monkeypatch.setattr("cyberfw.cli.pipeline_cmd", lambda name, **kw: seen.update(name=name, **kw))
        _interactive_pipeline()

        assert seen["choices"] == ["recon-to-vuln", "web-check"]
        assert seen["name"] == "web-check"
        assert seen["target"] == "example.com"

    def test_registered_tool_without_an_adapter_is_a_usage_error(self, tmp_path: Path) -> None:
        with (tmp_path / "registry.yaml").open("a", encoding="utf-8") as handle:
            handle.write("weirdtool:\n  repo: org/weirdtool\n  asset_patterns: []\n  binary: weirdtool\n")
        self._write_pipeline(tmp_path, "weird", "nodes:\n  - tool: weirdtool\n    stage: w\n")

        result = runner.invoke(app, ["pipeline", "weird", "-t", "example.com"])

        assert result.exit_code == 2
        assert "no adapter registered" in result.stdout


class TestReportProvenance:
    def test_pipeline_report_names_pipeline_seed_session_and_tools(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "prov"])

        assert result.exit_code == 0, result.stdout
        run = json.loads((tmp_path / "reports" / "prov" / "report.json").read_text(encoding="utf-8"))["run"]
        assert run["pipeline"] == "recon-to-vuln"
        assert run["seed"] == "example.com"
        assert run["session_id"] == "prov"
        assert set(run["tool_versions"]) == {"subfinder", "httpx", "nuclei"}
        assert run["duration_s"] is not None and run["duration_s"] >= 0
        assert "/" in run["platform"]


class TestRegistryLookup:
    def test_candidates_prefer_cwd_then_checkout_root_then_packaged_copy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cyberfw.cli import _registry_candidates

        monkeypatch.setattr("cyberfw.cli.packaged_data", lambda *parts: tmp_path / "site" / "registry.yaml")
        candidates = _registry_candidates()

        assert candidates[0] == Path.cwd() / "registry.yaml"
        assert candidates[1] == Path(__file__).resolve().parents[2] / "registry.yaml"
        assert candidates[-1] == tmp_path / "site" / "registry.yaml"

    def test_first_existing_candidate_wins(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyberfw.cli import _registry_path

        packaged = tmp_path / "site" / "registry.yaml"
        packaged.parent.mkdir()
        packaged.write_text("{}\n", encoding="utf-8")
        monkeypatch.setattr("cyberfw.cli._registry_candidates", lambda: [tmp_path / "missing.yaml", packaged])

        assert _registry_path() == packaged

    def test_no_registry_anywhere_is_a_registry_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyberfw.cli import _registry_path
        from cyberfw.exceptions import RegistryError

        monkeypatch.setattr("cyberfw.cli._registry_candidates", lambda: [tmp_path / "missing.yaml"])

        with pytest.raises(RegistryError, match="registry.yaml"):
            _registry_path()


class TestLiveProgress:
    """The pipeline and single runs show a live stage table plus the latest findings."""

    def test_pipeline_shows_every_stage_with_its_outcome(self) -> None:
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report"])

        assert result.exit_code == 0, result.stdout
        for stage in ("subdomains", "live_http", "vulns"):
            assert stage in result.stdout
        assert "ok" in result.stdout
        assert "pending" not in result.stdout, "every stage has finished by the time the run returns"

    def test_pipeline_shows_the_findings_as_they_arrive(self) -> None:
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report"])

        assert "Latest findings" in result.stdout
        assert "sub.example.com" in result.stdout

    def test_pipeline_stage_table_is_not_printed_twice(self) -> None:
        """The live table IS the stage table; repeating it after the run is noise."""
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report"])

        assert result.stdout.count("subdomains") == 1

    def test_failed_stage_is_visible_in_the_live_table(self, tmp_path: Path) -> None:
        crash = tmp_path / "tools_bin" / "nuclei"
        crash.write_text("#!/usr/bin/env bash\nexit 7\n", encoding="utf-8")
        crash.chmod(crash.stat().st_mode | stat.S_IEXEC)

        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report"])

        assert result.exit_code == 1
        assert "failed" in result.stdout
        assert "code 7" in result.stdout

    def test_redirected_output_gets_one_frame_not_a_flipbook(self) -> None:
        """A pipe or a CI log is not a terminal: repainting there would dump the whole
        table once per update instead of updating it in place."""
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report"])

        assert result.stdout.count("Latest findings") == 1

    def test_run_shows_the_live_view_too(self) -> None:
        result = runner.invoke(app, ["run", "subfinder", "-t", "example.com"])

        assert result.exit_code == 0
        assert "Latest findings" in result.stdout
        assert "sub.example.com" in result.stdout

    def test_verbose_mode_keeps_the_raw_stream(self, tmp_path: Path) -> None:
        """--no-parse is for watching the tools themselves; a Live region would fight it."""
        result = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-parse", "--no-report"]
        )

        assert "Latest findings" not in result.stdout
        assert '{"host": "sub.example.com"' in result.stdout


class TestRunSummary:
    def test_summary_panel_reports_status_totals_and_reports(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "sumry"])

        assert result.exit_code == 0, result.stdout
        assert "success" in result.stdout
        assert "subfinder" in result.stdout and "httpx" in result.stdout
        assert "sumry" in result.stdout
        assert "report.html" in result.stdout and "report.json" in result.stdout

    def test_summary_marks_a_failed_run(self, tmp_path: Path) -> None:
        crash = tmp_path / "tools_bin" / "nuclei"
        crash.write_text("#!/usr/bin/env bash\nexit 7\n", encoding="utf-8")
        crash.chmod(crash.stat().st_mode | stat.S_IEXEC)

        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report"])

        assert "failed" in result.stdout
        assert "success" not in result.stdout

    def test_summary_names_the_stage_that_failed(self, tmp_path: Path) -> None:
        """"failed" alone makes the user scroll back through a long run to find out
        which stage it was; the panel is the last thing on screen, so it must say."""
        _break_tool(tmp_path, "httpx")

        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report"])

        assert "live_http" in result.stdout.split("failed")[-1], "the failed stage is named in the panel"

    def test_summary_separates_skipped_stages_from_failed_ones(self, tmp_path: Path) -> None:
        _break_tool(tmp_path, "httpx")

        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report"])

        tail = result.stdout[result.stdout.rindex("elapsed") :]
        assert "failed" in tail and "live_http" in tail
        assert "skipped" in tail and "vulns" in tail

    def test_a_clean_run_says_nothing_about_failures(self) -> None:
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report"])

        tail = result.stdout[result.stdout.rindex("elapsed") :]
        assert "failed" not in tail and "skipped" not in tail

    def test_duration_is_reported(self) -> None:
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report"])

        assert "elapsed" in result.stdout


class TestInventoryPresentation:
    """The launcher and `status` answer the same question — what is ready to run — so
    they show the same inventory: version, state, and a one-line readiness summary."""

    def _install_state(self, tmp_path: Path, tool: str, version: str) -> None:
        binary = (tmp_path / "tools_bin" / tool).resolve()
        (tmp_path / "tools_bin" / f".{tool}.install.json").write_text(
            json.dumps({"binary": str(binary), "version": version, "os": "linux", "arch": "amd64"}),
            encoding="utf-8",
        )

    def test_a_runnable_binary_without_an_install_record_is_ready_not_blocked(self, tmp_path: Path) -> None:
        """A checkout whose tools_bin was copied from elsewhere has binaries but no
        records; calling those "blocked" would send the user hunting an antivirus."""
        from cyberfw.cli import _tool_state
        from cyberfw.config import Settings
        from cyberfw.manager import ToolManager, load_registry

        settings = Settings(root_dir=tmp_path)
        manager = ToolManager(settings, load_registry(tmp_path / "registry.yaml"))
        try:
            assert manager.install_state("subfinder") is None
            assert _tool_state(manager, "subfinder", settings.tools_dir) == "ready"
        finally:
            manager.close()

    def test_launcher_lists_installed_versions(self, tmp_path: Path) -> None:
        from cyberfw.cli import _launcher_view
        from cyberfw.config import Settings
        from cyberfw.manager import ToolManager, load_registry
        from cyberfw.manager.platform_map import Mapping

        self._install_state(tmp_path, "subfinder", "2.6.6")
        settings = Settings(root_dir=tmp_path)
        manager = ToolManager(settings, load_registry(tmp_path / "registry.yaml"), Mapping("linux", "amd64"))
        output = Console(theme=THEME, record=True, width=120)
        try:
            output.print(_launcher_view(manager, settings))
        finally:
            manager.close()
        rendered = output.export_text()

        assert "2.6.6" in rendered
        assert "4/4 ready" in rendered

    def test_status_opens_with_the_readiness_summary(self) -> None:
        """All four workspace binaries are runnable, so all four are ready — an install
        record is bookkeeping for the version, not a precondition for running."""
        result = runner.invoke(app, ["status"])

        assert result.exit_code == 0
        assert "4/4 ready" in result.stdout

    def test_status_shows_the_recorded_version_per_tool(self, tmp_path: Path) -> None:
        from cyberfw.manager.platform_map import get_target

        mapping = get_target()
        for tool in ("subfinder", "httpx"):
            binary = (tmp_path / "tools_bin" / tool).resolve()
            (tmp_path / "tools_bin" / f".{tool}.install.json").write_text(
                json.dumps(
                    {"binary": str(binary), "version": "9.9.9", "os": mapping.os_name, "arch": mapping.arch}
                ),
                encoding="utf-8",
            )

        result = runner.invoke(app, ["status"])

        assert "9.9.9" in result.stdout
        assert "—" in result.stdout, "a tool with no install record shows no version"


class TestInitPresentation:
    def test_results_are_listed_as_a_table(self, fake_github: object) -> None:
        result = runner.invoke(app, ["init", "pinme"])

        assert result.exit_code == 0
        assert "version" in result.stdout and "state" in result.stdout
        assert "1.2.3" in result.stdout
        assert "installed" in result.stdout

    def test_up_to_date_and_failed_rows_are_distinguishable(self, fake_github: object) -> None:
        runner.invoke(app, ["init", "pinme"])
        result = runner.invoke(app, ["init", "pinme"])

        assert "up to date" in result.stdout

    def test_a_failure_is_shown_in_the_table_and_exits_1(self, tmp_path: Path) -> None:
        with (tmp_path / "registry.yaml").open("a", encoding="utf-8") as handle:
            handle.write("broken:\n  repo: org/broken\n  asset_patterns: []\n  binary: broken\n")

        result = runner.invoke(app, ["init", "broken"])

        assert result.exit_code == 1
        assert "failed" in result.stdout


class TestPipelinePreFlight:
    """Whether a pipeline can run at all is knowable before the first byte is scanned:
    a real ports-to-vuln run spent 4.5 minutes to report that naabu — blocked by
    Defender before the run even started — never ran."""

    def test_a_missing_tool_stops_the_run_before_it_starts(self, tmp_path: Path) -> None:
        (tmp_path / "tools_bin" / "nuclei").unlink()

        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com"])

        assert result.exit_code == 2
        assert "nuclei" in result.stdout
        assert "cyberfw init" in result.stdout, "the message says how to fix it"
        assert not list((tmp_path / "reports").rglob("report.json")), "nothing ran"

    def test_the_stage_is_named_alongside_the_tool(self, tmp_path: Path) -> None:
        (tmp_path / "tools_bin" / "httpx").unlink()

        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com"])

        assert "live_http" in result.stdout

    def test_force_start_runs_anyway(self, tmp_path: Path) -> None:
        """The check is a courtesy, not a gate: a user who knows better can proceed."""
        (tmp_path / "tools_bin" / "nuclei").unlink()

        result = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--force-start", "--no-report"]
        )

        assert result.exit_code == 1, "the nuclei stage still fails, but the run happened"
        assert "subdomains" in result.stdout and "sub.example.com" in result.stdout

    def test_a_ready_workspace_is_not_bothered(self) -> None:
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report"])

        assert result.exit_code == 0
        assert "cyberfw init" not in result.stdout

    def test_only_the_tools_this_pipeline_uses_are_required(self, tmp_path: Path) -> None:
        """recon-to-vuln without --ffuf does not need ffuf installed."""
        (tmp_path / "tools_bin" / "ffuf").unlink()

        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report"])

        assert result.exit_code == 0


class TestSavePrompt:
    """Saving is the user's call: after the results are on screen, the command asks.
    Explicit flags answer it in advance, and a non-interactive session never blocks.
    """

    @staticmethod
    def _answer(monkeypatch: pytest.MonkeyPatch, reply: bool) -> list[str]:
        """Make the session look interactive and answer the confirmation with ``reply``."""
        asked: list[str] = []

        def fake_confirm(prompt: str, *_a, **_k) -> bool:
            asked.append(prompt)
            return reply

        monkeypatch.setattr("cyberfw.cli._is_interactive", lambda: True)
        monkeypatch.setattr("cyberfw.cli.Confirm.ask", fake_confirm)
        return asked

    @staticmethod
    def _never_asks(monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("cyberfw.cli._is_interactive", lambda: True)
        monkeypatch.setattr(
            "cyberfw.cli.Confirm.ask", lambda *_a, **_k: pytest.fail("an explicit flag must not be re-asked")
        )

    # -- pipeline ------------------------------------------------------------
    def test_pipeline_asks_and_saves_on_yes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        asked = self._answer(monkeypatch, True)

        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "yes"])

        assert result.exit_code == 0, result.stdout
        assert asked, "the user was asked"
        assert (tmp_path / "reports" / "yes" / "report.json").is_file()
        assert (tmp_path / "reports" / "yes" / "report.html").is_file()

    def test_pipeline_leaves_nothing_behind_on_no(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Declining means declining: the per-stage JSONL the run wrote goes too."""
        self._answer(monkeypatch, False)

        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "no"])

        assert result.exit_code == 0, result.stdout
        assert not (tmp_path / "reports" / "no").exists()
        assert "not saved" in result.stdout

    def test_no_report_flag_answers_the_question(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._never_asks(monkeypatch)

        result = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "flag", "--no-report"]
        )

        assert result.exit_code == 0
        assert not (tmp_path / "reports" / "flag").exists()

    def test_report_flag_answers_it_too(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._never_asks(monkeypatch)

        result = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "flag", "--report"]
        )

        assert result.exit_code == 0
        assert (tmp_path / "reports" / "flag" / "report.json").is_file()

    def test_a_non_interactive_run_saves_without_asking(self, tmp_path: Path) -> None:
        """Scripts and CI cannot answer a prompt, and must keep getting their reports."""
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "ci"])

        assert result.exit_code == 0
        assert (tmp_path / "reports" / "ci" / "report.json").is_file()

    def test_a_session_directory_that_already_existed_is_never_removed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--session can point at an earlier run's folder; "no" must not delete its data."""
        earlier = tmp_path / "reports" / "reused"
        earlier.mkdir(parents=True)
        (earlier / "earlier.jsonl").write_text("kept\n", encoding="utf-8")
        self._answer(monkeypatch, False)

        runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "reused"])

        assert (earlier / "earlier.jsonl").read_text(encoding="utf-8") == "kept\n"

    # -- run -----------------------------------------------------------------
    def test_run_asks_and_writes_a_report_on_yes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        asked = self._answer(monkeypatch, True)

        result = runner.invoke(app, ["run", "subfinder", "-t", "example.com", "--session", "single"])

        assert result.exit_code == 0, result.stdout
        assert asked
        session = tmp_path / "reports" / "single"
        assert (session / "report.json").is_file()
        assert (session / "subfinder.jsonl").is_file(), "the records themselves are archived too"

    def test_run_writes_nothing_on_no(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._answer(monkeypatch, False)

        runner.invoke(app, ["run", "subfinder", "-t", "example.com", "--session", "single"])

        assert not (tmp_path / "reports" / "single").exists()

    def test_run_save_flag_still_skips_the_question(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._never_asks(monkeypatch)

        result = runner.invoke(app, ["run", "subfinder", "-t", "example.com", "--session", "s", "--save"])

        assert result.exit_code == 0
        assert (tmp_path / "reports" / "s" / "subfinder.jsonl").is_file()

    def test_a_non_interactive_run_of_a_tool_saves_nothing(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["run", "subfinder", "-t", "example.com"])

        assert result.exit_code == 0
        assert not list((tmp_path / "reports").glob("run-*"))

    def test_an_empty_result_is_not_worth_asking_about(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Nothing was found, so there is nothing to save — do not make the user answer."""
        _silence_tool(tmp_path, "subfinder")
        asked = self._answer(monkeypatch, True)

        result = runner.invoke(app, ["run", "subfinder", "-t", "example.com"])

        assert result.exit_code == 0
        assert asked == []


class TestPreFlightExternalDependencies:
    """tools_bin is not the whole story: gowitness needs a Chrome it cannot ship, and
    rustscan wants an Nmap it can do without."""

    @staticmethod
    def _add_tool(tmp_path: Path, name: str, payload: str = "{}") -> None:
        binary = tmp_path / "tools_bin" / name
        binary.write_text(f"#!/usr/bin/env bash\nprintf '%s' '{payload}'\n", encoding="utf-8")
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
        with (tmp_path / "registry.yaml").open("a", encoding="utf-8") as handle:
            handle.write(f"{name}:\n  repo: org/{name}\n  asset_patterns: []\n  binary: {name}\n")

    def _needs_nmap(self, tmp_path: Path) -> None:
        """A registered rustscan whose registry entry declares the optional nmap."""
        self._add_tool(tmp_path, "rustscan", payload="a.example.com -> [80,443]")
        with (tmp_path / "registry.yaml").open("a", encoding="utf-8") as handle:
            handle.write('  check_deps: ["nmap"]\n')

    @staticmethod
    def _pipeline_file(tmp_path: Path, name: str, body: str) -> None:
        (tmp_path / "pipelines").mkdir(exist_ok=True)
        (tmp_path / "pipelines" / f"{name}.yaml").write_text(body, encoding="utf-8")

    def test_a_missing_chrome_stops_a_gowitness_run_before_it_starts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._add_tool(tmp_path, "gowitness")
        monkeypatch.setattr("cyberfw.tools.gowitness._find_chrome", lambda: None)

        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--gowitness"])

        assert result.exit_code == 2
        assert "gowitness" in result.stdout and "Chrome" in result.stdout
        assert not list((tmp_path / "reports").rglob("report.json"))

    def test_force_start_runs_without_chrome(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._add_tool(tmp_path, "gowitness")
        monkeypatch.setattr("cyberfw.tools.gowitness._find_chrome", lambda: None)

        result = runner.invoke(
            app,
            ["pipeline", "recon-to-vuln", "-t", "example.com", "--gowitness", "--force-start", "--no-report"],
        )

        assert result.exit_code == 1, "the screenshots stage fails, the rest still runs"
        assert "sub.example.com" in result.stdout

    def test_chrome_present_is_not_mentioned(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._add_tool(tmp_path, "gowitness")
        monkeypatch.setattr("cyberfw.tools.gowitness._find_chrome", lambda: "/usr/bin/chromium")

        result = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--gowitness", "--no-report"]
        )

        assert "Chrome" not in result.stdout

    def test_a_missing_nmap_only_warns(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Graceful degradation: rustscan still finds open ports without Nmap."""
        self._add_tool(tmp_path, "rustscan", payload="a.example.com -> [80,443]")
        with (tmp_path / "registry.yaml").open("a", encoding="utf-8") as handle:
            handle.write("  check_deps: [\"nmap\"]\n")
        self._pipeline_file(tmp_path, "ports", "nodes:\n  - tool: rustscan\n    stage: scan\n")
        monkeypatch.setattr("cyberfw.cli.shutil.which", lambda _dep: None)

        result = runner.invoke(app, ["pipeline", "ports", "-t", "example.com", "--no-report"])

        assert result.exit_code == 0, result.stdout
        assert "nmap" in result.stdout
        assert "a.example.com" in result.stdout, "the scan ran anyway"

    def test_the_same_dependency_is_reported_once(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The pre-flight says it before the run; the engine must not say it again as the
        stage starts, where the live region would bury it anyway."""
        self._needs_nmap(tmp_path)
        self._pipeline_file(tmp_path, "ports", "nodes:\n  - tool: rustscan\n    stage: scan\n")
        monkeypatch.setattr("cyberfw.cli.shutil.which", lambda _dep: None)
        monkeypatch.setattr("cyberfw.pipeline.engine.shutil.which", lambda _dep: None)

        result = runner.invoke(app, ["pipeline", "ports", "-t", "example.com", "--no-report"])

        # The install hint itself names Nmap, so count the warning, not the word.
        assert result.stdout.count("works best with") == 1

    def test_a_single_run_still_hears_about_it(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """`run` has no pre-flight, so the engine's own warning is what tells the user."""
        self._needs_nmap(tmp_path)
        monkeypatch.setattr("cyberfw.pipeline.engine.shutil.which", lambda _dep: None)

        result = runner.invoke(app, ["run", "rustscan", "-t", "example.com", "--no-save"])

        assert "nmap" in result.stdout.lower()

    def test_a_present_nmap_says_nothing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._add_tool(tmp_path, "rustscan", payload="a.example.com -> [80,443]")
        with (tmp_path / "registry.yaml").open("a", encoding="utf-8") as handle:
            handle.write("  check_deps: [\"nmap\"]\n")
        self._pipeline_file(tmp_path, "ports", "nodes:\n  - tool: rustscan\n    stage: scan\n")
        monkeypatch.setattr("cyberfw.cli.shutil.which", lambda _dep: "/usr/bin/nmap")

        result = runner.invoke(app, ["pipeline", "ports", "-t", "example.com", "--no-report"])

        assert result.exit_code == 0
        assert "nmap" not in result.stdout
