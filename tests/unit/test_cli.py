"""Typer CLI unit tests — end-to-end commands through CliRunner.

Uses a temporary workspace with fake tool binaries and a local registry.yaml,
so the whole code path runs without network and without real precompiled tools.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import stat
import subprocess
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from rich.console import Console
from rich.text import Text
from typer.testing import CliRunner

from cyberfw import completion
from cyberfw.logging import THEME
from cyberfw.ui import TOOL_GUIDES, banner, tool_guide

from ._cli import cli, patch_cli

_prompt_choice, _resolve_vt_key, _tool_menu, app = cli._prompt_choice, cli._resolve_vt_key, cli._tool_menu, cli.app

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


def _slow_tool(root: Path, tool: str, seconds: float) -> None:
    """Make a workspace binary take ``seconds`` before printing its usual output."""
    binary = root / "tools_bin" / tool
    binary.write_text(
        f"#!/usr/bin/env bash\nsleep {seconds}\n" f'printf "%s" \'{_FAKE_OUTPUT[tool]}\'\n',
        encoding="utf-8",
    )
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
    import hashlib
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
            # https URLs and GitHub's digests, as the real API reports them, so
            # locking needs no download of its own.
            digest = hashlib.sha256(archive).hexdigest()
            names = (
                "pinme_1.2.3_windows_amd64.zip",
                "pinme_1.2.3_linux_amd64.zip",
                "pinme_1.2.3_darwin_amd64.zip",
                "pinme_1.2.3_darwin_arm64.zip",
                "pinme_1.2.3_linux_arm64.zip",
            )
            return GitHubRelease(
                tag="v1.2.3",
                assets=[ReleaseAsset(name, f"https://example.test/{name}", len(archive), digest) for name in names],
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
        handle.write("pinme:\n  repo: org/pinme\n  asset_patterns: ['pinme_*']\n  binary: pinme\n")
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

        patch_cli(monkeypatch, "interactive_menu", fake_menu)
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
            "nmap",
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
        _inventory_table = cli._inventory_table
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
        monkeypatch.setattr(cli.Prompt, "ask", lambda *_a, **_k: next(answers))

        result = _prompt_choice(["a", "b", "c"])

        assert result == "3"

    def test_valid_choice_returned_immediately(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli.Prompt, "ask", lambda *_a, **_k: "0")

        assert _prompt_choice(["a", "b"]) == "0"

    def test_settings_hotkeys_are_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key in ("p", "l", "f", "P", "L", "F"):
            monkeypatch.setattr(cli.Prompt, "ask", lambda *_a, _k=key, **_kw: _k)
            assert _prompt_choice(["a", "b"]) == key.lower()

    def test_help_key_is_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli.Prompt, "ask", lambda *_a, **_k: "?")

        assert _prompt_choice(["a", "b"]) == "?"

    @pytest.mark.parametrize(
        ("typed", "key"),
        [
            ("nuclei", "2"),
            ("SUBFINDER", "1"),
            ("pipeline", "r"),
            ("help", "?"),
            ("exit", "q"),
            ("parse", "p"),
            ("log-level", "l"),
            ("log-file", "f"),
            ("animations", "a"),
        ],
    )
    def test_names_answer_like_their_keys(self, monkeypatch: pytest.MonkeyPatch, typed: str, key: str) -> None:
        # What Tab completes is a name, and Enter sends it: the menu acts on it
        # exactly as on the key beside it. (A rejected name would be asked
        # again; the "0" behind it ends that loop.)
        answers = iter([typed, "0"])
        monkeypatch.setattr(cli.Prompt, "ask", lambda *_a, **_k: next(answers))

        assert _prompt_choice(["subfinder", "nuclei"]) == key

    def test_tab_lists_every_tool_then_the_actions(self, monkeypatch: pytest.MonkeyPatch) -> None:
        offered: list[completion.Option] = []

        def ask(*_a: object, **_k: object) -> str:
            offered.extend(completion.offered())
            return "0"

        monkeypatch.setattr(cli.Prompt, "ask", ask)
        _prompt_choice(["subfinder", "nuclei"])

        assert [option.name for option in offered] == [
            "subfinder", "nuclei", "pipeline", "help", "parse", "log-level", "log-file", "animations", "exit",
        ]
        # Beside each name: its key, so the list also teaches the hotkeys.
        assert offered[1].hint == "2 · Vulnerability scanning"


class TestSettingsToggle:
    """The p/l/f hotkeys flip settings by exporting CYBERFW_* env vars."""

    @pytest.fixture(autouse=True)
    def _isolate_env(self) -> Iterator[None]:
        keys = ("CYBERFW_PARSE", "CYBERFW_LOG_TO_FILE", "CYBERFW_LOG_LEVEL", "CYBERFW_ANIMATIONS")
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
        _toggle_setting = cli._toggle_setting

        monkeypatch.delenv("CYBERFW_PARSE", raising=False)
        _toggle_setting("p", self._settings(tmp_path, parse=True))
        assert os.environ["CYBERFW_PARSE"] == "false"

    def test_f_toggles_log_to_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _toggle_setting = cli._toggle_setting

        monkeypatch.delenv("CYBERFW_LOG_TO_FILE", raising=False)
        _toggle_setting("f", self._settings(tmp_path, log_to_file=True))
        assert os.environ["CYBERFW_LOG_TO_FILE"] == "false"

    def test_l_cycles_log_level(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _toggle_setting = cli._toggle_setting

        monkeypatch.delenv("CYBERFW_LOG_LEVEL", raising=False)
        _toggle_setting("l", self._settings(tmp_path, log_level="INFO"))
        assert os.environ["CYBERFW_LOG_LEVEL"] == "WARNING"

    def test_a_toggles_animations(self, tmp_path: Path) -> None:
        _toggle_setting = cli._toggle_setting

        _toggle_setting("a", self._settings(tmp_path, animations=True))
        assert os.environ["CYBERFW_ANIMATIONS"] == "false"
        _toggle_setting("a", self._settings(tmp_path, animations=False))
        assert os.environ["CYBERFW_ANIMATIONS"] == "true"


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

    def test_pipeline_ffuf_uses_the_bundled_wordlist_when_none_given(self, tmp_path: Path) -> None:
        """--ffuf with no --wordlist now falls back to the bundled list instead of skipping."""
        (tmp_path / "wordlists").mkdir()
        (tmp_path / "wordlists" / "common.txt").write_text("admin\nlogin\n", encoding="utf-8")

        result = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--ffuf", "--no-report"]
        )

        assert result.exit_code == 0, result.stdout
        assert "bundled" in result.stdout  # the info line naming the default list
        assert "Traceback" not in result.stdout

    def test_pipeline_ffuf_warns_only_when_no_wordlist_and_no_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        patch_cli(monkeypatch, "default_wordlist", lambda: None)

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

    @staticmethod
    def _register_gowitness_and_stub_install(monkeypatch: pytest.MonkeyPatch) -> None:
        """Add gowitness to the workspace registry and make ``install`` a no-op.

        Keeps the network out of it: only the chromium-provisioning wiring is
        under test, not the real GitHub download.
        """
        from cyberfw.manager import InstallResult, ToolManager

        with (Path.cwd() / "registry.yaml").open("a", encoding="utf-8") as handle:
            handle.write("gowitness:\n  repo: sensepost/gowitness\n  asset_patterns: ['g_*']\n  binary: gowitness\n")

        def fake_install(self, name: str, *, force: bool = False) -> InstallResult:  # type: ignore[no-untyped-def]
            return InstallResult(self.spec(name), Path("tools_bin") / name / name, "1.0.0")

        monkeypatch.setattr(ToolManager, "install", fake_install)

    def test_init_gowitness_provisions_chromium(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._register_gowitness_and_stub_install(monkeypatch)
        called: list[bool] = []

        def spy(manager, settings, table, *, force, spinner):  # type: ignore[no-untyped-def]
            called.append(force)
            return 0

        patch_cli(monkeypatch, "_provision_chromium", spy)
        runner.invoke(app, ["init", "gowitness"])
        assert called == [False]

    def test_no_chromium_flag_skips_provisioning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._register_gowitness_and_stub_install(monkeypatch)
        called: list[bool] = []
        patch_cli(monkeypatch, "_provision_chromium", lambda *a, **k: called.append(True) or 0,
        )
        runner.invoke(app, ["init", "gowitness", "--no-chromium"])
        assert called == []

    def test_init_without_gowitness_does_not_provision_chromium(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._register_gowitness_and_stub_install(monkeypatch)
        called: list[bool] = []
        patch_cli(monkeypatch, "_provision_chromium", lambda *a, **k: called.append(True) or 0,
        )
        runner.invoke(app, ["init", "subfinder"])
        assert called == []


class TestProvisionChromium:
    """The init helper that downloads a portable Chromium for gowitness."""

    def _table(self):  # type: ignore[no-untyped-def]
        from rich.table import Table

        table = Table()
        for col in ("tool", "version", "state", "detail"):
            table.add_column(col)
        return table

    def _manager(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):  # type: ignore[no-untyped-def]
        from cyberfw.config import Settings
        from cyberfw.manager import ToolManager, load_registry

        settings = Settings(root_dir=tmp_path, tools_dir=tmp_path / "tools_bin")
        (tmp_path / "registry.yaml").write_text("{}\n", encoding="utf-8")
        manager = ToolManager(settings, load_registry(tmp_path / "registry.yaml"))
        return manager, settings

    def test_present_chrome_skips_download(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _provision_chromium = cli._provision_chromium

        monkeypatch.setattr("cyberfw.tools.gowitness._find_chrome", lambda *_: "/usr/bin/chrome")
        manager, settings = self._manager(monkeypatch, tmp_path)
        called: list[bool] = []
        monkeypatch.setattr(manager, "install_chromium", lambda **k: called.append(True))
        table = self._table()
        rc = _provision_chromium(manager, settings, table, force=False, spinner=None)
        assert rc == 0
        assert called == []  # a present Chrome means no download

    def test_downloads_when_absent(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _provision_chromium = cli._provision_chromium
        from cyberfw.manager.chromium import ChromiumInstallResult

        monkeypatch.setattr("cyberfw.tools.gowitness._find_chrome", lambda *_: None)
        manager, settings = self._manager(monkeypatch, tmp_path)
        binary = settings.tools_dir / "chromium" / "chrome"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"MZ")
        monkeypatch.setattr(
            manager,
            "install_chromium",
            lambda **k: ChromiumInstallResult(binary, "131.0.0"),
        )
        table = self._table()
        rc = _provision_chromium(manager, settings, table, force=False, spinner=None)
        assert rc == 0

    def test_unsupported_platform_is_skipped_not_failed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _provision_chromium = cli._provision_chromium
        from cyberfw.exceptions import ChromiumUnsupportedError

        monkeypatch.setattr("cyberfw.tools.gowitness._find_chrome", lambda *_: None)
        manager, settings = self._manager(monkeypatch, tmp_path)

        def boom(**k):  # type: ignore[no-untyped-def]
            raise ChromiumUnsupportedError("no build for linux/arm64")

        monkeypatch.setattr(manager, "install_chromium", boom)
        table = self._table()
        rc = _provision_chromium(manager, settings, table, force=False, spinner=None)
        assert rc == 0  # skipped, not a failure

    def test_download_failure_counts_as_failure(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _provision_chromium = cli._provision_chromium
        from cyberfw.exceptions import DownloadError

        monkeypatch.setattr("cyberfw.tools.gowitness._find_chrome", lambda *_: None)
        manager, settings = self._manager(monkeypatch, tmp_path)

        def boom(**k):  # type: ignore[no-untyped-def]
            raise DownloadError("network down")

        monkeypatch.setattr(manager, "install_chromium", boom)
        table = self._table()
        rc = _provision_chromium(manager, settings, table, force=False, spinner=None)
        assert rc == 1


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
        assert "animations" in result.stdout

    def test_doctor_is_an_alias_for_status(self) -> None:
        assert runner.invoke(app, ["doctor"]).exit_code == 0

    def test_verbose_flag_raises_log_level_to_debug(self) -> None:
        import logging

        runner.invoke(app, ["status"])
        assert logging.getLogger("cyberfw").level == logging.INFO
        runner.invoke(app, ["status", "--verbose"])
        assert logging.getLogger("cyberfw").level == logging.DEBUG

    def test_verbose_short_flag_is_accepted(self) -> None:
        import logging

        result = runner.invoke(app, ["status", "-v"])
        assert result.exit_code == 0
        assert logging.getLogger("cyberfw").level == logging.DEBUG

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
        _dispatch_choice = cli._dispatch_choice

        ran: list[str] = []
        patch_cli(monkeypatch, "_interactive_run", ran.append)
        patch_cli(monkeypatch, "_interactive_pipeline", lambda: ran.append("<pipeline>"))

        assert _dispatch_choice("9", self.NINE) is True
        assert ran == ["tool9"]

    def test_pipeline_has_its_own_hotkey(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _dispatch_choice = cli._dispatch_choice

        ran: list[str] = []
        patch_cli(monkeypatch, "_interactive_run", ran.append)
        patch_cli(monkeypatch, "_interactive_pipeline", lambda: ran.append("<pipeline>"))

        assert _dispatch_choice("r", self.NINE) is True
        assert ran == ["<pipeline>"]

    @pytest.mark.parametrize("key", ["0", "q"])
    def test_exit_keys(self, key: str) -> None:
        _dispatch_choice = cli._dispatch_choice

        assert _dispatch_choice(key, self.NINE) is False

    def test_prompt_accepts_pipeline_hotkey(self, monkeypatch: pytest.MonkeyPatch) -> None:
        answers = iter(["r", "0"])
        monkeypatch.setattr(cli.Prompt, "ask", lambda *_a, **_k: next(answers))

        assert _prompt_choice(["a", "b"]) == "r"

    def test_sidebar_counts_the_registered_tools(self, tmp_path: Path) -> None:
        _launcher_view = cli._launcher_view
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

        monkeypatch.setattr(cli.Prompt, "ask", fake_ask)
        patch_cli(monkeypatch, "run_cmd", lambda tool, **kw: calls.append((tool, kw)))
        return prompts, calls

    def test_gitleaks_asks_for_a_repository_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _interactive_run = cli._interactive_run

        prompts, calls = self._capture(monkeypatch, ["C:/repo"])
        _interactive_run("gitleaks")

        assert prompts == ["Local repository path"]
        assert calls == [("gitleaks", {"target": "C:/repo", "wordlist": None})]

    def test_ffuf_also_asks_for_its_wordlist(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _interactive_run = cli._interactive_run

        prompts, calls = self._capture(monkeypatch, ["https://example.com", "words.txt"])
        _interactive_run("ffuf")

        assert prompts == ["Target (domain, URL or host)", "Wordlist path"]
        assert calls == [("ffuf", {"target": "https://example.com", "wordlist": "words.txt"})]

    def test_a_tool_without_extra_input_gets_one_question(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _interactive_run = cli._interactive_run

        prompts, _calls = self._capture(monkeypatch, ["example.com"])
        _interactive_run("subfinder")

        assert prompts == ["Target (domain, URL or host)"]

    def test_a_new_adapter_brings_its_own_prompt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No per-tool branch in the CLI: registering an adapter is all a new tool needs."""
        _interactive_run = cli._interactive_run
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
        _interactive_pipeline = cli._interactive_pipeline

        self._write_pipeline(tmp_path, "web-check", "nodes:\n  - tool: httpx\n    stage: live\n")
        seen: dict[str, object] = {}

        def fake_ask(prompt: str, *_a, **kw) -> str:
            if prompt == "Pipeline":
                seen["choices"] = kw.get("choices")
                return "web-check"
            return "example.com"

        monkeypatch.setattr(cli.Prompt, "ask", fake_ask)
        monkeypatch.setattr(cli.Confirm, "ask", lambda *_a, **_k: pytest.fail("no recon options for a YAML pipeline"))
        patch_cli(monkeypatch, "pipeline_cmd", lambda name, **kw: seen.update(name=name, **kw))
        _interactive_pipeline()

        assert seen["choices"] == ["recon-to-vuln", "web-check"]
        assert seen["name"] == "web-check"
        assert seen["target"] == "example.com"

    @staticmethod
    def _offered_pipelines(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
        """Run the launcher's pipeline questions; return what Tab offered at "Pipeline"."""
        _interactive_pipeline = cli._interactive_pipeline

        offered: list[tuple[str, str]] = []

        def fake_ask(prompt: str, *_a: object, **_k: object) -> str:
            if prompt == "Pipeline":
                offered.extend((option.name, option.hint) for option in completion.offered())
                return "recon-to-vuln"
            return "example.com"

        monkeypatch.setattr(cli.Prompt, "ask", fake_ask)
        monkeypatch.setattr(cli.Confirm, "ask", lambda *_a, **_k: False)
        patch_cli(monkeypatch, "pipeline_cmd", lambda *_a, **_k: None)
        _interactive_pipeline()
        return offered

    def test_tab_lists_each_pipeline_with_its_stages(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._write_pipeline(
            tmp_path, "web-check", "nodes:\n  - tool: httpx\n    stage: live\n  - tool: nuclei\n    stage: vulns\n"
        )

        assert self._offered_pipelines(monkeypatch) == [
            ("recon-to-vuln", "subfinder → httpx → nuclei"),
            ("web-check", "httpx → nuclei"),
        ]

    def test_a_broken_pipeline_file_does_not_break_the_list(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Its error is reported when it is picked (as before); listing it must not
        # crash the launcher first.
        self._write_pipeline(tmp_path, "broken", "nodes: [")

        assert dict(self._offered_pipelines(monkeypatch))["broken"] == "invalid pipeline file"

    def test_registered_tool_without_an_adapter_is_a_usage_error(self, tmp_path: Path) -> None:
        with (tmp_path / "registry.yaml").open("a", encoding="utf-8") as handle:
            handle.write("weirdtool:\n  repo: org/weirdtool\n  asset_patterns: []\n  binary: weirdtool\n")
        self._write_pipeline(tmp_path, "weird", "nodes:\n  - tool: weirdtool\n    stage: w\n")

        result = runner.invoke(app, ["pipeline", "weird", "-t", "example.com"])

        assert result.exit_code == 2
        assert "no adapter registered" in result.stdout


class TestTabCompletion:
    """At a terminal the launcher's list questions read their answer with Tab completion."""

    def test_tab_picks_another_pipeline_without_typing_its_name(
        self, keyboard: Callable[..., object], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _interactive_pipeline = cli._interactive_pipeline

        # Two pipelines; the default is the first, ports-to-vuln.
        TestYamlPipelines._write_pipeline(tmp_path, "ports-to-vuln", "nodes:\n  - tool: httpx\n    stage: live\n")
        monkeypatch.setattr("cyberfw.completion.available", lambda _console: True)
        # The questions without a list keep plain input: target, Include Ffuf?, Include Gowitness?
        plain = iter(["example.com", "n", "n"])
        monkeypatch.setattr("builtins.input", lambda *_a: next(plain))
        seen: dict[str, object] = {}
        patch_cli(monkeypatch, "pipeline_cmd", lambda name, **kw: seen.update(name=name, **kw))

        keyboard(_interactive_pipeline, "r", "\t", "\r")

        assert seen["name"] == "recon-to-vuln"
        assert seen["target"] == "example.com"

    def test_without_a_terminal_the_answer_is_read_as_before(
        self, keyboard: Callable[..., object], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A pipe, CI or a test: plain input, whatever the keyboard pipe holds.
        monkeypatch.setattr("builtins.input", lambda *_a: "2")

        assert keyboard(lambda: _prompt_choice(["subfinder", "nuclei"]), "subfinder\r") == "2"


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
        _registry_candidates = cli.registry_candidates

        patch_cli(monkeypatch, "packaged_data", lambda *parts: tmp_path / "site" / "registry.yaml")
        candidates = _registry_candidates()

        assert candidates[0] == Path.cwd() / "registry.yaml"
        assert candidates[1] == Path(__file__).resolve().parents[2] / "registry.yaml"
        assert candidates[-1] == tmp_path / "site" / "registry.yaml"

    def test_first_existing_candidate_wins(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _registry_path = cli.registry_path

        packaged = tmp_path / "site" / "registry.yaml"
        packaged.parent.mkdir()
        packaged.write_text("{}\n", encoding="utf-8")
        patch_cli(monkeypatch, "registry_candidates", lambda: [tmp_path / "missing.yaml", packaged])

        assert _registry_path() == packaged

    def test_no_registry_anywhere_is_a_registry_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _registry_path = cli.registry_path
        from cyberfw.exceptions import RegistryError

        patch_cli(monkeypatch, "registry_candidates", lambda: [tmp_path / "missing.yaml"])

        with pytest.raises(RegistryError, match="registry.yaml"):
            _registry_path()


class TestLiveProgress:
    """The pipeline and single runs show a live stage table plus the latest findings."""

    def test_pipeline_shows_every_stage_with_its_outcome(self) -> None:
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-topology", "--no-report"])

        assert result.exit_code == 0, result.stdout
        for stage in ("subdomains", "live_http", "vulns"):
            assert stage in result.stdout
        assert "ok" in result.stdout
        assert "pending" not in result.stdout, "every stage has finished by the time the run returns"

    def test_pipeline_shows_the_findings_as_they_arrive(self) -> None:
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-topology", "--no-report"])

        assert "Latest findings" in result.stdout
        assert "sub.example.com" in result.stdout

    def test_pipeline_stage_table_is_not_printed_twice(self) -> None:
        """The live table IS the stage table; repeating it after the run is noise."""
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-topology", "--no-report"])

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
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-topology", "--no-report"])

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

    def test_topology_shows_a_map_instead_of_the_stage_table(self) -> None:
        result = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--topology", "--no-report"]
        )

        assert result.exit_code == 0, result.stdout
        # The map, not the stage table: seed root, the discovered host, its finding.
        assert "hosts" in result.stdout  # the map header counts line
        assert "example.com" in result.stdout and "sub.example.com" in result.stdout
        assert "medium" in result.stdout  # the fake nuclei finding's severity
        assert "Latest findings" not in result.stdout

    def test_map_is_an_alias_for_topology(self) -> None:
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--map", "--no-report"])

        assert result.exit_code == 0, result.stdout
        assert "sub.example.com" in result.stdout

    def test_topology_is_the_default_view(self) -> None:
        """With the shipped `view=topology`, a plain run shows the map, not the stage table."""
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report"])

        assert result.exit_code == 0, result.stdout
        assert "hosts" in result.stdout and "sub.example.com" in result.stdout
        assert "Latest findings" not in result.stdout

    def test_view_setting_can_restore_the_table_as_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CYBERFW_VIEW", "table")
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report"])

        assert result.exit_code == 0, result.stdout
        assert "Latest findings" in result.stdout and "subdomains" in result.stdout

    def test_flag_overrides_the_view_setting(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """--topology wins even when the setting says table."""
        monkeypatch.setenv("CYBERFW_VIEW", "table")
        result = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--topology", "--no-report"]
        )

        assert result.exit_code == 0, result.stdout
        assert "hosts" in result.stdout and "Latest findings" not in result.stdout

    def test_topology_is_ignored_in_verbose_mode_with_a_warning(self) -> None:
        result = runner.invoke(
            app,
            ["pipeline", "recon-to-vuln", "-t", "example.com", "--topology", "--no-parse", "--no-report"],
        )

        assert result.exit_code == 0, result.stdout
        assert "topology needs the parsed view" in result.stdout
        assert '{"host": "sub.example.com"' in result.stdout  # fell back to the raw stream


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


class TestHelpCard:
    """`?` at the launcher shows a cheatsheet: the menu keys, what each setting does,
    and the command-line calls the menu never shows."""

    @staticmethod
    def _card(names: list[str] | None = None) -> str:
        _help_card = cli._help_card

        output = Console(theme=THEME, record=True, width=100)
        output.print(_help_card(names or ["subfinder", "nuclei"]))
        return output.export_text()

    def test_names_the_menu_keys(self) -> None:
        card = self._card()
        assert "1-2" in card and "select" in card  # the tool-number range for two tools
        for word in ("pipeline", "Tab", "exit"):
            assert word in card, word
        assert "?" in card and "cheatsheet" in card  # the help key, and what it is

    def test_says_what_each_setting_does(self) -> None:
        card = self._card()
        for setting in ("parse", "log level", "log file", "animations"):
            assert setting in card, setting
        # not just the name: what it does, so the card is worth reading
        assert "DEBUG" in card  # the log-level cycle
        assert "logs/cyberfw.log" in card  # where the log file goes

    def test_shows_the_command_line_cheatsheet(self) -> None:
        card = self._card()
        for call in (
            "cstool status",
            "cstool run",
            "cstool pipeline recon-to-vuln",
            "cstool diff",
            "cstool vt",
            "cstool mute",
        ):
            assert call in card, call


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
        _tool_state = cli.tool_state
        from cyberfw.config import Settings
        from cyberfw.manager import ToolManager, load_registry

        settings = Settings(root_dir=tmp_path)
        manager = ToolManager(settings, load_registry(tmp_path / "registry.yaml"))
        try:
            assert manager.install_state("subfinder") is None
            assert _tool_state(manager, "subfinder", settings.tools_dir) == "ready"
        finally:
            manager.close()

    def test_an_unreadable_tools_dir_does_not_crash_the_state_check(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_binary_on_disk walks tools_bin with rglob/is_file; a directory that lists
        but cannot be entered raises PermissionError there on Python 3.10-3.13, which
        _tool_state caught only as CyberfwError. It must read as not installed."""
        _tool_state = cli.tool_state
        from cyberfw.config import Settings
        from cyberfw.manager import ToolManager, load_registry

        (tmp_path / "tools_bin" / "subfinder").unlink()  # so binary_path fails first
        settings = Settings(root_dir=tmp_path)
        manager = ToolManager(settings, load_registry(tmp_path / "registry.yaml"))

        real_is_file = Path.is_file

        def denying_is_file(self: Path) -> bool:
            if self.name == "subfinder":
                raise PermissionError(13, "Permission denied")
            return real_is_file(self)

        monkeypatch.setattr(Path, "is_file", denying_is_file)
        try:
            assert _tool_state(manager, "subfinder", settings.tools_dir) == "not installed"
        finally:
            manager.close()

    def test_launcher_lists_installed_versions(self, tmp_path: Path) -> None:
        _launcher_view = cli._launcher_view
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
        # The count lives in the banner above; a second copy here could disagree
        # with it as soon as a tool changed state during the session.
        assert "STATUS" not in rendered
        assert "4/4 ready" not in rendered

    def test_startup_resolves_each_tool_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The banner and the first launcher frame share one inventory pass."""

        calls: list[str] = []
        real_state = cli.tool_state

        def counting_state(manager, name, tools_dir):  # type: ignore[no-untyped-def]
            calls.append(name)
            return real_state(manager, name, tools_dir)

        patch_cli(monkeypatch, "tool_state", counting_state)
        patch_cli(monkeypatch, "_ensure_tools", lambda: None)
        patch_cli(monkeypatch, "_prompt_choice", lambda names: "0")
        cli.interactive_menu()

        assert sorted(calls) == sorted(_FAKE_OUTPUT), "one lookup per tool, not two"

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
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--force-start", "--no-topology", "--no-report"]
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


class TestSessionName:
    """--session names a directory under reports/; it must not reach anywhere else."""

    @pytest.mark.parametrize("session", ["../escape", "..\\escape", "..", "nested/dir", "C:escape"])
    @pytest.mark.parametrize(
        "command",
        [["run", "subfinder", "-t", "example.com", "--save"], ["pipeline", "recon-to-vuln", "-t", "example.com"]],
        ids=["run", "pipeline"],
    )
    def test_a_path_is_a_usage_error(self, tmp_path: Path, command: list[str], session: str) -> None:
        result = runner.invoke(app, [*command, "--session", session])

        assert result.exit_code == 2, result.stdout
        assert "--session" in result.stdout
        assert not (tmp_path / "escape").exists()
        assert not (tmp_path / "reports" / "nested").exists()

    def test_a_plain_name_is_accepted(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "scan-01.b_2"])

        assert result.exit_code == 0, result.stdout
        assert (tmp_path / "reports" / "scan-01.b_2" / "report.json").is_file()


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

        patch_cli(monkeypatch, "_is_interactive", lambda: True)
        monkeypatch.setattr(cli.Confirm, "ask", fake_confirm)
        return asked

    @staticmethod
    def _never_asks(monkeypatch: pytest.MonkeyPatch) -> None:
        patch_cli(monkeypatch, "_is_interactive", lambda: True)
        monkeypatch.setattr(cli.Confirm, "ask", lambda *_a, **_k: pytest.fail("an explicit flag must not be re-asked")
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

    def test_run_save_flag_writes_both_reports(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """--save used to keep only the JSONL; the README promises report.json and report.html too."""
        self._never_asks(monkeypatch)

        result = runner.invoke(app, ["run", "subfinder", "-t", "example.com", "--session", "flagged", "--save"])

        assert result.exit_code == 0, result.stdout
        session = tmp_path / "reports" / "flagged"
        assert (session / "report.json").is_file()
        assert (session / "report.html").is_file()
        lines = (session / "subfinder.jsonl").read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1, "records streamed during the run are not written a second time"

    @pytest.mark.parametrize("flags", [["--save"], []], ids=["save-flag", "answered-yes"])
    def test_run_report_times_the_tool_not_the_save(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flags: list[str]
    ) -> None:
        """The run's duration covers the process; it used to be stamped at save time (~0 s)."""
        _slow_tool(tmp_path, "subfinder", seconds=0.5)
        self._answer(monkeypatch, True)

        result = runner.invoke(app, ["run", "subfinder", "-t", "example.com", "--session", "slow", *flags])

        assert result.exit_code == 0, result.stdout
        run = json.loads((tmp_path / "reports" / "slow" / "report.json").read_text(encoding="utf-8"))["run"]
        assert run["duration_s"] >= 0.5

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
        monkeypatch.setattr("cyberfw.tools.gowitness._find_chrome", lambda *_: None)

        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--gowitness"])

        assert result.exit_code == 2
        assert "gowitness" in result.stdout and "Chrome" in result.stdout
        assert not list((tmp_path / "reports").rglob("report.json"))

    def test_force_start_runs_without_chrome(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._add_tool(tmp_path, "gowitness")
        monkeypatch.setattr("cyberfw.tools.gowitness._find_chrome", lambda *_: None)

        result = runner.invoke(
            app,
            ["pipeline", "recon-to-vuln", "-t", "example.com", "--gowitness", "--force-start", "--no-report"],
        )

        assert result.exit_code == 1, "the screenshots stage fails, the rest still runs"
        assert "sub.example.com" in result.stdout

    def test_chrome_present_is_not_mentioned(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._add_tool(tmp_path, "gowitness")
        monkeypatch.setattr("cyberfw.tools.gowitness._find_chrome", lambda *_: "/usr/bin/chromium")

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
        monkeypatch.setattr(cli.shutil, "which", lambda _dep: None)

        result = runner.invoke(app, ["pipeline", "ports", "-t", "example.com", "--no-report"])

        assert result.exit_code == 0, result.stdout
        assert "nmap" in result.stdout
        assert "a.example.com" in result.stdout, "the scan ran anyway"

    def test_the_same_dependency_is_reported_once(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The pre-flight says it before the run; the engine must not say it again as the
        stage starts, where the live region would bury it anyway."""
        self._needs_nmap(tmp_path)
        self._pipeline_file(tmp_path, "ports", "nodes:\n  - tool: rustscan\n    stage: scan\n")
        monkeypatch.setattr(cli.shutil, "which", lambda _dep: None)
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
        monkeypatch.setattr(cli.shutil, "which", lambda _dep: "/usr/bin/nmap")

        result = runner.invoke(app, ["pipeline", "ports", "-t", "example.com", "--no-report"])

        assert result.exit_code == 0
        assert "nmap" not in result.stdout


class TestResolveVtKey:
    """VT enrichment is default-on, asked for once, and --no-vt opts out."""

    @staticmethod
    def _settings(tmp_path: Path, *, key: str | None = None, prompted: bool = False) -> object:
        from types import SimpleNamespace

        return SimpleNamespace(vt_api_key=key, vt_prompted=prompted, root_dir=tmp_path)

    def test_no_vt_returns_none_without_asking(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli.vt, "resolve_or_prompt", lambda *a, **k: pytest.fail("prompted under --no-vt"))
        assert _resolve_vt_key(self._settings(tmp_path), False) is None

    def test_configured_key_is_used_silently(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli.vt, "resolve_api_key", lambda _explicit: "configured")
        monkeypatch.setattr(cli.vt, "resolve_or_prompt", lambda *a, **k: pytest.fail("should not prompt"))
        assert _resolve_vt_key(self._settings(tmp_path), None) == "configured"

    def test_default_run_asks_once_then_remembers(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        remembered: list[Path] = []
        monkeypatch.setattr(cli.vt, "resolve_api_key", lambda _explicit: None)
        patch_cli(monkeypatch, "_is_interactive", lambda: True)
        monkeypatch.setattr(cli.vt, "resolve_or_prompt", lambda *a, **k: "entered-key")
        monkeypatch.setattr(cli.vt, "remember_prompt", lambda p: remembered.append(p))
        assert _resolve_vt_key(self._settings(tmp_path), None) == "entered-key"
        assert remembered == [tmp_path / ".env"]

    def test_default_run_does_not_ask_again_after_prompted(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli.vt, "resolve_api_key", lambda _explicit: None)
        patch_cli(monkeypatch, "_is_interactive", lambda: True)
        monkeypatch.setattr(cli.vt, "resolve_or_prompt", lambda *a, **k: pytest.fail("asked twice"))
        assert _resolve_vt_key(self._settings(tmp_path, prompted=True), None) is None

    def test_non_interactive_never_prompts(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli.vt, "resolve_api_key", lambda _explicit: None)
        patch_cli(monkeypatch, "_is_interactive", lambda: False)
        monkeypatch.setattr(cli.vt, "resolve_or_prompt", lambda *a, **k: pytest.fail("prompted on a pipe"))
        assert _resolve_vt_key(self._settings(tmp_path), None) is None

    def test_explicit_vt_forces_the_prompt_even_after_skipping(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli.vt, "resolve_api_key", lambda _explicit: None)
        patch_cli(monkeypatch, "_is_interactive", lambda: True)
        monkeypatch.setattr(cli.vt, "resolve_or_prompt", lambda *a, **k: "late-key")
        monkeypatch.setattr(cli.vt, "remember_prompt", lambda p: None)
        assert _resolve_vt_key(self._settings(tmp_path, prompted=True), True) == "late-key"


class TestPostureChecks:
    """`pipeline` checks TLS certificates and the seed domain's email spoofing after the scan."""

    @staticmethod
    def _httpx_prints(root: Path, payload: dict[str, object]) -> None:
        binary = root / "tools_bin" / "httpx"
        binary.write_text("#!/usr/bin/env bash\n" f"printf '%s\\n' '{json.dumps(payload)}'\n", encoding="utf-8")
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)

    @staticmethod
    def _records(root: Path, session: str) -> list[dict[str, object]]:
        report = json.loads((root / "reports" / session / "report.json").read_text(encoding="utf-8"))
        return list(report["records"])

    def test_an_expiring_untrusted_certificate_is_reported(self, tmp_path: Path) -> None:
        soon = (datetime.now(timezone.utc) + timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._httpx_prints(tmp_path, {
            "url": "https://sub.example.com/", "status_code": 200, "title": "Home",
            "tls": {"host": "sub.example.com", "port": "443", "probe_status": True, "tls_version": "tls13",
                    "issuer_cn": "R11", "not_after": soon, "self_signed": True},
        })

        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "tls", "--no-mail"])

        assert result.exit_code == 0, result.stdout
        assert "TLS: 1 certificate(s)" in result.stdout
        checks = {r["template_id"] for r in self._records(tmp_path, "tls") if r["tool"] == "tlscheck"}
        assert checks == {"tls-cert-expiring", "tls-cert-self-signed"}

    def test_the_email_verdict_reaches_the_console_and_the_report(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cyberfw.pipeline.schemas import MailSecurity, PostureFinding
        from cyberfw.posture import mail

        seen: list[str] = []

        async def fake_check(domain: str) -> tuple[MailSecurity, list[PostureFinding]]:
            seen.append(domain)
            return mail.assess(domain, mx=[], null_mx=False, spf=[], spf_policy="", dmarc=[], dmarc_domain="")

        monkeypatch.setattr(cli.mailcheck, "check", fake_check)
        result = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "https://www.example.com/", "--session", "mail"]
        )

        assert result.exit_code == 0, result.stdout
        assert seen == ["example.com"]  # the seed URL reduced to its mail domain
        assert "Email (example.com): spoofable" in result.stdout
        records = self._records(tmp_path, "mail")
        assert [r["verdict"] for r in records if r["kind"] == "mail"] == ["spoofable"]
        assert {r["template_id"] for r in records if r["tool"] == "mailcheck" and r["kind"] == "vuln"} == {
            "mail-spf-missing", "mail-dmarc-missing",
        }

    def test_no_mail_skips_the_lookup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def must_not_run(domain: str) -> object:
            raise AssertionError("--no-mail must not look anything up")

        monkeypatch.setattr(cli.mailcheck, "check", must_not_run)
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report", "--no-mail"])

        assert result.exit_code == 0, result.stdout
        assert "Email" not in result.stdout

    def test_a_dns_outage_never_fails_the_scan(self) -> None:
        # tests/conftest.py keeps live DNS down for every test.
        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report"])

        assert result.exit_code == 0, result.stdout
        assert "Email check skipped" in result.stdout
        assert "DNS-over-HTTPS unreachable" in result.stdout  # the takeover check, also offline

    def test_a_subdomain_takeover_reaches_the_console_and_the_report(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cyberfw.pipeline.schemas import PostureFinding
        from cyberfw.posture import takeover

        seen: list[list[str]] = []

        async def fake_scan(hosts: list[str], **_kw: object) -> tuple[list[PostureFinding], list[str]]:
            seen.append(hosts)
            finding = PostureFinding.make(
                takeover.TOOL, "subdomain-takeover", "https://blog.example.com",
                name="Subdomain takeover possible — GitHub Pages", severity="high",
                description="blog.example.com → user.github.io, unclaimed", remediation="remove the record",
            )
            return [finding], []

        monkeypatch.setattr(cli.takeovercheck, "scan", fake_scan)
        result = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "to", "--no-mail"]
        )

        assert result.exit_code == 0, result.stdout
        assert "Subdomain takeover: 1 possible" in result.stdout and "blog.example.com" in result.stdout
        assert seen and "sub.example.com" in seen[0]  # the discovered subdomain was checked
        records = self._records(tmp_path, "to")
        takeovers = [r for r in records if r["tool"] == "takeover"]
        assert len(takeovers) == 1 and takeovers[0]["info"]["severity"] == "high"

    def test_no_takeover_skips_the_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def must_not_run(*_a: object, **_k: object) -> object:
            raise AssertionError("--no-takeover must not scan")

        monkeypatch.setattr(cli.takeovercheck, "scan", must_not_run)
        result = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report", "--no-mail", "--no-takeover"]
        )
        assert result.exit_code == 0, result.stdout
        assert "Subdomain takeover" not in result.stdout


class TestBaselineComparison:
    """A repeat scan says what changed since the previous one; `cyberfw diff` compares any two."""

    @staticmethod
    def _tool_prints(root: Path, tool: str, *lines: dict[str, object]) -> None:
        payload = "\n".join(json.dumps(line) for line in lines)
        binary = root / "tools_bin" / tool
        binary.write_text("#!/usr/bin/env bash\n" f"printf '%s\\n' '{payload}'\n", encoding="utf-8")
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)

    def _scan(self, session: str, *extra: str) -> object:
        result = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", session, "--no-mail", *extra]
        )
        assert result.exit_code == 0, result.stdout
        return result

    def _scan_twice(self, tmp_path: Path) -> object:
        first = self._scan("first")
        assert "Since" not in first.stdout  # nothing earlier to compare with
        self._tool_prints(tmp_path, "subfinder", {"host": "sub.example.com"}, {"host": "dev.example.com"})
        self._tool_prints(
            tmp_path, "nuclei",
            {"template-id": "xss", "matched-at": "https://sub.example.com/", "info": {"name": "XSS check", "severity": "medium"}},
            {"template-id": "sqli", "matched-at": "https://sub.example.com/login", "info": {"name": "SQLi", "severity": "high"}},
        )
        return self._scan("second")

    def test_a_repeat_scan_reports_what_changed(self, tmp_path: Path) -> None:
        second = self._scan_twice(tmp_path)

        assert "Since" in second.stdout and "(first)" in second.stdout
        assert "1 new finding" in second.stdout and "1 new subdomain" in second.stdout
        report = json.loads((tmp_path / "reports" / "second" / "report.json").read_text(encoding="utf-8"))
        assert report["changes"]["baseline"]["session_id"] == "first"
        assert report["changes"]["summary"] == ["1 new finding", "1 new subdomain"]
        html = (tmp_path / "reports" / "second" / "report.html").read_text(encoding="utf-8")
        assert '<section id="changes"' in html

    def test_no_baseline_skips_the_comparison(self, tmp_path: Path) -> None:
        self._scan_twice(tmp_path)
        third = self._scan("third", "--no-baseline")

        assert "Since" not in third.stdout
        assert "changes" not in json.loads((tmp_path / "reports" / "third" / "report.json").read_text(encoding="utf-8"))

    def test_diff_command_compares_two_saved_runs(self, tmp_path: Path) -> None:
        self._scan_twice(tmp_path)

        text = runner.invoke(app, ["diff", "first", "second"])
        assert text.exit_code == 0, text.stdout
        assert "1 new finding" in text.stdout and "SQLi" in text.stdout

        as_json = runner.invoke(app, ["diff", "first", "second", "--json"])
        assert as_json.exit_code == 0, as_json.stdout
        assert json.loads(as_json.stdout)["summary"] == ["1 new finding", "1 new subdomain"]

        missing = runner.invoke(app, ["diff", "first", "nope"])
        assert missing.exit_code == 2 and "no report.json" in missing.stdout


class TestAlertExitCode:
    """The exit code ranks a failed run above an alert above a clean run."""

    def test_a_failed_run_outranks_an_alert(self) -> None:
        _pipeline_exit_code = cli._pipeline_exit_code

        # Even with new findings to alert on, a broken scan is reported as broken.
        assert _pipeline_exit_code(succeeded=False, alert_hits=5) == 1

    def test_new_findings_exit_3(self) -> None:
        _pipeline_exit_code = cli._pipeline_exit_code

        assert _pipeline_exit_code(succeeded=True, alert_hits=1) == 3

    def test_a_clean_run_exits_0(self) -> None:
        _pipeline_exit_code = cli._pipeline_exit_code

        assert _pipeline_exit_code(succeeded=True, alert_hits=0) == 0


class TestAlert:
    """`pipeline --alert` turns new findings into exit code 3 and an ALERT line."""

    def _baseline_then_add_a_high_finding(self, tmp_path: Path) -> None:
        first = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "base", "--no-mail"]
        )
        assert first.exit_code == 0, first.stdout
        # The next run's nuclei keeps the medium xss and adds a new high finding.
        TestBaselineComparison._tool_prints(
            tmp_path, "nuclei",
            {"template-id": "xss", "matched-at": "https://sub.example.com/", "info": {"name": "XSS", "severity": "medium"}},
            {"template-id": "sqli", "matched-at": "https://sub.example.com/login", "info": {"name": "SQLi", "severity": "high"}},
        )

    def test_a_new_finding_exits_3_with_an_alert_line(self, tmp_path: Path) -> None:
        self._baseline_then_add_a_high_finding(tmp_path)

        res = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "watch", "--no-mail", "--alert"]
        )

        assert res.exit_code == 3, res.stdout
        assert "ALERT" in res.stdout and "new finding" in res.stdout

    def test_a_threshold_above_the_new_finding_does_not_alert(self, tmp_path: Path) -> None:
        self._baseline_then_add_a_high_finding(tmp_path)  # the new finding is high, not critical

        res = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "watch", "--no-mail",
                  "--alert", "--alert-severity", "critical"]
        )

        assert res.exit_code == 0, res.stdout
        assert "ALERT" not in res.stdout

    def test_an_unchanged_rescan_does_not_alert(self, tmp_path: Path) -> None:
        first = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "base", "--no-mail"]
        )
        assert first.exit_code == 0, first.stdout

        res = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "again", "--no-mail", "--alert"]
        )

        assert res.exit_code == 0, res.stdout
        assert "ALERT" not in res.stdout

    def test_the_first_scan_never_alerts(self) -> None:
        # No earlier run to compare with, so nothing is "new".
        res = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "only", "--no-mail", "--alert"]
        )

        assert res.exit_code == 0, res.stdout
        assert "ALERT" not in res.stdout

    def test_alert_with_no_baseline_is_a_usage_error(self) -> None:
        res = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-mail", "--alert", "--no-baseline"]
        )

        assert res.exit_code == 2
        assert "baseline" in res.stdout.lower()

    def test_alert_rejects_an_unknown_severity(self) -> None:
        res = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-mail", "--alert", "--alert-severity", "nope"]
        )

        assert res.exit_code == 2


class TestLocalToolInCli:
    """A `source: local` tool (nmap) is reported by PATH, skipped by init, and blocks
    a pipeline that needs it when it is not installed."""

    @staticmethod
    def _add_nmap(root: Path) -> None:
        with (root / "registry.yaml").open("a", encoding="utf-8") as handle:
            handle.write("nmap:\n  source: local\n  binary: nmap\n")

    def test_init_of_a_local_tool_skips_it_with_a_note(self, tmp_path: Path) -> None:
        self._add_nmap(tmp_path)

        res = runner.invoke(app, ["init", "nmap"])  # a local tool only → nothing to download

        assert res.exit_code == 0, res.stdout
        assert "local tool" in res.stdout and "skipping" in res.stdout
        assert "Done: 0 tool(s) ready" in res.stdout

    def test_status_lists_a_local_tool_found_on_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._add_nmap(tmp_path)
        monkeypatch.setattr("cyberfw.manager.find_in_path", lambda cmd: "/usr/bin/nmap" if cmd == "nmap" else None)

        res = runner.invoke(app, ["status"])

        assert res.exit_code == 0, res.stdout
        assert "nmap" in res.stdout and "local" in res.stdout  # listed, with source "local"

    def test_a_pipeline_needing_an_absent_local_tool_is_blocked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._add_nmap(tmp_path)
        (tmp_path / "pipelines").mkdir(exist_ok=True)
        (tmp_path / "pipelines" / "svc.yaml").write_text(
            "nodes:\n  - tool: httpx\n    stage: live\n  - tool: nmap\n    stage: services\n", encoding="utf-8"
        )
        monkeypatch.setattr("cyberfw.manager.find_in_path", lambda cmd: None)  # nmap not on PATH

        res = runner.invoke(app, ["pipeline", "svc", "-t", "example.com", "--no-mail"])

        assert res.exit_code == 2
        assert "nmap" in res.stdout and "not installed" in res.stdout


class TestGowitnessDefault:
    """On a vanilla run gowitness is included only when it can actually run; an
    explicit --gowitness/--no-gowitness is honoured as given."""

    class _Reg:
        def __init__(self, names: list[str]) -> None:
            self._names = names

        def names(self) -> list[str]:
            return self._names

    class _Mgr:
        def __init__(self, names: list[str], installed: bool) -> None:
            self.registry = TestGowitnessDefault._Reg(names)
            self._installed = installed

        def is_installed(self, name: str) -> bool:
            return self._installed

    def test_an_explicit_flag_is_honoured(self, tmp_path: Path) -> None:
        _resolve_gowitness = cli.resolve_gowitness

        mgr = self._Mgr(["gowitness"], True)
        assert _resolve_gowitness(True, mgr, tmp_path) is True
        assert _resolve_gowitness(False, mgr, tmp_path) is False

    def test_default_includes_it_only_when_registered_installed_and_chrome_present(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _resolve_gowitness = cli.resolve_gowitness

        monkeypatch.setattr("cyberfw.tools.gowitness._find_chrome", lambda _d: "/usr/bin/chrome")
        assert _resolve_gowitness(None, self._Mgr(["gowitness"], True), tmp_path) is True

        monkeypatch.setattr("cyberfw.tools.gowitness._find_chrome", lambda _d: None)  # no browser
        assert _resolve_gowitness(None, self._Mgr(["gowitness"], True), tmp_path) is False

        monkeypatch.setattr("cyberfw.tools.gowitness._find_chrome", lambda _d: "/usr/bin/chrome")
        assert _resolve_gowitness(None, self._Mgr(["gowitness"], False), tmp_path) is False  # not installed
        assert _resolve_gowitness(None, self._Mgr([], True), tmp_path) is False  # not registered


class TestSummaryDetail:
    """A vanilla run's closing summary breaks findings down, not just per-tool counts."""

    @staticmethod
    def _records() -> list[object]:
        from cyberfw.pipeline.schemas import NaabuResult, NucleiResult, SubfinderResult

        return [
            SubfinderResult(tool="subfinder", host="a.example.com", target="a.example.com", kind="host"),
            SubfinderResult(tool="subfinder", host="b.example.com", target="b.example.com", kind="host"),
            NaabuResult(tool="naabu", host="a.example.com", port=22, target="a.example.com:22", kind="port"),
            NucleiResult(tool="nuclei", target="https://a.example.com/x", kind="vuln",
                         template_id="sqli", info={"name": "SQL injection", "severity": "critical"}),
            NucleiResult(tool="nuclei", target="https://a.example.com/y", kind="vuln",
                         template_id="xss", info={"name": "XSS", "severity": "high"}),
            NucleiResult(tool="nuclei", target="https://a.example.com/z", kind="vuln",
                         template_id="info", info={"name": "Tech", "severity": "info"}),
        ]

    def test_severity_tally_counts_only_vulns(self) -> None:
        _severity_tally = cli._severity_tally

        tally = _severity_tally(self._records())
        assert tally["critical"] == 1 and tally["high"] == 1 and tally["info"] == 1
        assert tally["medium"] == 0 and tally["low"] == 0

    def test_asset_counts_are_by_kind(self) -> None:
        _asset_counts = cli._asset_counts

        assert _asset_counts(self._records()) == {"hosts": 2, "ports": 1}

    def test_fix_first_lists_the_worst_findings_first(self) -> None:
        _fix_first = cli._fix_first

        worst = _fix_first(self._records())
        # critical before high; the info-level finding is not "fix first"
        assert [getattr(r, "name", "") for r in worst] == ["SQL injection", "XSS"]

    def test_fix_first_skips_a_muted_finding(self) -> None:
        _fix_first = cli._fix_first
        from cyberfw.pipeline.schemas import NucleiResult

        records = [
            NucleiResult(tool="nuclei", target="https://a/x", kind="vuln", template_id="c",
                         info={"name": "Crit", "severity": "critical"}, muted={"reason": "false_positive"}),
        ]
        assert _fix_first(records) == []

    def test_summary_shows_the_breakdown(self) -> None:
        _run_summary = cli._run_summary
        from cyberfw.pipeline.engine import Node, NodeResult, PipelineResult

        result = PipelineResult(
            nodes=[NodeResult(node=Node(tool="nuclei", stage="vulns"), ok=True, count=3)],
            records=self._records(),
        )
        output = Console(theme=THEME, record=True, width=100)
        output.print(_run_summary(result, name="recon-to-vuln", session_id="s", reports=[]))
        text = output.export_text()

        assert "critical" in text and "high" in text  # severity breakdown
        assert "hosts" in text and "ports" in text  # asset counts
        assert "SQL injection" in text  # the worst finding is named


class TestPipelinePlan:
    """`pipeline --plan` prints the stage graph and pre-flight, and does not scan."""

    def test_plan_lists_the_stages_without_running(self) -> None:
        res = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--plan"])

        assert res.exit_code == 0, res.stdout
        for stage_tool in ("subfinder", "httpx", "nuclei"):
            assert stage_tool in res.stdout
        # it planned, it did not scan: no run summary, no report
        assert "record(s)" not in res.stdout and "elapsed" not in res.stdout

    def test_plan_needs_no_target(self) -> None:
        res = runner.invoke(app, ["pipeline", "recon-to-vuln", "--plan"])

        assert res.exit_code == 0, res.stdout
        assert "nuclei" in res.stdout

    def test_plan_shows_pre_flight_readiness(self) -> None:
        res = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--plan"])

        assert "ready" in res.stdout  # the pre-flight state of each stage's tool

    def test_plan_shows_per_stage_options(self, tmp_path: Path) -> None:
        TestYamlPipelines._write_pipeline(
            tmp_path, "tuned", "nodes:\n  - tool: nuclei\n    stage: vulns\n    severity: critical,high\n"
        )

        res = runner.invoke(app, ["pipeline", "tuned", "--plan"])

        assert res.exit_code == 0, res.stdout
        assert "critical,high" in res.stdout

    def test_plan_on_an_unknown_pipeline_is_a_usage_error(self) -> None:
        assert runner.invoke(app, ["pipeline", "nope", "--plan"]).exit_code == 2


class TestExportCommand:
    """`cyberfw export <run> --sarif|--csv` converts a saved report.json."""

    @staticmethod
    def _save_report(tmp_path: Path, session: str = "exp") -> str:
        payload = {
            "ok": True,
            "run": {"cyberfw_version": "9.9.9", "pipeline": "recon-to-vuln", "seed": "example.com"},
            "stages": [],
            "total_records": 2,
            "records": [
                {
                    "tool": "nuclei", "kind": "vuln", "target": "https://a.example.com/x",
                    "template_id": "xss", "matched_at": "https://a.example.com/x",
                    "info": {"name": "Reflected XSS", "severity": "critical"},
                },
                {"tool": "subfinder", "kind": "host", "target": "a.example.com", "host": "a.example.com"},
            ],
        }
        session_dir = tmp_path / "reports" / session
        session_dir.mkdir(parents=True, exist_ok=True)
        (session_dir / "report.json").write_text(json.dumps(payload), encoding="utf-8")
        return session

    def test_sarif_to_stdout_is_valid_json(self, tmp_path: Path) -> None:
        session = self._save_report(tmp_path)

        res = runner.invoke(app, ["export", session, "--sarif"])

        assert res.exit_code == 0, res.stdout
        doc = json.loads(res.stdout)  # the whole stdout is the document, nothing else
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["results"][0]["ruleId"] == "xss"

    def test_csv_to_stdout_parses(self, tmp_path: Path) -> None:
        session = self._save_report(tmp_path)

        res = runner.invoke(app, ["export", session, "--csv"])

        assert res.exit_code == 0, res.stdout
        rows = list(csv.DictReader(io.StringIO(res.stdout)))
        assert len(rows) == 2 and rows[0]["severity"] == "critical"

    def test_output_file_is_written(self, tmp_path: Path) -> None:
        session = self._save_report(tmp_path)
        out = tmp_path / "out.sarif"

        res = runner.invoke(app, ["export", session, "--sarif", "-o", str(out)])

        assert res.exit_code == 0, res.stdout
        assert out.is_file() and json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"

    def test_exactly_one_format_is_required(self, tmp_path: Path) -> None:
        session = self._save_report(tmp_path)
        assert runner.invoke(app, ["export", session]).exit_code == 2
        assert runner.invoke(app, ["export", session, "--sarif", "--csv"]).exit_code == 2

    def test_an_unknown_run_is_a_usage_error(self) -> None:
        assert runner.invoke(app, ["export", "nope", "--sarif"]).exit_code == 2


class TestScanControlsCli:
    """`--severity/--tags/--rate-limit/--exclude` override the settings for one run."""

    def test_overrides_picks_only_the_flags_that_were_set(self) -> None:
        _scan_control_overrides = cli._scan_control_overrides

        assert _scan_control_overrides(severity="", tags="", rate_limit=None, exclude=[]) == {}
        assert _scan_control_overrides(severity="high", tags="", rate_limit=None, exclude=[]) == {"severity": "high"}
        assert _scan_control_overrides(severity="high", tags="cve", rate_limit=20, exclude=["*.dev"]) == {
            "severity": "high", "tags": "cve", "rate_limit": 20, "exclude": ["*.dev"],
        }

    def test_rate_limit_zero_is_a_usage_error(self) -> None:
        res = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--rate-limit", "0"])
        assert res.exit_code == 2

    def test_exclude_drops_a_discovered_host_and_reports_it(self, tmp_path: Path) -> None:
        # The fake subfinder finds sub.example.com; excluding it must keep it out
        # of the downstream stages and print the scope line.
        res = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-mail", "--no-report",
                  "--exclude", "sub.example.com"]
        )
        assert res.exit_code == 0, res.stdout
        assert "scope: 1 host(s) excluded" in res.stdout

    def test_run_accepts_the_scan_control_flags(self) -> None:
        res = runner.invoke(app, ["run", "nuclei", "-t", "https://sub.example.com/", "--severity", "high", "--no-save"])
        assert res.exit_code == 0, res.stdout


class TestScheduleCommand:
    """`cyberfw schedule` generates an OS-scheduler entry (and installs it with --install)."""

    @staticmethod
    def _posix(monkeypatch: pytest.MonkeyPatch, *, yes: bool = True) -> None:
        patch_cli(monkeypatch, "_is_posix", lambda: yes)
        patch_cli(monkeypatch, "_schedule_program", lambda: ["cyberfw"])

    def test_prints_a_cron_line_by_default_on_posix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._posix(monkeypatch)
        installed: list[str] = []
        monkeypatch.setattr("cyberfw.schedule.install_cron", lambda *a, **k: installed.append("x"))

        res = runner.invoke(app, ["schedule", "recon-to-vuln", "-t", "example.com", "--every", "daily", "--at", "09:00"])

        assert res.exit_code == 0, res.stdout
        assert "0 9 * * *" in res.stdout and "--alert" in res.stdout
        assert "cyberfw-recon-to-vuln-example.com" in res.stdout
        assert installed == []  # printed only — nothing touched

    def test_prints_a_schtasks_command_on_windows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_cli(monkeypatch, "_is_posix", lambda: False)
        patch_cli(monkeypatch, "_schedule_program", lambda: ["cyberfw"])

        res = runner.invoke(app, ["schedule", "recon-to-vuln", "-t", "example.com"])

        assert res.exit_code == 0, res.stdout
        assert "schtasks" in res.stdout and "/Create" in res.stdout

    def test_a_target_with_shell_metacharacters_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The entry becomes a command cron/schtasks later runs, so an injection
        # target must be refused before it is ever written anywhere.
        self._posix(monkeypatch)
        installed: list[str] = []
        monkeypatch.setattr("cyberfw.schedule.install_cron", lambda *a, **k: installed.append("x"))

        res = runner.invoke(app, ["schedule", "recon-to-vuln", "-t", "example.com$(touch pwned)", "--install"])

        assert res.exit_code == 2
        assert installed == []  # refused before anything was generated or written
        assert "may only contain" in res.stdout  # and the reason is explained

    def test_install_applies_the_entry_with_the_passed_through_flags(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._posix(monkeypatch)
        seen: dict[str, object] = {}

        def fake_install(plan: object, *, program: str, root: str, log: str, expr: str | None = None) -> None:
            seen.update(
                pipeline=plan.pipeline, target=plan.target, severity=plan.alert_severity, args=plan.scan_args
            )

        monkeypatch.setattr("cyberfw.schedule.install_cron", fake_install)

        res = runner.invoke(
            app, ["schedule", "recon-to-vuln", "-t", "example.com", "--ffuf", "--no-mail",
                  "--alert-severity", "high", "--install"]
        )

        assert res.exit_code == 0, res.stdout
        assert seen["pipeline"] == "recon-to-vuln" and seen["target"] == "example.com"
        assert seen["severity"] == "high"
        assert "--ffuf" in seen["args"] and "--no-mail" in seen["args"]

    def test_remove_deletes_the_entry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._posix(monkeypatch)
        removed: list[str] = []
        monkeypatch.setattr("cyberfw.schedule.remove_cron", lambda plan: bool(removed.append(plan.target)) or True)

        res = runner.invoke(app, ["schedule", "recon-to-vuln", "-t", "example.com", "--remove"])

        assert res.exit_code == 0, res.stdout
        assert removed == ["example.com"]

    def test_a_raw_cron_overrides_the_cadence_on_posix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._posix(monkeypatch)

        res = runner.invoke(app, ["schedule", "recon-to-vuln", "-t", "example.com", "--cron", "*/5 * * * *"])

        assert res.exit_code == 0, res.stdout
        assert "*/5 * * * *" in res.stdout

    def test_a_raw_cron_on_windows_is_a_usage_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        patch_cli(monkeypatch, "_is_posix", lambda: False)

        res = runner.invoke(app, ["schedule", "recon-to-vuln", "-t", "example.com", "--cron", "*/5 * * * *"])

        assert res.exit_code == 2
        assert "cron" in res.stdout.lower()

    def test_a_bad_cadence_is_a_usage_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._posix(monkeypatch)

        res = runner.invoke(app, ["schedule", "recon-to-vuln", "-t", "example.com", "--every", "monthly"])

        assert res.exit_code == 2

    def test_the_fallback_program_starts_the_cli(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Without `cyberfw` on PATH the entry runs this interpreter with
        # `-m cyberfw`; if that cannot start the CLI, every such scheduled scan fails.
        _schedule_program = cli._schedule_program

        monkeypatch.setattr(cli.shutil, "which", lambda _name: None)
        run = subprocess.run(
            [*_schedule_program(), "--help"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            env={**os.environ, "PYTHONUTF8": "1"},
            timeout=120,
        )

        assert run.returncode == 0, run.stderr
        assert "schedule" in run.stdout and "pipeline" in run.stdout


class TestTriage:
    """`cyberfw mute` silences a finding; the next scan sets it aside and does not call it new."""

    def _mute(self, *args: str) -> object:
        result = runner.invoke(app, ["mute", *args])
        assert result.exit_code == 0, result.stdout
        return result

    def test_mute_list_and_unmute_round_trip(self, tmp_path: Path) -> None:
        self._mute("self-signed", "--target", "dev.example.com", "--reason", "accepted_risk", "--note", "dev box")
        self._mute("CVE-2021-1234", "--reason", "false_positive")

        assert (tmp_path / "triage.yaml").is_file()
        listed = runner.invoke(app, ["mutes"])
        assert "m1" in listed.stdout and "self-signed" in listed.stdout and "dev.example.com" in listed.stdout
        assert "m2" in listed.stdout and "CVE-2021-1234" in listed.stdout

        removed = runner.invoke(app, ["unmute", "m1"])
        assert removed.exit_code == 0 and "Removed" in removed.stdout
        assert "m1" not in runner.invoke(app, ["mutes"]).stdout
        assert runner.invoke(app, ["unmute", "m1"]).exit_code == 1  # already gone

    def test_mute_validates_reason_and_expiry(self) -> None:
        assert runner.invoke(app, ["mute", "x", "--reason", "nonsense"]).exit_code == 2
        assert runner.invoke(app, ["mute", "x", "--expires", "soon"]).exit_code == 2

    def test_a_muted_finding_is_set_aside_on_the_next_scan(self, tmp_path: Path) -> None:
        self._tool_prints_xss()
        first = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "pre", "--no-mail", "--no-baseline"]
        )
        assert first.exit_code == 0 and "1 new finding" not in first.stdout

        self._mute("xss", "--reason", "false_positive")
        second = runner.invoke(
            app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "post", "--no-mail"]
        )
        assert second.exit_code == 0, second.stdout
        assert "Triage: 1 finding(s) muted" in second.stdout
        assert "new finding" not in second.stdout  # muted, so the comparison with 'pre' does not call it new

        report = json.loads((tmp_path / "reports" / "post" / "report.json").read_text(encoding="utf-8"))
        vuln = next(r for r in report["records"] if r["kind"] == "vuln")
        assert vuln["muted"] == {"reason": "false_positive", "rule": "m1"}

    @staticmethod
    def _tool_prints_xss() -> None:
        import cyberfw  # noqa: F401 - ensure the package import path is set up

        binary = Path("tools_bin") / "nuclei"
        line = json.dumps({"template-id": "xss", "matched-at": "https://sub.example.com/",
                           "info": {"name": "XSS check", "severity": "medium"}})
        binary.write_text("#!/usr/bin/env bash\n" f"printf '%s\\n' '{line}'\n", encoding="utf-8")
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)


class TestCleanInterface:
    """The interface opens on a clean screen and keeps the launcher on one."""

    @staticmethod
    def _screen(monkeypatch: pytest.MonkeyPatch, *, interactive: bool = True,
                inputs: list[object] | None = None) -> list[str]:
        """Record what the console is asked to do; ``inputs`` feed ``console.input``."""

        calls: list[str] = []
        queue = list(inputs or [])

        def fake_input(*_a: object, **_k: object) -> str:
            calls.append("input")
            item = queue.pop(0) if queue else ""
            if isinstance(item, BaseException):
                raise item
            return str(item)

        patch_cli(monkeypatch, "_is_interactive", lambda: interactive)
        monkeypatch.setattr(cli.console, "clear", lambda *a, **k: calls.append("clear"))
        monkeypatch.setattr(cli.console, "set_window_title", lambda title: calls.append(f"title:{title}"))
        monkeypatch.setattr(cli.console, "input", fake_input)
        return calls

    def test_prepare_installs_missing_tools_and_exits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ran: list[bool] = []
        patch_cli(monkeypatch, "_ensure_tools", lambda: ran.append(True))
        result = runner.invoke(app, ["prepare"])
        assert result.exit_code == 0 and ran == [True]
        assert "prepare" not in runner.invoke(app, ["--help"]).stdout  # a launcher detail, not a command to advertise

    def test_the_interface_starts_on_a_clean_titled_screen(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _fresh_screen = cli._fresh_screen

        calls = self._screen(monkeypatch)
        _fresh_screen()
        assert calls == ["title:CS-TOOL", "clear"]

    def test_a_pipe_or_a_log_keeps_its_plain_transcript(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _back_to_launcher, _fresh_screen = cli._back_to_launcher, cli._fresh_screen

        calls = self._screen(monkeypatch, interactive=False)
        _fresh_screen()
        assert _back_to_launcher(review=True) is True
        assert calls == []  # no clearing, no waiting

    def test_back_to_the_launcher_waits_after_an_action_but_not_after_a_toggle(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _back_to_launcher = cli._back_to_launcher

        calls = self._screen(monkeypatch)
        assert _back_to_launcher(review=True) is True
        assert calls == ["input", "clear"]  # read the output, Enter, clean frame
        calls.clear()
        assert _back_to_launcher(review=False) is True
        assert calls == ["clear"]  # a settings toggle redraws at once

    def test_leaving_at_the_pause_says_goodbye(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _back_to_launcher = cli._back_to_launcher

        self._screen(monkeypatch, inputs=[KeyboardInterrupt()])
        assert _back_to_launcher(review=True) is False

    @staticmethod
    def _terminal_console(monkeypatch: pytest.MonkeyPatch) -> io.StringIO:
        """Point the module console at a StringIO that records a terminal's control codes."""

        screen = io.StringIO()
        # _environ={} so the suite's TERM=dumb does not make Rich suppress control codes.
        patch_cli(monkeypatch, "console", Console(file=screen, force_terminal=True, force_interactive=True, _environ={})
        )
        return screen

    def test_clearing_the_screen_also_wipes_the_scrollback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Returning to the menu must leave nothing to scroll back to: the visible
        screen (CSI 2J) and the scrollback (CSI 3J) both go."""

        screen = self._terminal_console(monkeypatch)
        cli._clear_screen()
        out = screen.getvalue()
        assert "\x1b[2J" in out and "\x1b[3J" in out

    def test_returning_to_the_launcher_wipes_the_scrollback(self, monkeypatch: pytest.MonkeyPatch) -> None:

        screen = self._terminal_console(monkeypatch)
        assert cli._back_to_launcher(review=False) is True
        assert "\x1b[3J" in screen.getvalue()

    def test_a_pipe_never_wipes_the_scrollback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Redirected output keeps its full transcript — no screen or scrollback control codes.

        screen = io.StringIO()
        patch_cli(monkeypatch, "console", Console(file=screen, force_interactive=False))
        assert cli._back_to_launcher(review=True) is True
        assert screen.getvalue() == ""

    def test_the_menu_pauses_then_redraws_cleanly_between_actions(self, monkeypatch: pytest.MonkeyPatch) -> None:

        calls = self._screen(monkeypatch)
        choices = iter(["1", "0"])
        patch_cli(monkeypatch, "_ensure_tools", lambda: None)
        patch_cli(monkeypatch, "_prompt_choice", lambda names: next(choices))
        patch_cli(monkeypatch, "_dispatch_choice", lambda choice, names: choice != "0")  # "1" = an action ran
        cli.interactive_menu()

        assert calls[:2] == ["title:CS-TOOL", "clear"]  # clean start after install/check
        assert calls[2:] == ["input", "clear"]  # after the action: Enter, then a clean launcher

    def test_the_help_key_shows_the_cheatsheet_then_returns(self, monkeypatch: pytest.MonkeyPatch) -> None:

        calls = self._screen(monkeypatch)
        choices = iter(["?", "0"])
        shown: list[list[str]] = []
        patch_cli(monkeypatch, "_ensure_tools", lambda: None)
        patch_cli(monkeypatch, "_prompt_choice", lambda names: next(choices))
        patch_cli(monkeypatch, "_show_help", lambda names: shown.append(names))
        patch_cli(monkeypatch, "_dispatch_choice", lambda choice, names: choice != "0")
        cli.interactive_menu()

        assert len(shown) == 1  # the cheatsheet was shown once
        # Shown like any action output: it stays until Enter, then the launcher redraws.
        assert calls[2:] == ["input", "clear"]

    def test_ctrl_c_at_the_menu_is_a_clean_exit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Exit 0, not "Aborted!" — so a Windows Terminal window opened for the interface closes."""

        def interrupted(names: list[str]) -> str:
            raise KeyboardInterrupt

        patch_cli(monkeypatch, "_ensure_tools", lambda: None)
        patch_cli(monkeypatch, "_prompt_choice", interrupted)
        result = runner.invoke(app, [])
        assert result.exit_code == 0 and "Goodbye." in result.stdout

    def test_launchers_open_the_interface_in_a_clean_terminal(self) -> None:
        root = Path(__file__).resolve().parents[2]
        bat = (root / "cstool.bat").read_text(encoding="utf-8")
        # tools are fetched in the install window, then a new Windows Terminal window
        # opens the interface, unless already in one or opted out
        assert "cyberfw.cli prepare" in bat
        assert "if defined WT_SESSION goto run_here" in bat and "CYBERFW_NO_WT" in bat
        assert 'wt -w new --size 120,36 --title "CS-TOOL"' in bat
        assert 'if not "%~1"=="" goto run_here' in bat  # commands with arguments stay in place
        sh = (root / "start.sh").read_text(encoding="utf-8")
        assert "cyberfw.cli prepare" in sh and "exec uv run" in sh


class TestLockCommand:
    def test_lock_creates_the_file_and_lists_the_tool(self, fake_github: object) -> None:
        result = runner.invoke(app, ["lock", "pinme"])

        assert result.exit_code == 0
        assert (Path.cwd() / "tools.lock").is_file()
        assert "pinme" in result.stdout and "added" in result.stdout and "v1.2.3" in result.stdout

    def test_a_second_run_reports_unchanged_and_keeps_the_file(self, fake_github: object) -> None:
        runner.invoke(app, ["lock", "pinme"])
        before = (Path.cwd() / "tools.lock").read_bytes()

        result = runner.invoke(app, ["lock", "pinme"])

        assert result.exit_code == 0
        assert "unchanged" in result.stdout
        assert (Path.cwd() / "tools.lock").read_bytes() == before

    def test_an_unknown_tool_is_a_usage_error(self, fake_github: object) -> None:
        result = runner.invoke(app, ["lock", "nope"])

        assert result.exit_code == 2
        assert "Unknown tool" in result.stdout

    def test_the_lock_lives_next_to_the_registry_in_use(
        self, fake_github: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An editable install run from another directory uses the checkout's registry —
        its lock belongs next to that registry, not in the current directory."""
        checkout = tmp_path / "checkout"
        checkout.mkdir()
        (checkout / "registry.yaml").write_text(
            (tmp_path / "registry.yaml").read_text(encoding="utf-8"), encoding="utf-8"
        )
        patch_cli(monkeypatch, "registry_path", lambda: checkout / "registry.yaml")

        result = runner.invoke(app, ["lock", "pinme", "--token", "t0ken"])

        assert result.exit_code == 0
        assert (checkout / "tools.lock").is_file()
        assert not (tmp_path / "tools.lock").exists()


class TestInitWithLock:
    def test_init_without_a_lock_creates_it_and_says_to_commit_it(self, fake_github: object) -> None:
        result = runner.invoke(app, ["init", "pinme"])

        assert result.exit_code == 0
        assert (Path.cwd() / "tools.lock").is_file()
        assert "commit" in result.stdout

    def test_init_with_a_lock_does_not_repeat_the_note(self, fake_github: object) -> None:
        runner.invoke(app, ["lock", "pinme"])

        result = runner.invoke(app, ["init", "pinme"])

        assert result.exit_code == 0
        assert "commit" not in result.stdout

    def test_a_download_that_does_not_match_the_lock_is_a_failed_row(self, fake_github: object) -> None:
        runner.invoke(app, ["lock", "pinme"])
        lock = Path.cwd() / "tools.lock"
        lock.write_text(
            re.sub(r"sha256: [0-9a-f]{64}", "sha256: " + "0" * 64, lock.read_text(encoding="utf-8")),
            encoding="utf-8",
        )

        result = runner.invoke(app, ["init", "pinme"])

        assert result.exit_code == 1
        assert "failed" in result.stdout


def _one_line(text: str) -> str:
    """Rich folds long lines at the console width; compare against the unfolded text."""
    return text.replace("\n", "")


class TestLockCommandOutcomes:
    def test_upgrade_moves_a_tool_to_the_newer_release(
        self, fake_github: object, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cyberfw.manager.github_client import GitHubRelease, ReleaseAsset

        runner.invoke(app, ["lock", "pinme"])
        original = fake_github.release  # type: ignore[attr-defined]

        def newer(self: object, owner: str, repo: str, tag: str) -> GitHubRelease:
            old = original(self, owner, repo, tag)
            renamed = [
                ReleaseAsset(a.name.replace("1.2.3", "1.2.4"), a.url.replace("1.2.3", "1.2.4"), a.size, a.digest)
                for a in old.assets
            ]
            return GitHubRelease(tag="v1.2.4", assets=renamed, checksums_url=None)

        monkeypatch.setattr(fake_github, "release", newer)

        plain = runner.invoke(app, ["lock", "pinme"])
        upgraded = runner.invoke(app, ["lock", "pinme", "--upgrade"])

        assert "unchanged" in plain.stdout
        assert upgraded.exit_code == 0
        assert "upgraded" in upgraded.stdout and "v1.2.4" in upgraded.stdout

    def test_a_tool_that_cannot_be_resolved_is_a_failed_row_and_exit_1(
        self, fake_github: object, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cyberfw.exceptions import DownloadError

        def unreachable(self: object, owner: str, repo: str, tag: str) -> object:
            raise DownloadError(f"GitHub API unreachable for {owner}/{repo}")

        monkeypatch.setattr(fake_github, "release", unreachable)

        result = runner.invoke(app, ["lock", "pinme"])

        assert result.exit_code == 1
        assert "failed" in result.stdout

    @pytest.mark.parametrize(
        ("command", "says"), [(["lock", "pinme"], "tools.lock"), (["init", "pinme"], "failed")], ids=["lock", "init"]
    )
    def test_a_malformed_lock_is_exit_1_without_a_traceback(
        self, fake_github: object, command: list[str], says: str
    ) -> None:
        (Path.cwd() / "tools.lock").write_bytes("version: 1\ntools: {}\n".encode("utf-16"))

        result = runner.invoke(app, command)

        assert result.exit_code == 1
        assert result.exception is None or isinstance(result.exception, SystemExit)
        assert says in _one_line(result.stdout)

    def test_a_lock_that_cannot_be_written_still_shows_the_changes(
        self, fake_github: object, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def refuse(src: object, dst: object) -> None:
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr("cyberfw.manager.lock.os.replace", refuse)

        result = runner.invoke(app, ["lock", "pinme"])

        assert result.exit_code == 1
        assert "added" in result.stdout
        assert "workspace" in _one_line(result.stdout)

    def test_with_nothing_to_lock_it_says_so(self) -> None:
        (Path.cwd() / "registry.yaml").write_text("{}\n", encoding="utf-8")

        result = runner.invoke(app, ["lock"])

        assert result.exit_code == 0
        assert "Nothing to lock" in result.stdout
        assert "unchanged" not in result.stdout


class TestInitLockMessages:
    def test_init_help_describes_the_lock(self) -> None:
        result = runner.invoke(app, ["init", "--help"])

        assert "tools.lock" in _one_line(result.stdout)
        assert "latest release" not in _one_line(result.stdout)

    def test_the_progress_line_names_the_locked_tag(self, fake_github: object) -> None:
        _bootstrap, _locked_tags = cli._bootstrap, cli._locked_tags

        runner.invoke(app, ["lock", "pinme"])
        _, manager = _bootstrap()
        try:
            assert _locked_tags(manager) == {"pinme": "v1.2.3"}
        finally:
            manager.close()

    def test_an_unreadable_lock_gives_no_tags_rather_than_a_crash(self, fake_github: object) -> None:
        _bootstrap, _locked_tags = cli._bootstrap, cli._locked_tags

        (Path.cwd() / "tools.lock").write_text("- not a lock\n", encoding="utf-8")
        _, manager = _bootstrap()
        try:
            assert _locked_tags(manager) == {}
        finally:
            manager.close()

    def test_init_names_what_it_added_to_an_existing_lock(self, fake_github: object) -> None:
        (Path.cwd() / "tools.lock").write_text("version: 1\ntools: {}\n", encoding="utf-8")

        result = runner.invoke(app, ["init", "pinme"])

        assert result.exit_code == 0
        assert "Added pinme to tools.lock" in _one_line(result.stdout)
        assert "commit" in result.stdout

    def test_the_launcher_names_what_it_added_to_the_lock(self, fake_github: object) -> None:

        (Path.cwd() / "registry.yaml").write_text(
            "pinme:\n  repo: org/pinme\n  asset_patterns: ['pinme_*']\n  binary: pinme\n", encoding="utf-8"
        )

        with cli.console.capture() as captured:
            cli._ensure_tools()

        text = _one_line(captured.get())
        assert "Created tools.lock with pinme" in text
        assert "commit" in text

    def test_a_packaged_lock_is_not_called_something_to_commit(
        self, fake_github: object, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A wheel install keeps its lock in site-packages: there is no repository to commit to."""
        site = tmp_path / "site" / "cyberfw" / "data"
        site.mkdir(parents=True)
        (site / "registry.yaml").write_text((tmp_path / "registry.yaml").read_text(encoding="utf-8"), encoding="utf-8")
        patch_cli(monkeypatch, "registry_path", lambda: site / "registry.yaml")
        patch_cli(monkeypatch, "packaged_data", lambda *parts: site.joinpath(*parts))

        result = runner.invoke(app, ["init", "pinme"])

        assert result.exit_code == 0
        assert "Created tools.lock with pinme" in _one_line(result.stdout)
        assert "commit" not in result.stdout


class TestLiveDisplaysOnATerminal:
    """On a terminal the scan's live view and each step's activity line are Rich
    live displays, opened and closed by the run's events."""

    def test_every_live_display_is_closed_when_the_run_ends(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Rich nests live displays, so one left open raises nothing — it keeps
        # redrawing and leaves the cursor hidden. Every hidden cursor comes back.
        monkeypatch.setenv("TERM", "xterm-256color")
        monkeypatch.setenv("CYBERFW_ANIMATIONS", "true")
        terminal = Console(file=io.StringIO(), force_terminal=True, width=120, theme=THEME)
        patch_cli(monkeypatch, "console", terminal)

        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report"])

        assert result.exit_code == 0, repr(result.exception)
        raw = terminal.file.getvalue()  # type: ignore[attr-defined]
        assert raw.count("\x1b[?25l") == raw.count("\x1b[?25h") > 1, "a live display was left open"
        drawn = Text.from_ansi(raw).plain
        assert "recon-to-vuln · example.com" in drawn and "Email check skipped" in drawn
