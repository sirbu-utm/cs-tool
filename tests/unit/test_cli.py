"""Typer CLI unit tests — end-to-end commands through CliRunner.

Uses a temporary workspace with fake tool binaries and a local registry.yaml,
so the whole code path runs without network and without real precompiled tools.
"""

from __future__ import annotations

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
        assert len(rendered.rows) == 3

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

    def test_banner_shows_wordmark_and_tool_count(self) -> None:
        output = Console(theme=THEME, record=True, width=100)
        output.print(banner(tool_count=8))
        rendered = output.export_text()
        # the block-art wordmark itself, not literal "CS-TOOL" text
        assert "▄▄▄▄▄▄▄▄▄" in rendered
        assert "Integrated Cybersecurity Framework" in rendered
        assert "8 tools registered" in rendered


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
