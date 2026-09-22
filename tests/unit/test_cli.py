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
