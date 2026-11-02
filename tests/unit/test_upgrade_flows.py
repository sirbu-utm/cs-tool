"""Exercise the upgrade fixes together through public runs and saved reports."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from cyberfw import api
from cyberfw.cli import app
from cyberfw.config import Settings
from cyberfw.manager import ToolManager
from cyberfw.manager.registry import ToolRegistry, ToolSpec
from cyberfw.plugin import BaseTool, ToolContext
from cyberfw.posture import takeover

_FIXTURE = r'''
import json, os, sys, time
from pathlib import Path

script = Path(__file__)
role, args = sys.argv[1], sys.argv[2:]
script.with_suffix(".started").write_text(
    json.dumps({"role": role, "argv": args, "cwd": os.getcwd()}), encoding="utf-8"
)
config = json.loads(script.with_suffix(".json").read_text(encoding="utf-8")).get(role, {})
if "-tags" in args:
    tag = args[args.index("-tags") + 1]
    config = config.get("variants", {}).get(tag, config)
sys.stdout.write(config.get("stdout", "")); sys.stdout.flush()
sys.stderr.write(config.get("stderr", "")); sys.stderr.flush()
if config.get("close_pipes"):
    os.close(1)
    os.close(2)
time.sleep(config.get("sleep", 0))
os._exit(config.get("exit_code", 0))
'''


@dataclass
class ToolWorkspace:
    settings: Settings
    repo: Path
    script: Path

    @property
    def marker(self) -> Path:
        return self.script.with_suffix(".started")

    def configure(self, config: dict[str, Any]) -> None:
        self.script.with_suffix(".json").write_text(json.dumps(config), encoding="utf-8")


@pytest.fixture
def tools(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ToolWorkspace:
    root = tmp_path / "workspace with spaces"
    script = root / "bin" / "fixture.py"
    script.parent.mkdir(parents=True)
    script.write_text(_FIXTURE, encoding="utf-8")
    repo = root / "repository с пробелами"
    repo.mkdir()
    settings = Settings(root_dir=root, animations=False, log_to_file=False)
    names = ("gitleaks", "subfinder", "httpx", "nuclei")
    registry = ToolRegistry({name: ToolSpec(name=name, source="local", path="bin/fixture.py") for name in names})
    manager = ToolManager(settings, registry)
    original_adapter = manager.adapter_for

    def adapter_for(name: str, binary: Path) -> BaseTool:
        adapter = original_adapter(name, binary)
        original_build = adapter.build_cmd

        def build(ctx: ToolContext) -> list[str]:
            cmd = original_build(ctx)
            # Keep the real adapter's flags, validation and parser. Only the
            # external executable is a harmless, stdlib-only Python fixture.
            return [getattr(sys, "_base_executable", sys.executable), cmd[0], name, *cmd[1:]]

        monkeypatch.setattr(adapter, "build_cmd", build)
        return adapter

    monkeypatch.setattr(manager, "adapter_for", adapter_for)
    # These flows start with an explicit manager, past the registry selection that
    # test_core_workspace covers, and exercise its path resolution and execution.
    monkeypatch.setattr(api, "open_manager", lambda _settings: manager)
    monkeypatch.setattr("cyberfw.cli.scan._setup", lambda **_kwargs: settings)
    other = tmp_path / "unrelated working directory"
    (other / "bin").mkdir(parents=True)
    (other / "bin" / "fixture.py").write_text("raise SystemExit('wrong workspace')\n", encoding="utf-8")
    monkeypatch.chdir(other)
    workspace = ToolWorkspace(settings, repo, script)
    workspace.configure({})
    return workspace


@pytest.mark.parametrize("mode", ["success", "failed-exit", "timeout-after-eof"])
def test_public_tool_run_keeps_unicode_findings_reports_and_failure_status(
    tools: ToolWorkspace, mode: str
) -> None:
    target = "repo/конфиг с пробелами.txt"
    config: dict[str, Any] = {
        "stdout": json.dumps([{"RuleID": "fixture-rule", "File": target, "Description": "Fixture finding"}]) + "\n",
        "stderr": "fixture diagnostic\n",
        "exit_code": 7 if mode == "failed-exit" else 0,
    }
    if mode == "timeout-after-eof":
        config.update(close_pipes=True, sleep=3)
        tools.settings.stage_timeout = 1
    tools.configure({"gitleaks": config})

    outcome = api.run_tool("gitleaks", target=str(tools.repo), settings=tools.settings, save=True)

    assert outcome.succeeded == (mode == "success")
    assert outcome.exit_code() == (0 if mode == "success" else 1)
    assert outcome.result.nodes[0].count == 1
    assert [record.target for record in outcome.result.records] == [target]
    saved = api.load_run(outcome.session_id, settings=tools.settings)
    assert saved.payload["ok"] == outcome.succeeded
    assert saved.payload["records"][0]["target"] == target
    assert saved.payload["stages"][0]["count"] == 1
    assert outcome.reports["html"].is_file()
    assert outcome.session_dir.parent == tools.settings.reports_dir
    lines = (outcome.session_dir / "gitleaks.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["target"] == target
    assert api.export_sarif(saved)["runs"][0]["results"][0]["ruleId"] == "fixture-rule"
    assert target in api.export_csv(saved)
    called = json.loads(tools.marker.read_text(encoding="utf-8"))
    assert called["argv"][:2] == ["dir", str(tools.repo)]
    assert Path(called["cwd"]) == Path.cwd()
    if mode == "failed-exit":
        assert "exited with code 7" in (outcome.result.nodes[0].error or "")
    elif mode == "timeout-after-eof":
        assert "timed out" in (outcome.result.nodes[0].error or "")


@pytest.mark.parametrize("entry", ["api", "cli"])
def test_directory_list_is_rejected_before_the_external_fixture_starts(tools: ToolWorkspace, entry: str) -> None:
    if entry == "api":
        outcome = api.run_tool("gitleaks", inputs=[str(tools.repo)], settings=tools.settings, save=True)
        assert not outcome.succeeded
        assert "--list" in (outcome.result.nodes[0].error or "")
        saved = api.load_run(outcome.session_id, settings=tools.settings)
        assert saved.payload["ok"] is False and saved.payload["records"] == []
    else:
        list_file = tools.repo / "directories.txt"
        list_file.write_text(str(tools.repo) + "\n", encoding="utf-8")
        result = CliRunner().invoke(app, ["run", "gitleaks", "--list", str(list_file), "--no-save"])
        assert result.exit_code == 1
        assert "--list" in result.output and "--target" in result.output

    assert not tools.marker.exists()


def test_cli_empty_directory_list_is_a_noop(tools: ToolWorkspace) -> None:
    list_file = tools.repo / "empty.txt"
    list_file.write_text("# intentionally empty\n\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["run", "gitleaks", "--list", str(list_file), "--no-save"])

    assert result.exit_code == 0
    assert not tools.marker.exists()


def _vuln(template: str) -> str:
    return json.dumps({
        "template-id": template, "matched-at": "https://public.example.com/",
        "info": {"name": template, "severity": "high"},
    }) + "\n"


def test_saved_pipeline_comparison_does_not_call_a_failed_stage_finding_fixed(tools: ToolWorkspace) -> None:
    tools.settings.pipelines_dir.mkdir()
    (tools.settings.pipelines_dir / "two-nuclei.yaml").write_text(
        "nodes:\n"
        "  - {tool: httpx, stage: live}\n"
        "  - {tool: nuclei, stage: cves, input_from: live, tags: cve}\n"
        "  - {tool: nuclei, stage: exposures, input_from: live, tags: exposure}\n",
        encoding="utf-8",
    )
    config = {
        "httpx": {"stdout": json.dumps({"url": "https://public.example.com/", "status_code": 200}) + "\n"},
        "nuclei": {"variants": {"cve": {"stdout": _vuln("cve-fixture")}, "exposure": {"stdout": _vuln("exposure-fixture")}}},
    }
    tools.configure(config)
    baseline = api.run_pipeline(
        "two-nuclei", "example.com", settings=tools.settings, session="baseline",
        mail=False, takeover=False, intel=False, gowitness=False, compare=False,
    )
    assert baseline.succeeded
    config["nuclei"]["variants"]["exposure"] = {"exit_code": 7, "stderr": "fixture failed\n"}
    tools.configure(config)

    outcome = api.run_pipeline(
        "two-nuclei", "example.com", settings=tools.settings, session="current", baseline=str(baseline.session_dir),
        mail=False, takeover=False, intel=False, gowitness=False,
    )

    assert not outcome.succeeded and outcome.exit_code("low") == 1
    assert [stage.ok for stage in outcome.result.nodes] == [True, True, False]
    assert outcome.changes is not None and outcome.changes.changes == []
    assert len(outcome.changes.not_compared) == 1 and "nuclei" in outcome.changes.not_compared[0]
    saved = api.load_run(outcome.session_id, settings=tools.settings)
    assert saved.payload["changes"]["changes"] == []
    assert saved.payload["changes"]["not_compared"] == outcome.changes.not_compared
    assert api.compare_runs(api.load_run(baseline.session_id, settings=tools.settings), saved).changes == []


def test_full_recon_pipeline_keeps_excluded_discoveries_without_probing_them(
    tools: ToolWorkspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    probes: list[tuple[str, str]] = []

    async def resolve(_client: httpx.AsyncClient, host: str, _rtype: str) -> tuple[int, list[str]]:
        probes.append(("dns", host))
        return 0, ["unclaimed.github.io"]

    async def fetch(_client: httpx.AsyncClient, host: str) -> str:
        probes.append(("http", host))
        return "There isn't a GitHub Pages site here."

    monkeypatch.setattr(takeover, "doh", resolve)
    monkeypatch.setattr(takeover, "http_body", fetch)
    tools.configure({
        "subfinder": {"stdout": '{"host":"private.example.com"}\n{"host":"public.example.com"}\n'},
        "httpx": {"stdout": '{"url":"https://public.example.com/","status_code":200}\n'},
        "nuclei": {"stdout": ""},
    })

    outcome = api.run_pipeline(
        "recon-to-vuln", "example.com", settings=tools.settings, exclude=["private.example.com"],
        mail=False, takeover=True, intel=False, gowitness=False, compare=False,
    )

    assert outcome.succeeded
    assert outcome.result.excluded == ["private.example.com"]
    assert probes == [("dns", "public.example.com"), ("http", "public.example.com")]
    assert any(record.kind == "host" and record.target == "private.example.com" for record in outcome.result.records)
    findings = [record for record in outcome.result.records if record.tool == "takeover"]
    assert [finding.target for finding in findings] == ["https://public.example.com"]
    saved = api.load_run(outcome.session_id, settings=tools.settings)
    assert any(record["target"] == "private.example.com" for record in saved.payload["records"])
    assert [record["target"] for record in saved.payload["records"] if record["tool"] == "takeover"] == [
        "https://public.example.com"
    ]
