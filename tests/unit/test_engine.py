"""Unit tests for the PipelineEngine using a stubbed tool adapter.

The engine is tested end-to-end but with a fake child process, so no real
security binary is required (and no network is touched).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from cyberfw.config import Settings
from cyberfw.manager import ToolManager
from cyberfw.manager.registry import load_registry
from cyberfw.pipeline.context import SessionContext
from cyberfw.pipeline.engine import Node, PipelineEngine
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.tools.base import BaseTool, ToolContext


class _StubTool(BaseTool):
    """Adapter whose ``build_cmd`` runs a tiny JSONL printer for the target."""

    def build_cmd(self, ctx: ToolContext) -> list[str]:
        target = ctx.target or (ctx.inputs[0] if ctx.inputs else "")
        return [sys.executable, str(self.binary), target]


class _CaptureCmdTool(BaseTool):
    """Adapter that records the argv it receives (for threading regression test).

    This mimics real adapters (httpx, nuclei, subfinder, naabu) which prefer
    `input_file` with `-l` when available, and only fall back to `target` with `-u`
    when there's no input file.
    """

    last_cmd: list[str] | None = None

    @property
    def input_flag(self) -> str | None:
        return "-l"

    def build_cmd(self, ctx: ToolContext) -> list[str]:
        cmd: list[str] = [sys.executable, str(self.binary)]
        if ctx.target:
            cmd += ["-u", ctx.target]
        elif ctx.input_file:
            cmd += ["-l", str(ctx.input_file)]
        _CaptureCmdTool.last_cmd = cmd
        return cmd


class _PerTargetTool(BaseTool):
    per_target = True

    def build_cmd(self, ctx: ToolContext) -> list[str]:
        return [ctx.target or ""]


def _make_engine(tmp_path: Path, registry_path: Path) -> PipelineEngine:
    settings = Settings(root_dir=tmp_path, reports_dir=tmp_path / "reports")
    settings.ensure_dirs()
    registry = load_registry(registry_path)
    manager = ToolManager(settings, registry)
    context = SessionContext(tmp_path / "reports", "sess")
    return PipelineEngine(settings, manager, context=context)


def _stub_binary(tmp_path: Path) -> Path:
    script = tmp_path / "stub_probe.py"
    script.write_text(
        'import json, sys\n'
        't = sys.argv[1] if len(sys.argv) > 1 else "seed.example.com"\n'
        'sys.stdout.write(json.dumps({"host": t, "source": "stub"}) + "\\n")\n',
        encoding="utf-8",
    )
    return script


class TestEngine:
    async def test_runs_single_node_and_records(self, tmp_path: Path) -> None:
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: stub_probe.py\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        stub = _StubTool(engine.tool_manager.spec("subfinder"), _stub_binary(tmp_path))
        engine.build_tool = lambda name: stub  # type: ignore[method-assign]

        result = await engine.run([Node(tool="subfinder", stage="subdomains")], seed="seed.example.com")
        assert result.succeeded()
        assert len(result.records) == 1
        assert result.records[0].target == "seed.example.com"
        assert result.totals_by_tool["subfinder"] == 1

    async def test_max_records_caps(self, tmp_path: Path) -> None:
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: stub_probe.py\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        script = tmp_path / "many.py"
        script.write_text(
            'import json, sys\n'
            'for i in range(10):\n'
            '    sys.stdout.write(json.dumps({"host": f"h{i}.x"}) + "\\n")\n',
            encoding="utf-8",
        )
        stub = _StubTool(engine.tool_manager.spec("subfinder"), script)
        engine.build_tool = lambda name: stub  # type: ignore[method-assign]

        result = await engine.run([Node(tool="subfinder", stage="sub", max_records=3)], seed="x")
        assert result.succeeded()
        assert len(result.records) == 3

    async def test_crash_recorded_not_raised(self, tmp_path: Path) -> None:
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: stub_probe.py\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        script = tmp_path / "crash.py"
        script.write_text("import sys\nsys.exit(9)\n", encoding="utf-8")
        stub = _StubTool(engine.tool_manager.spec("subfinder"), script)
        engine.build_tool = lambda name: stub  # type: ignore[method-assign]

        result = await engine.run([Node(tool="subfinder", stage="sub")], seed="x")
        assert not result.succeeded()
        assert result.nodes[0].ok is False
        assert result.nodes[0].error is not None

    async def test_build_cmd_toolnotfound_is_clean_stage_failure(self, tmp_path: Path) -> None:
        """A pre-flight ToolNotFoundError (e.g. Ffuf without a wordlist) must be a
        clean stage failure carrying the message — not a propagated traceback."""
        from cyberfw.exceptions import ToolNotFoundError

        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: stub_probe.py\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)

        class _NoWordlistTool(_StubTool):
            def build_cmd(self, ctx: ToolContext) -> list[str]:
                raise ToolNotFoundError("Ffuf needs a wordlist.")

        stub = _NoWordlistTool(engine.tool_manager.spec("subfinder"), _stub_binary(tmp_path))
        engine.build_tool = lambda name: stub  # type: ignore[method-assign]

        result = await engine.run([Node(tool="subfinder", stage="fuzz")], seed="x")

        assert result.nodes[0].ok is False
        assert "wordlist" in (result.nodes[0].error or "")

    async def test_run_threads_extra_input_to_stages(self, tmp_path: Path) -> None:
        """engine.run(extra_input=...) must reach adapters (Ffuf wordlist path)."""
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: stub_probe.py\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        seen: list[str | None] = []

        class _RecordingTool(_StubTool):
            def build_cmd(self, ctx: ToolContext) -> list[str]:
                seen.append(ctx.extra_input)
                return super().build_cmd(ctx)

        stub = _RecordingTool(engine.tool_manager.spec("subfinder"), _stub_binary(tmp_path))
        engine.build_tool = lambda name: stub  # type: ignore[method-assign]

        await engine.run(
            [Node(tool="subfinder", stage="sub")], seed="x", extra_input="/tmp/words.txt"
        )
        assert seen == ["/tmp/words.txt"]

    async def test_threads_records_between_nodes(self, tmp_path: Path) -> None:
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: stub_probe.py\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        script = tmp_path / "echo_one.py"
        script.write_text(
            'import json, sys\n'
            'sys.stdout.write(json.dumps({"host": sys.argv[1]}) + "\\n")\n',
            encoding="utf-8",
        )
        stub = _StubTool(engine.tool_manager.spec("subfinder"), script)
        engine.build_tool = lambda name: stub  # type: ignore[method-assign]

        # Two nodes; the second runs per_target? No — both single. Verify dedup threading:
        result = await engine.run(
            [Node(tool="subfinder", stage="a"), Node(tool="subfinder", stage="b")], seed="s.example.com"
        )
        assert len(result.records) == 2
        assert result.nodes[0].count == 1
        assert result.nodes[1].count == 1

    async def test_stage2_uses_input_file_not_seed(self, tmp_path: Path) -> None:
        """
        Regression test for the threading bug: stage 2+ must receive -l <input_file>
        with previous stage's results, NOT -u <original_seed>.

        This test uses an adapter that captures the command it receives.
        The stub binary echoes back whatever target it gets.
        """
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: stub_probe.py\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        script = tmp_path / "echo_target.py"
        script.write_text(
            'import json, sys\n'
            'sys.stdout.write(json.dumps({"host": sys.argv[1]}) + "\\n")\n',
            encoding="utf-8",
        )
        stub = _CaptureCmdTool(engine.tool_manager.spec("subfinder"), script)
        engine.build_tool = lambda name: stub  # type: ignore[method-assign]

        # Run a two-stage pipeline: seed "seed.example.com" -> stage "a" produces "a1.example.com"
        # Stage "b" should receive "a1.example.com" via input file, NOT "seed.example.com"
        await engine.run(
            [Node(tool="subfinder", stage="a"), Node(tool="subfinder", stage="b")], seed="seed.example.com"
        )

        # Stage 2 (node "b") should have been invoked with the output from stage 1
        assert _CaptureCmdTool.last_cmd is not None
        # The command should use -l <input_file> (threaded input), NOT -u <seed>
        cmd_str = " ".join(_CaptureCmdTool.last_cmd)
        assert "-l" in cmd_str, f"Stage 2 should use -l <input_file>, got: {cmd_str}"
        assert "-u" not in cmd_str, f"Stage 2 should NOT use -u <seed>, got: {cmd_str}"
        # The input file should be the stage-specific one (b.input for stage "b")
        assert "b.input" in cmd_str, f"Stage 2 should use its own input file, got: {cmd_str}"

    async def test_fan_out_honors_concurrency_limit(self, tmp_path: Path, monkeypatch) -> None:
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: stub_probe.py\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        engine.settings.concurrency = 2
        adapter = _PerTargetTool(engine.tool_manager.spec("subfinder"), tmp_path / "stub_probe.py")
        active = 0
        peak = 0

        async def fake_run_stage(command, **kwargs):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return [ToolRecord(tool="subfinder", target=command[0], kind="host")]

        monkeypatch.setattr("cyberfw.pipeline.engine.run_stage", fake_run_stage)
        records = await engine._fan_out(
            adapter,
            ToolContext(inputs=[f"host-{index}" for index in range(5)]),
            Node(tool="subfinder", stage="fan-out"),
        )

        assert peak == 2
        assert [record.target for record in records] == [f"host-{index}" for index in range(5)]


class TestToolContextDefaults:
    def test_empty_context(self) -> None:
        ctx = ToolContext()
        assert ctx.target is None
        assert ctx.inputs == []
        assert ctx.input_file is None
        assert ctx.extra_input is None


class TestBuildToolDependencyCheck:
    """RustScan's Nmap dependency degrades gracefully: warn, never block."""

    async def test_missing_dependency_warns_but_still_builds(
        self, tmp_path: Path, monkeypatch, caplog
    ) -> None:
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "rustscan:\n"
            "  repo: org/rustscan\n"
            "  asset_patterns: []\n"
            "  binary: rustscan\n"
            '  check_deps: ["nmap"]\n',
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        binary = engine.settings.tools_dir / "rustscan"
        binary.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
        binary.chmod(0o755)

        monkeypatch.setattr("cyberfw.pipeline.engine.shutil.which", lambda _dep: None)
        with caplog.at_level("WARNING", logger="cyberfw.engine"):
            adapter = engine.build_tool("rustscan")

        assert adapter.name == "rustscan"
        assert any("nmap" in record.message for record in caplog.records)

    async def test_present_dependency_stays_quiet(self, tmp_path: Path, monkeypatch, caplog) -> None:
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "rustscan:\n"
            "  repo: org/rustscan\n"
            "  asset_patterns: []\n"
            "  binary: rustscan\n"
            '  check_deps: ["nmap"]\n',
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        binary = engine.settings.tools_dir / "rustscan"
        binary.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
        binary.chmod(0o755)

        monkeypatch.setattr("cyberfw.pipeline.engine.shutil.which", lambda _dep: "/usr/bin/nmap")
        with caplog.at_level("WARNING", logger="cyberfw.engine"):
            engine.build_tool("rustscan")

        assert not caplog.records
