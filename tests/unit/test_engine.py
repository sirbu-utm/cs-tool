"""Unit tests for the PipelineEngine using a stubbed tool adapter.

The engine is tested end-to-end but with a fake child process, so no real
security binary is required (and no network is touched).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from cyberfw.config import Settings
from cyberfw.exceptions import ExecutionError
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

    async def test_input_from_reads_a_named_earlier_stage_not_the_previous_one(self, tmp_path: Path) -> None:
        """nuclei/ffuf/gowitness must all fan out over httpx's live hosts, not over each other's findings."""
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: stub_probe.py\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        script = tmp_path / "append_x.py"
        script.write_text(
            'import json, sys\n'
            'sys.stdout.write(json.dumps({"host": sys.argv[1] + "x"}) + "\\n")\n',
            encoding="utf-8",
        )
        seen_inputs: list[list[str]] = []

        class _RecordingTool(_StubTool):
            def build_cmd(self, ctx: ToolContext) -> list[str]:
                seen_inputs.append(list(ctx.inputs))
                return super().build_cmd(ctx)

        stub = _RecordingTool(engine.tool_manager.spec("subfinder"), script)
        engine.build_tool = lambda name: stub  # type: ignore[method-assign]

        result = await engine.run(
            [
                Node(tool="subfinder", stage="a"),
                Node(tool="subfinder", stage="b"),
                Node(tool="subfinder", stage="c", input_from="a"),
            ],
            seed="s",
        )

        # a: s -> sx ; b: sx -> sxx ; c reads a's output (sx), not b's (sxx)
        assert seen_inputs == [[], ["sx"], ["sx"]]
        assert [r.target for r in result.records] == ["sx", "sxx", "sxx"]

    async def test_input_from_unknown_stage_is_rejected_up_front(self, tmp_path: Path) -> None:
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: stub_probe.py\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        with pytest.raises(ValueError, match="input_from"):
            await engine.run(
                [Node(tool="subfinder", stage="a"), Node(tool="subfinder", stage="b", input_from="nope")],
                seed="s",
            )

    async def test_input_list_is_materialised_without_a_session_context(self, tmp_path: Path) -> None:
        """`run <tool> --list hosts.txt` without --save has no SessionContext but must still get -l <file>."""
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: stub_probe.py\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        engine.context = None
        script = tmp_path / "noop.py"
        script.write_text("pass\n", encoding="utf-8")
        stub = _CaptureCmdTool(engine.tool_manager.spec("subfinder"), script)
        engine.build_tool = lambda name: stub  # type: ignore[method-assign]

        node_result, _ = await engine._run_node(Node(tool="subfinder", stage="s"), None, ["a.example.com", "b.example.com"])

        assert node_result.ok, node_result.error
        assert _CaptureCmdTool.last_cmd is not None and "-l" in _CaptureCmdTool.last_cmd
        listed = Path(_CaptureCmdTool.last_cmd[-1]).read_text(encoding="utf-8").split()
        assert listed == ["a.example.com", "b.example.com"]

    async def test_adapter_can_normalise_inputs_before_they_are_materialised(self, tmp_path: Path, monkeypatch) -> None:
        """RustScan wants bare hosts in its --addresses file even when upstream handed over URLs / host:port."""
        from cyberfw.tools.rustscan import RustscanTool

        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "rustscan:\n  repo: org/rustscan\n  asset_patterns: []\n  binary: rustscan\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        adapter = RustscanTool(engine.tool_manager.spec("rustscan"), tmp_path / "rustscan")
        captured: list[list[str]] = []

        async def fake_run_stage(command, **kwargs):
            captured.append(command)
            return []

        monkeypatch.setattr("cyberfw.pipeline.engine.run_stage", fake_run_stage)
        await engine._dispatch(
            adapter,
            ToolContext(inputs=["https://a.example.com/login", "10.0.0.1:8080", "a.example.com"]),
            Node(tool="rustscan", stage="ports"),
        )

        cmd = captured[0]
        addresses = Path(cmd[cmd.index("--addresses") + 1])
        assert addresses.read_text(encoding="utf-8").split() == ["a.example.com", "10.0.0.1"]

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

    async def test_fan_out_keeps_other_targets_when_one_crashes(self, tmp_path: Path, monkeypatch) -> None:
        """One unreachable host (ffuf/gowitness exits non-zero) must not discard the other 49."""
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: stub_probe.py\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        adapter = _PerTargetTool(engine.tool_manager.spec("subfinder"), tmp_path / "stub_probe.py")

        async def flaky_run_stage(command, **kwargs):
            if command[0] == "host-1":
                raise ExecutionError("gowitness exited with code 1", exit_code=1, stderr_tail=["connection reset"])
            return [ToolRecord(tool="subfinder", target=command[0], kind="host")]

        monkeypatch.setattr("cyberfw.pipeline.engine.run_stage", flaky_run_stage)
        records = await engine._fan_out(
            adapter,
            ToolContext(inputs=["host-0", "host-1", "host-2"]),
            Node(tool="subfinder", stage="fan-out"),
        )

        assert [record.target for record in records] == ["host-0", "host-2"]

    async def test_fan_out_fails_the_stage_only_when_every_target_fails(self, tmp_path: Path, monkeypatch) -> None:
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: stub_probe.py\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        adapter = _PerTargetTool(engine.tool_manager.spec("subfinder"), tmp_path / "stub_probe.py")

        async def always_fail(command, **kwargs):
            raise ExecutionError("boom", exit_code=1, stderr_tail=[])

        monkeypatch.setattr("cyberfw.pipeline.engine.run_stage", always_fail)
        with pytest.raises(ExecutionError, match="all 2 target"):
            await engine._fan_out(
                adapter, ToolContext(inputs=["host-0", "host-1"]), Node(tool="subfinder", stage="fan-out")
            )


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


class TestContextStoreLifecycle:
    async def test_stage_files_are_released_once_the_stage_is_over(self, tmp_path: Path, monkeypatch) -> None:
        """The store keeps a stage's JSONL file open while records stream in; the engine
        must close it when the stage finishes, so nothing outlives the run."""
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: stub_probe.py\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        stub = _StubTool(engine.tool_manager.spec("subfinder"), _stub_binary(tmp_path))
        engine.build_tool = lambda name: stub  # type: ignore[method-assign]
        assert engine.context is not None

        await engine.run([Node(tool="subfinder", stage="sub")], seed="seed.example.com")

        opens = 0
        real_open = Path.open

        def counting_open(self: Path, *args, **kwargs):
            nonlocal opens
            opens += 1
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", counting_open)
        engine.context.append("sub", ToolRecord(tool="subfinder", target="late.example.com", kind="host"))
        engine.context.close()

        assert opens == 1, "the stage file was still open after the run"


class TestStageTimeout:
    async def test_a_hung_tool_is_a_clean_stage_failure(self, tmp_path: Path) -> None:
        """Without a limit a stuck scanner blocks the whole pipeline until Ctrl+C;
        with ``stage_timeout`` it becomes an ordinary failed NodeResult."""
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: hang.py\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        engine.settings.stage_timeout = 0.3
        script = tmp_path / "hang.py"
        script.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
        stub = _StubTool(engine.tool_manager.spec("subfinder"), script)
        engine.build_tool = lambda name: stub  # type: ignore[method-assign]

        result = await engine.run([Node(tool="subfinder", stage="sub")], seed="x")

        assert not result.succeeded()
        assert result.nodes[0].error is not None
        assert "timed out" in result.nodes[0].error


class TestRunSingle:
    async def test_public_single_node_entry_point(self, tmp_path: Path) -> None:
        """``cyberfw run`` drives one node through the same fan-out/timeout/error handling
        as a pipeline stage, via a public method rather than the engine's internals."""
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: stub_probe.py\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        stub = _StubTool(engine.tool_manager.spec("subfinder"), _stub_binary(tmp_path))
        engine.build_tool = lambda name: stub  # type: ignore[method-assign]

        node_result, records = await engine.run_single(
            Node(tool="subfinder", stage="subfinder"), ToolContext(target="seed.example.com")
        )

        assert node_result.ok
        assert [r.target for r in records] == ["seed.example.com"]
