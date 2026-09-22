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
from cyberfw.pipeline.engine import Node, PipelineEngine, StageEvent
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


class TestMissingBinaryIsAStageFailure:
    async def test_uninstalled_tool_fails_its_stage_and_the_rest_still_runs(self, tmp_path: Path) -> None:
        """A registered tool whose binary is absent (``--gowitness`` never installed) must
        become a failed NodeResult like any other stage error — not abort the run and
        throw away the report for the stages that already completed."""
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "gowitness:\n  repo: org/gowitness\n  asset_patterns: []\n  binary: gowitness\n"
            "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: stub_probe.py\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        stub = _StubTool(engine.tool_manager.spec("subfinder"), _stub_binary(tmp_path))
        real_build_tool = engine.build_tool
        engine.build_tool = lambda name: stub if name == "subfinder" else real_build_tool(name)  # type: ignore[method-assign]

        result = await engine.run(
            [Node(tool="subfinder", stage="sub"), Node(tool="gowitness", stage="shots", input_from="sub")],
            seed="seed.example.com",
        )

        assert result.nodes[0].ok is True
        assert result.nodes[1].ok is False
        assert "not installed" in (result.nodes[1].error or "")
        # the failure does not discard what the stage before it found
        assert [r.target for r in result.records] == ["seed.example.com"]


class TestRunTiming:
    async def test_result_records_when_the_run_started_and_finished(self, tmp_path: Path) -> None:
        from datetime import datetime, timezone

        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: stub_probe.py\n",
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)
        stub = _StubTool(engine.tool_manager.spec("subfinder"), _stub_binary(tmp_path))
        engine.build_tool = lambda name: stub  # type: ignore[method-assign]
        before = datetime.now(timezone.utc)

        result = await engine.run([Node(tool="subfinder", stage="sub")], seed="x")

        assert result.started_at is not None and result.finished_at is not None
        assert result.started_at.tzinfo is not None, "timestamps must be timezone-aware (UTC)"
        assert before <= result.started_at <= result.finished_at <= datetime.now(timezone.utc)
        assert result.duration_s is not None and result.duration_s >= 0


# -- stage lifecycle events (what a live progress view subscribes to) -----------------
_REGISTRY = "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: stub_probe.py\n"


def _engine_with(tmp_path: Path, adapter_factory) -> tuple[PipelineEngine, list[StageEvent]]:
    registry_path = tmp_path / "registry.yaml"
    registry_path.write_text(_REGISTRY, encoding="utf-8")
    engine = _make_engine(tmp_path, registry_path)
    adapter: BaseTool = adapter_factory(engine)
    engine.build_tool = lambda name: adapter  # type: ignore[method-assign]
    events: list[StageEvent] = []

    async def on_stage(event: StageEvent) -> None:
        events.append(event)

    engine.set_stage_callback(on_stage)
    return engine, events


class TestStageEvents:
    async def test_single_process_stage_emits_start_then_done(self, tmp_path: Path) -> None:
        engine, events = _engine_with(
            tmp_path, lambda e: _StubTool(e.tool_manager.spec("subfinder"), _stub_binary(tmp_path))
        )

        result = await engine.run([Node(tool="subfinder", stage="sub")], seed="seed.example.com")

        assert [(e.kind, e.stage, e.tool) for e in events] == [("start", "sub", "subfinder"), ("done", "sub", "subfinder")]
        assert events[0].result is None
        assert events[1].result is result.nodes[0]
        assert events[1].result is not None and events[1].result.ok

    async def test_fan_out_reports_progress_per_target(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        engine, events = _engine_with(
            tmp_path, lambda e: _PerTargetTool(e.tool_manager.spec("subfinder"), tmp_path / "stub_probe.py")
        )

        async def fake_run_stage(command, **kwargs):
            return [ToolRecord(tool="subfinder", target=command[0], kind="host")]

        monkeypatch.setattr("cyberfw.pipeline.engine.run_stage", fake_run_stage)
        await engine.run_single(
            Node(tool="subfinder", stage="shots"), ToolContext(inputs=["host-0", "host-1", "host-2"])
        )

        kinds = [e.kind for e in events]
        assert kinds == ["start", "progress", "progress", "progress", "done"]
        assert [(e.done, e.total) for e in events if e.kind == "progress"] == [(1, 3), (2, 3), (3, 3)]
        assert (events[0].done, events[0].total) == (0, 3), "start announces how many targets there are"

    async def test_progress_counts_failed_targets_too(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A host that errors out is still a finished unit of work — the bar must reach total."""
        engine, events = _engine_with(
            tmp_path, lambda e: _PerTargetTool(e.tool_manager.spec("subfinder"), tmp_path / "stub_probe.py")
        )

        async def flaky_run_stage(command, **kwargs):
            if command[0] == "host-1":
                raise ExecutionError("exited with code 1", exit_code=1, stderr_tail=[])
            return [ToolRecord(tool="subfinder", target=command[0], kind="host")]

        monkeypatch.setattr("cyberfw.pipeline.engine.run_stage", flaky_run_stage)
        await engine.run_single(Node(tool="subfinder", stage="shots"), ToolContext(inputs=["host-0", "host-1"]))

        assert [(e.done, e.total) for e in events if e.kind == "progress"] == [(1, 2), (2, 2)]

    async def test_failed_stage_emits_done_carrying_the_failure(self, tmp_path: Path) -> None:
        script = tmp_path / "crash.py"
        script.write_text("import sys\nsys.exit(9)\n", encoding="utf-8")
        engine, events = _engine_with(tmp_path, lambda e: _StubTool(e.tool_manager.spec("subfinder"), script))

        await engine.run([Node(tool="subfinder", stage="sub")], seed="x")

        done = events[-1]
        assert done.kind == "done"
        assert done.result is not None and done.result.ok is False
        assert "code 9" in (done.result.error or "")

    async def test_no_subscriber_is_fine(self, tmp_path: Path) -> None:
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(_REGISTRY, encoding="utf-8")
        engine = _make_engine(tmp_path, registry_path)
        stub = _StubTool(engine.tool_manager.spec("subfinder"), _stub_binary(tmp_path))
        engine.build_tool = lambda name: stub  # type: ignore[method-assign]

        result = await engine.run([Node(tool="subfinder", stage="sub")], seed="x")

        assert result.succeeded()

    def test_event_is_a_plain_value(self) -> None:
        event = StageEvent(kind="start", stage="sub", tool="subfinder", done=0, total=1)
        assert event == StageEvent(kind="start", stage="sub", tool="subfinder", done=0, total=1)
        assert event.result is None


class TestFailedSourceIsNotSilentlyReplacedByTheSeed:
    """A stage exists to scan what the stage before it found. If that stage failed,
    running anyway against the bare seed quietly changes what the pipeline means:
    `ports-to-vuln` with a blocked naabu probed the seed URL instead of open ports.
    """

    @staticmethod
    def _engine(tmp_path: Path):
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "naabu:\n  repo: org/naabu\n  asset_patterns: []\n  binary: stub_probe.py\n"
            "httpx:\n  repo: org/httpx\n  asset_patterns: []\n  binary: stub_probe.py\n"
            "nuclei:\n  repo: org/nuclei\n  asset_patterns: []\n  binary: stub_probe.py\n",
            encoding="utf-8",
        )
        return _make_engine(tmp_path, registry_path)

    @staticmethod
    def _tools(engine, tmp_path: Path, crashing: set[str]):
        crash = tmp_path / "crash.py"
        crash.write_text("import sys\nsys.exit(4)\n", encoding="utf-8")
        probe = _stub_binary(tmp_path)

        def build(name: str):
            spec = engine.tool_manager.spec(name)
            return _StubTool(spec, crash if name in crashing else probe)

        engine.build_tool = build  # type: ignore[method-assign]

    async def test_next_stage_is_skipped_when_its_source_failed(self, tmp_path: Path) -> None:
        engine = self._engine(tmp_path)
        self._tools(engine, tmp_path, crashing={"naabu"})

        result = await engine.run(
            [Node(tool="naabu", stage="ports"), Node(tool="httpx", stage="live_http")],
            seed="https://example.com",
        )

        assert result.nodes[0].ok is False
        assert result.nodes[1].ok is False
        assert result.nodes[1].skipped is True
        assert "ports" in (result.nodes[1].error or "")
        assert result.records == []

    async def test_skip_propagates_down_the_chain(self, tmp_path: Path) -> None:
        engine = self._engine(tmp_path)
        self._tools(engine, tmp_path, crashing={"naabu"})

        result = await engine.run(
            [
                Node(tool="naabu", stage="ports"),
                Node(tool="httpx", stage="live_http"),
                Node(tool="nuclei", stage="vulns", input_from="live_http"),
            ],
            seed="https://example.com",
        )

        assert [n.skipped for n in result.nodes] == [False, True, True]
        assert all(not n.ok for n in result.nodes)

    async def test_a_named_source_that_ran_fine_is_unaffected(self, tmp_path: Path) -> None:
        """Only the stage that reads the failed one is skipped; a sibling reading an
        earlier, healthy stage still runs."""
        engine = self._engine(tmp_path)
        self._tools(engine, tmp_path, crashing={"httpx"})

        result = await engine.run(
            [
                Node(tool="naabu", stage="ports"),
                Node(tool="httpx", stage="live_http"),
                Node(tool="nuclei", stage="vulns", input_from="ports"),
            ],
            seed="https://example.com",
        )

        by_stage = {n.node.stage: n for n in result.nodes}
        assert by_stage["live_http"].ok is False and by_stage["live_http"].skipped is False
        assert by_stage["vulns"].ok is True, "reads `ports`, which succeeded"

    async def test_an_empty_but_successful_source_still_runs_the_next_stage(self, tmp_path: Path) -> None:
        """Finding nothing is a result, not a failure: the next tool decides what to do
        with an empty list (it simply has no targets)."""
        engine = self._engine(tmp_path)
        silent = tmp_path / "silent.py"
        silent.write_text("pass\n", encoding="utf-8")
        probe = _stub_binary(tmp_path)
        engine.build_tool = lambda name: _StubTool(  # type: ignore[method-assign]
            engine.tool_manager.spec(name), silent if name == "naabu" else probe
        )

        result = await engine.run(
            [Node(tool="naabu", stage="ports"), Node(tool="httpx", stage="live_http")],
            seed="https://example.com",
        )

        assert result.nodes[0].ok is True and result.nodes[0].count == 0
        assert result.nodes[1].skipped is False

    async def test_the_first_stage_still_uses_the_seed(self, tmp_path: Path) -> None:
        engine = self._engine(tmp_path)
        self._tools(engine, tmp_path, crashing=set())

        result = await engine.run([Node(tool="naabu", stage="ports")], seed="seed.example.com")

        assert result.succeeded()
        # naabu's schema normalises a record to host:port; the stub prints no port.
        assert [r.target for r in result.records] == ["seed.example.com:0"]

    async def test_a_skipped_stage_reports_done_so_the_view_stays_in_sync(self, tmp_path: Path) -> None:
        engine = self._engine(tmp_path)
        self._tools(engine, tmp_path, crashing={"naabu"})
        events: list[StageEvent] = []

        async def on_stage(event: StageEvent) -> None:
            events.append(event)

        engine.set_stage_callback(on_stage)
        await engine.run(
            [Node(tool="naabu", stage="ports"), Node(tool="httpx", stage="live_http")],
            seed="https://example.com",
        )

        skipped = [e for e in events if e.stage == "live_http"]
        assert [e.kind for e in skipped] == ["done"], "a skipped stage never starts"
        assert skipped[0].result is not None and skipped[0].result.skipped is True
