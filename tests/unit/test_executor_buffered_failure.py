"""A failing buffered tool keeps a usable report without hiding its failure."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from cyberfw.config import Settings
from cyberfw.exceptions import ExecutionError
from cyberfw.manager import ToolManager
from cyberfw.manager.registry import ToolRegistry, ToolSpec
from cyberfw.pipeline.context import SessionContext
from cyberfw.pipeline.engine import Node, PipelineEngine, PipelineResult
from cyberfw.pipeline.executor import LOG, run_stage
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.plugin import ToolContext
from cyberfw.report.json_report import report_payload
from cyberfw.tools.gitleaks import GitleaksTool


def _command(stdout: str, *, exit_code: int = 7, hang: bool = False) -> list[str]:
    code = (
        "import sys, time\n"
        f"sys.stdout.write({stdout!r}); sys.stdout.flush()\n"
        "sys.stderr.write('scanner diagnostic\\n'); sys.stderr.flush()\n"
    )
    code += "time.sleep(30)\n" if hang else f"raise SystemExit({exit_code})\n"
    # Avoid a Windows venv launcher holding pipes or outliving the timed-out
    # process fixture. The base interpreter runs these stdlib-only scripts.
    return [getattr(sys, "_base_executable", sys.executable), "-c", code]


def _parse(text: str) -> list[ToolRecord]:
    return [ToolRecord(tool="fixture", target=item["target"], kind="host") for item in json.loads(text)]


async def test_failed_buffered_report_is_kept_once_in_the_error_callback_and_store(tmp_path: Path) -> None:
    seen: list[ToolRecord] = []

    async def on_record(record: ToolRecord) -> None:
        seen.append(record)

    with SessionContext(tmp_path, "session") as context:
        with pytest.raises(ExecutionError, match="exited with code 7") as error:
            await run_stage(
                _command('[{"target":"first.example.com"},{"target":"second.example.com"}]\n'),
                tool="fixture", stage="scan", context=context, parse_buffer=_parse, on_record=on_record,
            )
        assert context.targets("scan") == ["first.example.com", "second.example.com"]
        assert len(context.records("scan")) == 2

    assert error.value.exit_code == 7
    assert error.value.stderr_tail == ["scanner diagnostic"]
    assert seen == error.value.partial_records
    assert [record.target for record in seen] == ["first.example.com", "second.example.com"]


async def test_timeout_keeps_a_complete_report_received_before_the_deadline() -> None:
    with pytest.raises(ExecutionError, match="timed out") as error:
        await run_stage(
            _command('[{"target":"early.example.com"}]\n', hang=True),
            tool="fixture", stage="scan", context=None, parse_buffer=_parse, timeout=1,
        )

    assert [record.target for record in error.value.partial_records] == ["early.example.com"]
    assert error.value.stderr_tail == ["scanner diagnostic"]


@pytest.mark.parametrize("stdout", ['[{"target":', "unexpected output\n"])
async def test_bad_buffer_never_replaces_the_original_exit_error(
    stdout: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    warnings: list[str] = []
    monkeypatch.setattr(LOG, "warning", lambda fmt, *args: warnings.append(fmt % args))

    with pytest.raises(ExecutionError, match="exited with code 7") as error:
        await run_stage(_command(stdout), tool="fixture", stage="scan", context=None, parse_buffer=_parse)

    assert error.value.exit_code == 7
    assert error.value.stderr_tail == ["scanner diagnostic"]
    assert error.value.partial_records == []
    assert len(warnings) == 1
    assert "buffer" in warnings[0].lower()


async def test_a_broken_plugin_parser_preserves_the_original_process_error(monkeypatch: pytest.MonkeyPatch) -> None:
    warnings: list[str] = []
    monkeypatch.setattr(LOG, "warning", lambda fmt, *args: warnings.append(fmt % args))

    def broken(_text: str) -> list[ToolRecord]:
        raise RuntimeError("plugin parser failed")

    with pytest.raises(ExecutionError, match="exited with code 7"):
        await run_stage(_command("[]\n"), tool="fixture", stage="scan", context=None, parse_buffer=broken)

    assert len(warnings) == 1
    assert "plugin parser failed" in warnings[0]


async def test_successful_exit_with_a_bad_buffer_still_raises_the_parse_error() -> None:
    with pytest.raises(json.JSONDecodeError):
        await run_stage(_command("broken", exit_code=0), tool="fixture", stage="scan", context=None, parse_buffer=_parse)


async def test_raw_mode_never_invokes_the_buffer_parser_even_on_failure() -> None:
    def forbidden(_text: str) -> list[ToolRecord]:
        pytest.fail("--no-parse must not invoke the buffered parser")

    with pytest.raises(ExecutionError) as error:
        await run_stage(
            _command("raw output\n"), tool="fixture", stage="scan", context=None,
            parse_buffer=forbidden, parse=False,
        )

    assert [(record.kind, record.raw) for record in error.value.partial_records] == [("raw", "raw output")]


async def test_record_callback_errors_are_not_misreported_as_bad_buffered_output() -> None:
    async def broken_callback(_record: ToolRecord) -> None:
        raise RuntimeError("observer failed")

    with pytest.raises(RuntimeError, match="observer failed"):
        await run_stage(
            _command('[{"target":"example.com"}]\n'), tool="fixture", stage="scan", context=None,
            parse_buffer=_parse, on_record=broken_callback,
        )


async def test_pipeline_reports_a_failed_buffered_stage_with_its_findings(tmp_path: Path) -> None:
    class FixtureTool(GitleaksTool):
        def build_cmd(self, ctx: ToolContext) -> list[str]:
            return _command('[{"RuleID":"demo-rule","File":"repo/settings.txt"}]\n')

    spec = ToolSpec(name="gitleaks", source="local", path=sys.executable)
    settings = Settings(root_dir=tmp_path)
    manager = ToolManager(settings, ToolRegistry({"gitleaks": spec}))
    with SessionContext(tmp_path, "session") as context:
        engine = PipelineEngine(settings, manager, context=context)
        engine.build_tool = lambda _name: FixtureTool(spec, Path(sys.executable))  # type: ignore[method-assign]

        node, records = await engine.run_single(Node(tool="gitleaks", stage="secrets"), ToolContext(target=str(tmp_path)))

        assert not node.ok and node.count == 1
        assert "exited with code 7" in (node.error or "")
        assert context.targets("secrets") == ["repo/settings.txt"]
        report = report_payload(PipelineResult(nodes=[node], records=records))
        assert report["ok"] is False
        assert report["total_records"] == 1
        assert report["records"][0]["kind"] == "secret"
