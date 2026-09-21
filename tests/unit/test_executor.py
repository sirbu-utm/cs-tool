"""Tests for the subprocess executor (JSONL streaming, error surfacing)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from cyberfw.exceptions import ExecutionError
from cyberfw.pipeline.executor import run_stage
from cyberfw.pipeline.schemas import ToolRecord


def _write_script(tmp_path: Path, body: str) -> Path:
    script = tmp_path / "fake_tool.py"
    script.write_text(body, encoding="utf-8")
    return script


class TestRunStage:
    async def test_parses_jsonl_stdout(self, tmp_path: Path) -> None:
        script = _write_script(
            tmp_path,
            'import json, sys\n'
            'for i in range(3):\n'
            '    sys.stdout.write(json.dumps({"host": f"s{i}.example.com"}) + "\\n")\n',
        )
        records = await run_stage(
            [sys.executable, str(script)], tool="subfinder", stage="sub", context=None
        )
        assert len(records) == 3
        assert records[0].target == "s0.example.com"
        assert records[0].kind == "host"

    async def test_ignores_non_jsonl_lines(self, tmp_path: Path) -> None:
        script = _write_script(
            tmp_path,
            'import sys\n'
            'sys.stdout.write("not json\\n")\n'
            'sys.stdout.write("{\\"host\\": \\"ok.example.com\\"}\\n")\n',
        )
        records = await run_stage(
            [sys.executable, str(script)], tool="subfinder", stage="sub", context=None
        )
        # only the valid line produces a record
        assert len(records) == 1
        assert records[0].target == "ok.example.com"

    async def test_uses_tool_parser_for_non_json_output(self, tmp_path: Path) -> None:
        script = _write_script(
            tmp_path,
            'import sys\n'
            'sys.stdout.write("Open 192.0.2.10:443\\n")\n',
        )

        def parse_line(line: str, lineno: int) -> ToolRecord:
            return ToolRecord(tool="custom", line_number=lineno, raw=line, target=line)

        records = await run_stage(
            [sys.executable, str(script)],
            tool="custom",
            stage="scan",
            context=None,
            parse_line=parse_line,
        )

        assert records[0].target == "Open 192.0.2.10:443"

    async def test_no_parse_keeps_every_stdout_line(self, tmp_path: Path) -> None:
        script = _write_script(
            tmp_path,
            'import sys\n'
            'sys.stdout.write("banner\\n")\n'
            'sys.stdout.write("  padded  \\n")\n'
            'sys.stdout.write("\\n")\n'
            'sys.stdout.write("{not-json}\\n")\n',
        )

        records = await run_stage(
            [sys.executable, str(script)],
            tool="custom",
            stage="raw",
            context=None,
            parse=False,
        )

        assert [record.target for record in records] == ["banner", "  padded  ", "", "{not-json}"]
        assert all(record.kind == "raw" for record in records)

    async def test_nonzero_exit_raises_execution_error(self, tmp_path: Path) -> None:
        script = _write_script(tmp_path, "import sys\nsys.exit(3)\n")
        with pytest.raises(ExecutionError) as exc_info:
            await run_stage(
                [sys.executable, str(script)], tool="subfinder", stage="sub", context=None
            )
        assert exc_info.value.exit_code == 3

    async def test_missing_binary_raises_execution_error(self, tmp_path: Path) -> None:
        with pytest.raises(ExecutionError, match="could not start"):
            await run_stage(
                [str(tmp_path / "does-not-exist")], tool="subfinder", stage="sub", context=None
            )

    async def test_on_stderr_receives_every_line_live(self, tmp_path: Path) -> None:
        script = _write_script(
            tmp_path,
            'import sys\n'
            'sys.stderr.write("connecting...\\n")\n'
            'sys.stderr.write("rate limited, retrying\\n")\n',
        )
        seen: list[str] = []

        async def on_stderr(line: str) -> None:
            seen.append(line)

        await run_stage(
            [sys.executable, str(script)],
            tool="subfinder",
            stage="sub",
            context=None,
            on_stderr=on_stderr,
        )

        assert seen == ["connecting...", "rate limited, retrying"]

    async def test_parse_buffer_parses_whole_document_after_exit(self, tmp_path: Path) -> None:
        """Whole-document tools (gitleaks): stdout is collected and parsed once."""
        script = _write_script(
            tmp_path,
            'import sys\n'
            'sys.stdout.write("[\\n")\n'
            'sys.stdout.write(\'  {"File": "/a"},\\n\')\n'
            'sys.stdout.write(\'  {"File": "/b"}\\n\')\n'
            'sys.stdout.write("]\\n")\n',
        )
        import json as _json

        def parse_buffer(text: str) -> list[ToolRecord]:
            return [
                ToolRecord(tool="gitleaks", raw=_json.dumps(item), target=item["File"], kind="secret")
                for item in _json.loads(text)
            ]

        records = await run_stage(
            [sys.executable, str(script)],
            tool="gitleaks",
            stage="secrets",
            context=None,
            parse_buffer=parse_buffer,
        )

        assert [r.target for r in records] == ["/a", "/b"]

    async def test_on_stdout_raw_sees_every_line_while_parsing(self, tmp_path: Path) -> None:
        """Verbose pipeline view: raw stdout streams even for non-parseable lines,
        yet valid JSON lines are still parsed into records for threading."""
        script = _write_script(
            tmp_path,
            'import json, sys\n'
            'sys.stdout.write(json.dumps({"host": "a.com"}) + "\\n")\n'
            'sys.stdout.write("progress 50% not-json\\n")\n'
            'sys.stdout.write(json.dumps({"host": "b.com"}) + "\\n")\n',
        )
        raw_lines: list[str] = []

        async def on_stdout_raw(line: str) -> None:
            raw_lines.append(line)

        records = await run_stage(
            [sys.executable, str(script)],
            tool="subfinder",
            stage="sub",
            context=None,
            on_stdout_raw=on_stdout_raw,
        )

        # every line reached the raw view, including the non-JSON chatter
        assert raw_lines == [
            '{"host": "a.com"}',
            "progress 50% not-json",
            '{"host": "b.com"}',
        ]
        # parsing still produced records only for the valid JSON lines
        assert [r.target for r in records] == ["a.com", "b.com"]

    async def test_streams_into_context_store(self, tmp_path: Path) -> None:
        from cyberfw.pipeline.context import SessionContext

        script = _write_script(
            tmp_path,
            'import json, sys\n'
            'sys.stdout.write(json.dumps({"host": "ctx.example.com"}) + "\\n")\n',
        )
        context = SessionContext(root_dir=tmp_path, session_id="sess")
        await run_stage(
            [sys.executable, str(script)], tool="subfinder", stage="sub", context=context
        )
        targets = context.targets("sub")
        assert targets == ["ctx.example.com"]


@pytest.mark.parametrize("exit_code", [1, 255])
async def test_error_carries_exit_code(exit_code: int, tmp_path: Path) -> None:
    script = _write_script(tmp_path, f"import sys\nsys.exit({exit_code})\n")
    with pytest.raises(ExecutionError) as exc_info:
        await run_stage([sys.executable, str(script)], tool="x", stage="s", context=None)
    assert exc_info.value.exit_code == exit_code


def test_close_transport_closes_pipe_transport() -> None:
    """The child's pipe transport is closed so it doesn't leak to GC/shutdown.

    On Windows the ProactorEventLoop otherwise emits a noisy 'unclosed transport'
    ResourceWarning from the transport's __del__ after the loop is gone.
    """
    from cyberfw.pipeline.executor import _close_transport

    class _FakeTransport:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class _FakeProc:
        def __init__(self) -> None:
            self._transport = _FakeTransport()

    proc = _FakeProc()
    _close_transport(proc)  # type: ignore[arg-type]
    assert proc._transport.closed is True

    # Missing/None transport and a raising close() must never propagate.
    _close_transport(object())  # type: ignore[arg-type]

    class _Boom:
        _transport = type("T", (), {"close": lambda self: (_ for _ in ()).throw(OSError("x"))})()

    _close_transport(_Boom())  # type: ignore[arg-type]
