"""Tests for the subprocess executor (JSONL streaming, error surfacing)."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path, PureWindowsPath

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

    async def test_unparsed_lines_are_summarised_as_one_warning(self, tmp_path: Path, caplog) -> None:
        """A schema drift must not silently swallow findings: surface a count at WARNING."""
        script = _write_script(
            tmp_path,
            "import json\n"
            "for i in range(3): print('garbage', i)\n"
            "print(json.dumps({'host': 'ok.example.com'}))\n",
        )
        with caplog.at_level("WARNING", logger="cyberfw.executor"):
            records = await run_stage(
                [sys.executable, str(script)], tool="subfinder", stage="sub", context=None
            )
        assert len(records) == 1
        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert len(warnings) == 1
        assert "3" in warnings[0].getMessage() and "subfinder" in warnings[0].getMessage()

    async def test_jsonl_line_larger_than_default_reader_limit_is_parsed(self, tmp_path: Path) -> None:
        """A single finding longer than asyncio's 64 KiB default must not fail the stage.

        nuclei -jsonl can emit one finding well past 64 KiB (large extracted /
        matched content); the reader used to raise LimitOverrunError ("Separator
        is not found, and chunk exceed the limit") and kill the whole stage.
        """
        script = _write_script(
            tmp_path,
            "import json, sys\n"
            "big = 'x' * 200_000\n"  # ~200 KiB on one line, far over the 64 KiB default
            "sys.stdout.write(json.dumps({'host': 'big.example.com', 'source': big}) + '\\n')\n",
        )
        records = await run_stage(
            [sys.executable, str(script)], tool="subfinder", stage="sub", context=None
        )
        assert len(records) == 1
        assert records[0].target == "big.example.com"

    async def test_line_over_stream_limit_is_dropped_not_fatal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Even a line past our raised limit degrades to a dropped line, not a dead stage."""
        import cyberfw.pipeline.executor as executor

        monkeypatch.setattr(executor, "_STREAM_LIMIT", 2048)  # tiny, to exercise the overrun path
        script = _write_script(
            tmp_path,
            "import json, sys\n"
            "sys.stdout.write('y' * 10_000 + '\\n')\n"  # one monster line, no valid JSON
            "sys.stdout.write(json.dumps({'host': 'ok.example.com'}) + '\\n')\n",
        )
        records = await run_stage(
            [sys.executable, str(script)], tool="subfinder", stage="sub", context=None
        )
        # The oversized line is dropped; the following valid finding still lands.
        assert [r.target for r in records] == ["ok.example.com"]

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
        with SessionContext(root_dir=tmp_path, session_id="sess") as context:
            await run_stage(
                [sys.executable, str(script)], tool="subfinder", stage="sub", context=context
            )
            targets = context.targets("sub")
        assert targets == ["ctx.example.com"]


@pytest.mark.parametrize("transport_cleanup", ["real", "disabled"])
async def test_child_is_killed_when_a_callback_raises_mid_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, transport_cleanup: str
) -> None:
    """A failing on_record hook must not leave the scanner running in the background.

    The child prints one record, then sleeps and drops a marker file; if it survived
    the executor's cleanup the marker would appear. Closing the pipe transport also
    kills the child, but that goes through a private attribute, so the kill must not
    depend on it: the "disabled" variant turns transport cleanup into a no-op.
    """
    if transport_cleanup == "disabled":
        monkeypatch.setattr("cyberfw.pipeline.executor._close_transport", lambda proc: None)
    marker = tmp_path / "still_alive"
    script = _write_script(
        tmp_path,
        "import json, sys, time, pathlib\n"
        "print(json.dumps({'host': 'x.example.com'}), flush=True)\n"
        "time.sleep(0.5)\n"
        f"pathlib.Path({str(marker)!r}).write_text('alive')\n",
    )

    async def boom(record: ToolRecord) -> None:
        raise RuntimeError("callback failed")

    with pytest.raises(RuntimeError, match="callback failed"):
        await run_stage([sys.executable, str(script)], tool="subfinder", stage="s", context=None, on_record=boom)
    await asyncio.sleep(1.0)
    assert not marker.exists(), "child process outlived run_stage"


class TestFindBash:
    """On Windows ``bash.exe`` in System32 is the WSL launcher: it needs a distro, boots
    for seconds and mounts drives under /mnt. Git Bash must win whenever it exists."""

    @staticmethod
    def _bash_in(directory: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        exe = directory / "bash.exe"
        exe.write_bytes(b"MZ")
        return exe

    def test_prefers_git_bash_later_on_path_over_system32_shim(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cyberfw.pipeline.executor import _find_bash

        wsl = self._bash_in(tmp_path / "Windows" / "System32")
        git = self._bash_in(tmp_path / "Git" / "usr" / "bin")
        monkeypatch.setenv("PATH", os.pathsep.join([str(wsl.parent), str(git.parent)]))
        monkeypatch.setenv("ProgramFiles", str(tmp_path / "nowhere"))
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "nowhere"))

        assert _find_bash() == str(git)

    def test_falls_back_to_git_default_install_dir_when_not_on_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cyberfw.pipeline.executor import _find_bash

        wsl = self._bash_in(tmp_path / "Windows" / "System32")
        git = self._bash_in(tmp_path / "Program Files" / "Git" / "bin")
        monkeypatch.setenv("PATH", str(wsl.parent))
        monkeypatch.setenv("ProgramFiles", str(tmp_path / "Program Files"))
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "nowhere"))

        assert _find_bash() == str(git)

    def test_uses_wsl_shim_only_when_nothing_else_exists(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cyberfw.pipeline.executor import _find_bash

        wsl = self._bash_in(tmp_path / "Windows" / "System32")
        monkeypatch.setenv("PATH", str(wsl.parent))
        monkeypatch.setenv("ProgramFiles", str(tmp_path / "nowhere"))
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "nowhere"))

        assert _find_bash() == str(wsl)

    def test_none_when_no_bash_at_all(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyberfw.pipeline.executor import _find_bash

        monkeypatch.setenv("PATH", str(tmp_path / "empty"))
        monkeypatch.setenv("ProgramFiles", str(tmp_path / "nowhere"))
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "nowhere"))

        assert _find_bash() is None


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


class TestCancellation:
    """Ctrl+C / task cancellation must stop the child promptly *and* cleanly."""

    @staticmethod
    def _long_running_child(tmp_path: Path, marker: Path) -> Path:
        # Exits cleanly (dropping ``marker``) on SIGTERM; otherwise sleeps far longer
        # than any test would wait.
        return _write_script(
            tmp_path,
            "import pathlib, signal, sys, time\n"
            "def bye(signum, frame):\n"
            f"    pathlib.Path({str(marker)!r}).write_text('terminated cleanly')\n"
            "    sys.exit(0)\n"
            "signal.signal(signal.SIGTERM, bye)\n"
            "print('ready', flush=True)\n"
            "time.sleep(30)\n",
        )

    @staticmethod
    async def _start_and_cancel(script: Path) -> None:
        ready = asyncio.Event()

        async def on_stdout_raw(line: str) -> None:
            if line == "ready":
                ready.set()

        task = asyncio.create_task(
            run_stage([sys.executable, str(script)], tool="x", stage="s", context=None, on_stdout_raw=on_stdout_raw)
        )
        await asyncio.wait_for(ready.wait(), 10)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    async def test_cancellation_leaves_no_background_task_behind(self, tmp_path: Path) -> None:
        """A fire-and-forget "kill later" task used to outlive run_stage and get destroyed
        with the event loop; cleanup must finish before the cancellation propagates."""
        marker = tmp_path / "terminated-cleanly"
        await self._start_and_cancel(self._long_running_child(tmp_path, marker))

        stray = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        assert stray == []

    @pytest.mark.skipif(os.name == "nt", reason="TerminateProcess has no graceful form on Windows")
    async def test_cancellation_gives_the_child_a_chance_to_exit_cleanly(self, tmp_path: Path) -> None:
        """SIGTERM first, SIGKILL only if the child ignores it: a scanner that flushes
        its output on SIGTERM must get to do so."""
        marker = tmp_path / "terminated-cleanly"
        await self._start_and_cancel(self._long_running_child(tmp_path, marker))

        assert marker.read_text() == "terminated cleanly"


class TestTimeout:
    async def test_child_exceeding_timeout_is_killed_and_reported(self, tmp_path: Path) -> None:
        marker = tmp_path / "still_alive"
        script = _write_script(
            tmp_path,
            "import pathlib, sys, time\n"
            "sys.stderr.write('resolving example.com\\n'); sys.stderr.flush()\n"
            "time.sleep(1.0)\n"
            f"pathlib.Path({str(marker)!r}).write_text('alive')\n",
        )

        with pytest.raises(ExecutionError, match="timed out after 0.3s") as exc_info:
            await run_stage([sys.executable, str(script)], tool="httpx", stage="s", context=None, timeout=0.3)

        # Diagnostics gathered before the deadline survive into the error.
        assert exc_info.value.stderr_tail == ["resolving example.com"]
        await asyncio.sleep(1.2)
        assert not marker.exists(), "child process outlived the timeout"

    async def test_records_streamed_before_the_deadline_reach_the_store(self, tmp_path: Path) -> None:
        from cyberfw.pipeline.context import SessionContext

        script = _write_script(
            tmp_path,
            "import json, time\n"
            "print(json.dumps({'host': 'early.example.com'}), flush=True)\n"
            "time.sleep(30)\n",
        )
        with SessionContext(root_dir=tmp_path, session_id="sess") as context:
            with pytest.raises(ExecutionError, match="timed out"):
                await run_stage(
                    [sys.executable, str(script)], tool="subfinder", stage="sub", context=context, timeout=0.5
                )
            assert context.targets("sub") == ["early.example.com"]

    async def test_no_timeout_by_default(self, tmp_path: Path) -> None:
        script = _write_script(tmp_path, "import time\ntime.sleep(0.6)\n")
        assert await run_stage([sys.executable, str(script)], tool="x", stage="s", context=None) == []


class TestCrashDescription:
    @pytest.mark.parametrize(
        ("exit_code", "expected"),
        [
            (3, "exited with code 3"),
            (-11, "crashed with SIGSEGV"),
            (-9, "signal 9"),
            (0xC0000005, "access violation"),
        ],
    )
    def test_describe_crash(self, exit_code: int, expected: str) -> None:
        from cyberfw.pipeline.executor import _describe_crash

        assert expected in _describe_crash(exit_code)

    @pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
    async def test_signal_death_is_named_in_the_error(self, tmp_path: Path) -> None:
        script = _write_script(tmp_path, "import os, signal\nos.kill(os.getpid(), signal.SIGSEGV)\n")
        with pytest.raises(ExecutionError, match="crashed with SIGSEGV") as exc_info:
            await run_stage([sys.executable, str(script)], tool="nuclei", stage="s", context=None)
        assert exc_info.value.exit_code == -11

    @pytest.mark.skipif(os.name != "nt", reason="NTSTATUS exit codes")
    async def test_access_violation_is_named_in_the_error(self, tmp_path: Path) -> None:
        # os._exit takes a C int: pass STATUS_ACCESS_VIOLATION in its signed form.
        script = _write_script(tmp_path, "import os\nos._exit(0xC0000005 - 2**32)\n")
        with pytest.raises(ExecutionError, match="access violation"):
            await run_stage([sys.executable, str(script)], tool="nuclei", stage="s", context=None)


class TestPosixPathConversion:
    """Git for Windows keeps bash in two places and cygpath in only one of them:
    ``Git\\bin\\bash.exe`` has no cygpath sibling, ``Git\\usr\\bin`` does. Guessing the
    WSL layout (/mnt/c/...) when cygpath is not found next to bash made Git Bash
    answer "No such file or directory" and every fake-tool test exited 127 —
    but only when PATH offered bin before usr/bin, which is how PowerShell and
    the GitHub Windows runner see it.
    """

    @staticmethod
    def _git_layout(tmp_path: Path, *, with_cygpath: bool = True) -> Path:
        """A Git-for-Windows tree: bin/bash.exe, and cygpath over in usr/bin."""
        root = tmp_path / "Git"
        (root / "bin").mkdir(parents=True)
        (root / "usr" / "bin").mkdir(parents=True)
        bash = root / "bin" / "bash.exe"
        bash.write_bytes(b"MZ")
        if with_cygpath:
            (root / "usr" / "bin" / "cygpath.exe").write_bytes(b"MZ")
        return bash

    def test_msys_layout_is_used_even_when_cygpath_is_not_a_sibling(self, tmp_path: Path) -> None:
        from cyberfw.pipeline.executor import _to_posix_path

        bash = self._git_layout(tmp_path, with_cygpath=False)

        # PureWindowsPath so the conversion is exercised on every platform:
        # to Path() on Linux a Windows path is just an odd file name.
        converted = _to_posix_path(PureWindowsPath(r"C:\tools_bin\subfinder"), str(bash))

        assert converted == "/c/tools_bin/subfinder"
        assert "/mnt/" not in converted, "that is the WSL layout, not Git Bash's"

    def test_the_wsl_shim_still_gets_the_wsl_layout(self, tmp_path: Path) -> None:
        from cyberfw.pipeline.executor import _to_posix_path

        shim = tmp_path / "Windows" / "System32" / "bash.exe"
        shim.parent.mkdir(parents=True)
        shim.write_bytes(b"MZ")

        assert (
            _to_posix_path(PureWindowsPath(r"C:\tools_bin\subfinder"), str(shim))
            == "/mnt/c/tools_bin/subfinder"
        )

    def test_cygpath_next_to_bash_is_still_preferred(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyberfw.pipeline import executor

        bash = tmp_path / "bin" / "bash.exe"
        bash.parent.mkdir(parents=True)
        bash.write_bytes(b"MZ")
        (tmp_path / "bin" / "cygpath.exe").write_bytes(b"MZ")
        asked: list[str] = []

        class _Result:
            returncode = 0
            stdout = "/from/cygpath\n"

        def fake_run(cmd, **_kwargs):
            asked.append(cmd[0])
            return _Result()

        monkeypatch.setattr(executor.subprocess, "run", fake_run)

        assert executor._to_posix_path(Path(r"C:\x"), str(bash)) == "/from/cygpath"
        assert asked and asked[0].endswith("cygpath.exe")

    def test_cygpath_found_in_the_sibling_usr_bin(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyberfw.pipeline import executor

        bash = self._git_layout(tmp_path)
        used: list[str] = []

        class _Result:
            returncode = 0
            stdout = "/c/x\n"

        def fake_run(cmd, **_kwargs):
            used.append(cmd[0])
            return _Result()

        monkeypatch.setattr(executor.subprocess, "run", fake_run)
        executor._to_posix_path(Path(r"C:\x"), str(bash))

        assert used and used[0].endswith(str(Path("usr") / "bin" / "cygpath.exe"))


@pytest.mark.skipif(os.name != "nt", reason="Windows shebang handling")
async def test_a_shebang_tool_runs_under_git_bin_bash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """End to end with the bash PowerShell and the CI runner pick first: the script
    must actually execute, not exit 127 on a path it cannot read."""
    from cyberfw.pipeline import executor

    git_bin_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
    if not git_bin_bash.is_file():
        pytest.skip("Git for Windows is not installed in its default location")
    monkeypatch.setattr(executor, "_find_bash", lambda: str(git_bin_bash))
    script = tmp_path / "faketool"
    script.write_text('#!/usr/bin/env bash\necho \'{"host": "a.example.com"}\'\n', encoding="utf-8")

    records = await run_stage([str(script)], tool="subfinder", stage="s", context=None)

    assert [r.target for r in records] == ["a.example.com"]
