"""Stopping a tool stops every process it started, not only the one cyberfw launched.

A tool is often a wrapper — a shell script, an entry point, a binary that forks
workers (gowitness and its Chrome). Whatever it left behind would go on scanning:
after a timeout, a cancellation or a failing callback, and after the tool itself
has exited, none of it may remain.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

import pytest

from cyberfw.exceptions import ExecutionError
from cyberfw.pipeline.executor import run_stage
from cyberfw.pipeline.schemas import ToolRecord


def _bare_python() -> str:
    """The interpreter itself. On Windows a venv's python.exe is a launcher that runs
    it as a child in a job of its own, and ends that child along with itself — which
    would stop the tool's tree for us and hide what this file checks."""
    return getattr(sys, "_base_executable", sys.executable)


def _wrapper(tmp_path: Path, then: str, *, delay: float = 2.0) -> tuple[list[str], Path, Path]:
    """A tool that starts a child, waits until the child runs, then does ``then``.

    The child marks ``started`` at once — with the time it would mark ``late`` —
    and ``late`` ``delay`` seconds later: longer than the tool runs, so only a
    child that outlived the tool's stop gets to."""
    started, late = tmp_path / "child_started", tmp_path / "child_late"
    child = tmp_path / "child.py"
    child.write_text(
        "import pathlib, time\n"
        f"pathlib.Path({str(started)!r}).write_text(str(time.time() + {delay}))\n"
        f"time.sleep({delay})\n"
        f"pathlib.Path({str(late)!r}).write_text('late')\n",
        encoding="utf-8",
    )
    tool = tmp_path / "tool.py"
    tool.write_text(
        "import pathlib, subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, {str(child)!r}], stdin=subprocess.DEVNULL,\n"
        "                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        f"while not pathlib.Path({str(started)!r}).exists():\n"
        "    time.sleep(0.02)\n" + then,
        encoding="utf-8",
    )
    return [_bare_python(), str(tool)], started, late


async def _assert_the_child_was_stopped(started: Path, late: Path) -> None:
    assert started.exists(), "the tool's child never ran"
    due = float(started.read_text())  # when a surviving child would mark ``late``
    await asyncio.sleep(max(0.0, due + 1.0 - time.time()))
    assert not late.exists(), "the tool's child outlived the tool"


async def test_a_timeout_stops_the_tool_s_children_too(tmp_path: Path) -> None:
    cmd, started, late = _wrapper(tmp_path, "print('ready', flush=True)\ntime.sleep(30)\n", delay=6.0)

    with pytest.raises(ExecutionError, match="timed out"):
        await run_stage(cmd, tool="x", stage="s", context=None, timeout=4)

    await _assert_the_child_was_stopped(started, late)


async def test_cancelling_stops_the_tool_s_children_too(tmp_path: Path) -> None:
    cmd, started, late = _wrapper(tmp_path, "print('ready', flush=True)\ntime.sleep(30)\n")
    ready = asyncio.Event()

    async def on_stdout_raw(line: str) -> None:
        if line == "ready":
            ready.set()

    task = asyncio.create_task(run_stage(cmd, tool="x", stage="s", context=None, on_stdout_raw=on_stdout_raw))
    await asyncio.wait_for(ready.wait(), 20)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    await _assert_the_child_was_stopped(started, late)


async def test_a_failing_callback_stops_the_tool_s_children_too(tmp_path: Path) -> None:
    cmd, started, late = _wrapper(tmp_path, "print('x.example.com', flush=True)\ntime.sleep(30)\n")

    async def boom(record: ToolRecord) -> None:
        raise RuntimeError("callback failed")

    with pytest.raises(RuntimeError, match="callback failed"):
        await run_stage(cmd, tool="x", stage="s", context=None, on_record=boom, parse=False)

    await _assert_the_child_was_stopped(started, late)


async def test_what_a_finished_tool_left_running_is_stopped(tmp_path: Path) -> None:
    cmd, started, late = _wrapper(tmp_path, "")

    assert await run_stage(cmd, tool="x", stage="s", context=None) == []

    await _assert_the_child_was_stopped(started, late)


async def test_a_tool_whose_process_cannot_be_taken_in_is_killed_not_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cyberfw.pipeline import processes

    def refuse(self: processes.ProcessGroup, pid: int) -> None:
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(processes.ProcessGroup, "adopt", refuse)
    marker = tmp_path / "ran"
    tool = tmp_path / "tool.py"
    tool.write_text(f"import pathlib, time\ntime.sleep(0.5)\npathlib.Path({str(marker)!r}).write_text('ran')\n")

    with pytest.raises(ExecutionError, match="x could not start: .*Access is denied"):
        await run_stage([sys.executable, str(tool)], tool="x", stage="s", context=None)

    await asyncio.sleep(1.5)
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="Job Objects are Windows'")
async def test_a_tool_runs_even_where_no_job_object_can_hold_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cyberfw.pipeline import processes

    def no_job() -> int:
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(processes, "_new_job", no_job)
    tool = tmp_path / "tool.py"
    tool.write_text("print('x.example.com')\n")

    records = await asyncio.wait_for(
        run_stage([sys.executable, str(tool)], tool="x", stage="s", context=None, parse=False), 30
    )

    assert [record.target for record in records] == ["x.example.com"]
