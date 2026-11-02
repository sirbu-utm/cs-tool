"""Stopping a tool stops every process it started, not only the one cyberfw launched.

A tool is often a wrapper — a shell script, an entry point, a binary that forks
workers (gowitness and its Chrome). Whatever it left behind would go on scanning:
after a timeout, a cancellation or a failing callback, and after the tool itself
has exited, none of it may remain.
"""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable
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


async def test_a_child_left_holding_the_tool_s_output_is_stopped_once_the_tool_has_exited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tool's output stays open while a process it left behind holds it: once the
    tool has exited, that process gets a grace period, then goes with the group — the
    stage does not wait for it, however long it would run."""
    monkeypatch.setattr("cyberfw.pipeline.executor._LEFTOVER_GRACE", 0.5, raising=False)
    started, late = tmp_path / "child_started", tmp_path / "child_late"
    child = tmp_path / "child.py"
    child.write_text(
        "import pathlib, time\n"
        "print('from the child', flush=True)\n"
        f"pathlib.Path({str(started)!r}).write_text(str(time.time() + 3.0))\n"
        "time.sleep(3.0)\n"
        f"pathlib.Path({str(late)!r}).write_text('late')\n",
        encoding="utf-8",
    )
    tool = tmp_path / "tool.py"
    tool.write_text(
        "import pathlib, subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, {str(child)!r}], stdout=sys.stdout)  # the tool's own output\n"
        f"while not pathlib.Path({str(started)!r}).exists():\n"
        "    time.sleep(0.02)\n",
        encoding="utf-8",
    )

    records = await asyncio.wait_for(
        run_stage([_bare_python(), str(tool)], tool="x", stage="s", context=None, parse=False), 30
    )

    assert [record.raw for record in records] == ["from the child"]
    await _assert_the_child_was_stopped(started, late)


async def test_stopping_a_tool_in_a_group_signals_the_group_and_not_the_tool_again() -> None:
    """A tool that flushes on SIGTERM and quits at once on a second one must get one."""
    from cyberfw.pipeline.executor import _stop

    sent: list[str] = []

    class Group:
        def terminate(self) -> bool:
            sent.append("group: SIGTERM")
            return True

        def kill(self) -> bool:
            sent.append("group: SIGKILL")
            return True

    class Tool:
        returncode: int | None = None

        def terminate(self) -> None:
            sent.append("tool: SIGTERM")

        async def wait(self) -> int:
            self.returncode = -15
            return -15

    await _stop(Tool(), Group())  # type: ignore[arg-type]

    assert sent == ["group: SIGTERM", "group: SIGKILL"]


# -- signals that would end cyberfw (POSIX) ----------------------------------------------

REPO = Path(__file__).resolve().parents[2]

#: A stand-in for cyberfw: one tool run by run_stage, the way the engine runs it.
_CYBERFW = (
    "import asyncio, sys\n"
    "from cyberfw.pipeline.executor import run_stage\n"
    "from cyberfw.pipeline.processes import stopping_tools_on_signals\n"
    "async def main():\n"
    "    with stopping_tools_on_signals():\n"
    "        await run_stage(sys.argv[1:], tool='x', stage='s', context=None)\n"
    "asyncio.run(main())\n"
)


def _cyberfw(cmd: list[str]) -> subprocess.Popen[bytes]:
    """cyberfw running ``cmd`` as its one tool, in a process group of its own — as a
    shell job is — so a signal reaches cyberfw's group the way a terminal sends it."""
    return subprocess.Popen([sys.executable, "-c", _CYBERFW, *cmd], cwd=REPO, process_group=0)


async def _until(condition: Callable[[], bool], cyberfw: subprocess.Popen[bytes]) -> None:
    for _ in range(400):
        if condition():
            return
        assert cyberfw.poll() is None, "cyberfw ended before its tool ran"
        await asyncio.sleep(0.05)
    raise AssertionError("the tool never ran")


@pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
@pytest.mark.parametrize("name", ["SIGTERM", "SIGHUP"])  # SIGQUIT takes the same path, and dumps core
async def test_a_signal_that_ends_cyberfw_stops_its_tools_first(tmp_path: Path, name: str) -> None:
    """A tool runs in a session of its own, so a closed terminal, ``kill`` or
    ``timeout`` reaches cyberfw alone: it must stop its tools before it goes."""
    signum = getattr(signal, name)
    cmd, started, late = _wrapper(tmp_path, "time.sleep(30)\n", delay=6.0)
    cyberfw = _cyberfw(cmd)
    try:
        await _until(started.exists, cyberfw)
        os.killpg(cyberfw.pid, signum)
        returncode = await asyncio.to_thread(cyberfw.wait, 20)
    finally:
        if cyberfw.poll() is None:
            cyberfw.kill()

    assert returncode == -signum  # cyberfw still ends by the signal — after its tools
    await _assert_the_child_was_stopped(started, late)


@pytest.mark.skipif(os.name == "nt", reason="POSIX job control")
async def test_ctrl_z_pauses_the_tools_with_cyberfw_and_fg_resumes_them(tmp_path: Path) -> None:
    ticks = tmp_path / "ticks"
    tool = tmp_path / "tool.py"
    tool.write_text(
        "import time\n"
        "while True:\n"
        f"    with open({str(ticks)!r}, 'a') as out:\n"
        "        out.write('.')\n"
        "    time.sleep(0.05)\n",
        encoding="utf-8",
    )
    cyberfw = _cyberfw([_bare_python(), str(tool)])

    async def ticks_after(seconds: float) -> int:
        await asyncio.sleep(seconds)
        return ticks.stat().st_size

    try:
        await _until(ticks.exists, cyberfw)
        os.killpg(cyberfw.pid, signal.SIGTSTP)
        paused = await ticks_after(0.5)
        assert await ticks_after(1.0) == paused, "the tool went on while cyberfw was stopped"
        os.killpg(cyberfw.pid, signal.SIGCONT)
        assert await ticks_after(1.0) > paused, "resuming cyberfw did not resume its tool"
        os.killpg(cyberfw.pid, signal.SIGTERM)
        assert await asyncio.to_thread(cyberfw.wait, 20) == -signal.SIGTERM
        stopped = await ticks_after(0.3)
        assert await ticks_after(0.5) == stopped, "the tool outlived cyberfw"
    finally:
        if cyberfw.poll() is None:
            cyberfw.kill()


@pytest.mark.skipif(os.name == "nt", reason="POSIX job control")
async def test_a_tool_stopped_and_continued_does_not_freeze_cyberfw(tmp_path: Path) -> None:
    # macOS's waitid() returns for a child that is only stopped; asyncio 3.14's watcher
    # took that for an exit, and its loop then sat in waitpid() until the tool ended.
    pid_file, ticks = tmp_path / "pid", tmp_path / "ticks"
    tool = tmp_path / "tool.py"
    tool.write_text(
        "import os, time\n"
        f"open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
        "while True:\n"
        f"    with open({str(ticks)!r}, 'a') as out:\n"
        "        out.write('.')\n"
        "    time.sleep(0.05)\n",
        encoding="utf-8",
    )
    cyberfw = _cyberfw([_bare_python(), str(tool)])
    try:
        await _until(ticks.exists, cyberfw)
        tool_pid = int(pid_file.read_text(encoding="utf-8"))
        os.kill(tool_pid, signal.SIGSTOP)  # someone else pauses the tool, cyberfw runs on
        await asyncio.sleep(1.0)
        os.kill(tool_pid, signal.SIGCONT)
        await asyncio.sleep(0.5)
        os.killpg(cyberfw.pid, signal.SIGTERM)
        assert await asyncio.to_thread(cyberfw.wait, 20) == -signal.SIGTERM
    finally:
        if cyberfw.poll() is None:
            cyberfw.kill()


@pytest.mark.skipif(os.name == "nt", reason="POSIX job control")
async def test_cyberfws_child_watcher_waits_for_an_exit_not_a_stop() -> None:
    from cyberfw.pipeline import processes

    child = subprocess.Popen([_bare_python(), "-c", "import time; time.sleep(1.5)"])
    loop = asyncio.get_running_loop()
    ended: asyncio.Future[tuple[int, int]] = loop.create_future()
    processes._WaitpidChildWatcher().add_child_handler(child.pid, lambda pid, code: ended.set_result((pid, code)))
    try:
        os.kill(child.pid, signal.SIGSTOP)
        await asyncio.sleep(0.5)
        assert not ended.done(), "a stopped child was taken for an exited one"
        os.kill(child.pid, signal.SIGCONT)
        assert await asyncio.wait_for(ended, 10) == (child.pid, 0)
    finally:
        if ended.done():
            child.returncode = 0  # the watcher reaped it: Popen would warn it still runs
        else:
            child.kill()
            child.wait()


@pytest.mark.skipif(os.name == "nt", reason="POSIX event loops")
@pytest.mark.parametrize("affected", [True, False])
def test_where_waitid_takes_a_stop_for_an_exit_asyncios_watcher_gives_way(
    monkeypatch: pytest.MonkeyPatch, affected: bool
) -> None:
    from asyncio import unix_events

    from cyberfw.pipeline import processes

    threaded = getattr(unix_events, "_ThreadedChildWatcher", None)
    if threaded is None:
        pytest.skip("this asyncio has no _ThreadedChildWatcher of its own")

    class Loop:
        _watcher = threaded()

    loop = Loop()
    monkeypatch.setattr(processes, "_WAITID_TAKES_A_STOP_FOR_AN_EXIT", affected)

    processes.watch_children_with_waitpid(loop)  # type: ignore[arg-type]
    processes.watch_children_with_waitpid(loop)  # type: ignore[arg-type]  # twice: one swap

    assert isinstance(loop._watcher, processes._WaitpidChildWatcher) is affected


def test_only_macos_on_python_3_14_before_3_14_10_needs_the_watcher() -> None:
    from cyberfw.pipeline import processes

    expected = sys.platform == "darwin" and (3, 14) <= sys.version_info < (3, 14, 10)

    assert processes._WAITID_TAKES_A_STOP_FOR_AN_EXIT is expected


@pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
async def test_a_signal_cyberfw_is_told_to_ignore_stays_ignored() -> None:
    # ``nohup cyberfw …`` ignores SIGHUP: a hangup must not stop the scan.
    from cyberfw.pipeline.processes import stopping_tools_on_signals

    previous = signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        with stopping_tools_on_signals():
            inside_hup, inside_term = signal.getsignal(signal.SIGHUP), signal.getsignal(signal.SIGTERM)
        after_term = signal.getsignal(signal.SIGTERM)
    finally:
        signal.signal(signal.SIGHUP, previous)

    assert inside_hup is signal.SIG_IGN
    assert inside_term not in (signal.SIG_DFL, signal.SIG_IGN)  # taken over for the run
    assert after_term is signal.SIG_DFL  # and given back
