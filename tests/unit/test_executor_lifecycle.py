"""Closing output pipes must not end a tool's timeout or cancellation handling."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from cyberfw.exceptions import ExecutionError
from cyberfw.pipeline.context import SessionContext
from cyberfw.pipeline.executor import run_stage


class ClosedPipesChild:
    """A process whose pipes reach EOF while the process itself is still alive."""

    def __init__(self) -> None:
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.returncode: int | None = None
        self.wait_started = asyncio.Event()
        self.exited = asyncio.Event()
        self.terminated = False
        self.killed = False
        self.reaped = False
        self.exit_delay: float | None = None

    def close_pipes(self) -> None:
        self.stdout.feed_eof()
        self.stderr.feed_eof()

    def finish(self, code: int) -> None:
        if self.returncode is None:
            self.returncode = code
            self.exited.set()

    async def wait(self) -> int:
        self.wait_started.set()
        if self.exit_delay is None:
            await self.exited.wait()
        else:
            try:
                await asyncio.wait_for(self.exited.wait(), self.exit_delay)
            except asyncio.TimeoutError:
                self.finish(0)
        self.reaped = True
        assert self.returncode is not None
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.finish(-15)

    def kill(self) -> None:
        self.killed = True
        self.finish(-9)


@pytest.fixture
async def child(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[ClosedPipesChild]:
    process = ClosedPipesChild()

    async def spawn(*_args: object, **_kwargs: object) -> ClosedPipesChild:
        return process

    monkeypatch.setattr("cyberfw.pipeline.executor.asyncio.create_subprocess_exec", spawn)
    yield process
    process.finish(0)


async def test_timeout_still_applies_after_both_pipes_close(child: ClosedPipesChild, tmp_path: Path) -> None:
    child.stdout.feed_data(b'{"host":"early.example.com"}\n')
    child.stderr.feed_data(b"scanner still running\n")
    child.close_pipes()

    with SessionContext(tmp_path, "session") as context:
        with pytest.raises(ExecutionError, match="timed out after 0.05s") as error:
            await asyncio.wait_for(
                run_stage(["fixture"], tool="subfinder", stage="sub", context=context, timeout=0.05),
                2,
            )
        assert context.targets("sub") == ["early.example.com"]

    assert [record.target for record in error.value.partial_records] == ["early.example.com"]
    assert error.value.stderr_tail == ["scanner still running"]
    assert child.terminated and child.reaped
    assert not child.killed


@pytest.mark.parametrize("timeout", [None, 30], ids=["no-deadline", "with-deadline"])
async def test_cancellation_during_process_wait_uses_graceful_cleanup(
    child: ClosedPipesChild, timeout: float | None
) -> None:
    child.close_pipes()
    before = asyncio.all_tasks()
    task = asyncio.create_task(run_stage(["fixture"], tool="x", stage="x", context=None, timeout=timeout))
    try:
        await asyncio.wait_for(child.wait_started.wait(), 2)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)

    assert child.terminated and child.reaped
    assert not child.killed
    assert not (asyncio.all_tasks() - before)


async def test_eof_alone_does_not_report_success(child: ClosedPipesChild) -> None:
    child.close_pipes()
    task = asyncio.create_task(run_stage(["fixture"], tool="x", stage="x", context=None))
    try:
        await asyncio.wait_for(child.wait_started.wait(), 2)
        assert not task.done()
    finally:
        child.finish(0)
        records = await asyncio.wait_for(task, 2)

    assert records == []
    assert child.reaped
    assert not child.terminated and not child.killed


async def test_drain_and_process_wait_share_one_deadline(child: ClosedPipesChild) -> None:
    child.exit_delay = 0.2

    async def close_later() -> None:
        await asyncio.sleep(0.2)
        child.close_pipes()

    close_task = asyncio.create_task(close_later())
    try:
        with pytest.raises(ExecutionError, match="timed out after 0.3s"):
            await asyncio.wait_for(
                run_stage(["fixture"], tool="x", stage="x", context=None, timeout=0.3), 2,
            )
    finally:
        await close_task

    assert child.terminated and child.reaped


@pytest.mark.parametrize("cancel", [False, True], ids=["timeout", "cancellation"])
async def test_real_process_is_stopped_after_closing_both_output_pipes(
    monkeypatch: pytest.MonkeyPatch, cancel: bool
) -> None:
    original_spawn = asyncio.create_subprocess_exec
    started: asyncio.Future[asyncio.subprocess.Process] = asyncio.get_running_loop().create_future()

    async def spawn(*args: str, **kwargs: Any) -> asyncio.subprocess.Process:
        process = await original_spawn(*args, **kwargs)
        started.set_result(process)
        return process

    monkeypatch.setattr("cyberfw.pipeline.executor.asyncio.create_subprocess_exec", spawn)
    # A Windows venv's python.exe can be a launcher that holds its own copies
    # of the pipes. Run the base interpreter so there is exactly one process.
    python = getattr(sys, "_base_executable", sys.executable)
    command = [python, "-c", "import os,time; os.close(1); os.close(2); time.sleep(30)"]
    task = asyncio.create_task(run_stage(command, tool="fixture", stage="s", context=None, timeout=None if cancel else 2))
    process: asyncio.subprocess.Process | None = None
    try:
        process = await asyncio.wait_for(started, 5)

        async def wait_for_eof() -> None:
            assert process is not None and process.stdout is not None and process.stderr is not None
            while not (process.stdout.at_eof() and process.stderr.at_eof()):
                await asyncio.sleep(0.01)

        await asyncio.wait_for(wait_for_eof(), 5)
        assert process.returncode is None, "both streams must close while the process is still alive"
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 5)
        else:
            with pytest.raises(ExecutionError, match="timed out after 2s"):
                await asyncio.wait_for(task, 5)
        assert process.returncode is not None
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        if process is not None and process.returncode is None:
            process.kill()
            await asyncio.wait_for(process.wait(), 5)
