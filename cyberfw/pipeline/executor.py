"""Executor — anyio wrapper over ``asyncio.create_subprocess_exec``.

Spawns an external tool without a TTY, parses its stdout as JSONL line-by-line
and its stderr separately (kept as a bounded tail for diagnostics), and on
cancellation (Ctrl+C / SIGTERM) asks the child to exit (SIGTERM), waits a short
grace period and only then SIGKILLs it, so a long scan never orphans a process
yet a tool that flushes on SIGTERM gets to. A non-zero exit (including SIGSEGV /
OOM kill by the OS) is surfaced as :class:`ExecutionError` carrying the last
stderr lines; the pipeline engine catches it and does not crash the parent.
"""

from __future__ import annotations

import asyncio
import collections
import os
import signal
import subprocess
from collections.abc import Awaitable, Callable
from pathlib import Path

from cyberfw.exceptions import ExecutionError, ParseError
from cyberfw.logging import get_logger
from cyberfw.pipeline.context import SessionContext
from cyberfw.pipeline.schemas import ToolRecord, validate_record

LOG = get_logger("executor")

#: How many trailing stderr lines to keep for error reporting.
_STDERR_KEEP = 25

#: Seconds a child gets to exit after SIGTERM before it is SIGKILLed.
_TERM_GRACE = 3.0


def _prepare_cmd(cmd: list[str]) -> list[str]:
    """Make Windows shebang scripts runnable via bash when the target is a file.

    Python's subprocess on Windows cannot directly execute a bare Unix shell
    script without an executable extension. Many tool fixtures and some portable
    wrappers are written as ``#!/usr/bin/env bash`` scripts in a project-local
    ``tools_bin`` directory, so intercept them here and hand them to ``bash``.
    """
    if os.name != "nt" or not cmd:
        return cmd

    exe = cmd[0]
    path = Path(exe)
    if not path.is_file():
        return cmd

    suffix = path.suffix.lower()
    if suffix in {".exe", ".bat", ".cmd", ".com", ".ps1"}:
        return cmd

    try:
        with path.open("rb") as handle:
            first = handle.readline(256)
    except OSError:
        return cmd

    if not first.startswith(b"#!"):
        return cmd

    bash = _find_bash()
    if not bash:
        return cmd

    return [bash, _to_posix_path(path, bash), *cmd[1:]]


#: Directories whose ``bash.exe`` is the WSL launcher, not a native shell.
_WSL_SHIM_DIRS = ("\\windows\\system32", "\\microsoft\\windowsapps")


def _find_bash() -> str | None:
    """Locate a ``bash.exe``, preferring Git Bash / MSYS2 over the WSL shim.

    ``C:\\Windows\\System32\\bash.exe`` (and its WindowsApps alias) launches a WSL
    distribution: it fails outright when none is installed, takes seconds to
    boot, and sees the filesystem under ``/mnt/c``. It frequently precedes Git's
    ``usr\\bin`` on PATH, so a plain ``shutil.which`` would pick it. Walk every
    PATH entry plus Git for Windows' default install locations, and only fall
    back to the WSL shim when no native bash exists anywhere.
    """
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    git_dirs = [
        os.path.join(program_files, "Git", "bin"),
        os.path.join(program_files, "Git", "usr", "bin"),
        os.path.join(local_appdata, "Programs", "Git", "bin") if local_appdata else "",
        os.path.join(local_appdata, "Programs", "Git", "usr", "bin") if local_appdata else "",
    ]
    path_dirs = [d for d in os.environ.get("PATH", "").split(os.pathsep) if d]

    shim: str | None = None
    for directory in [*path_dirs, *git_dirs]:
        if not directory:
            continue
        candidate = os.path.join(directory, "bash.exe")
        if not os.path.isfile(candidate):
            continue
        if any(marker in candidate.lower() for marker in _WSL_SHIM_DIRS):
            shim = shim or candidate
            continue
        return candidate
    return shim


def _to_posix_path(path: Path, bash: str) -> str:
    """Convert a Windows path to the POSIX form the resolved ``bash`` expects.

    MSYS2/Git Bash mounts drives at ``/c/...`` while WSL mounts them at
    ``/mnt/c/...``; passing the wrong one makes bash report "No such file or
    directory" even though the file exists. Git Bash and Cygwin ship a
    ``cygpath`` helper next to ``bash.exe`` that performs the exact
    conversion the running shell expects, so prefer it when present and fall
    back to the WSL convention otherwise.
    """
    cygpath = Path(bash).with_name("cygpath.exe")
    if cygpath.is_file():
        try:
            result = subprocess.run(
                [str(cygpath), "-u", str(path)],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except OSError:
            result = None
        if result is not None and result.returncode == 0:
            converted = result.stdout.strip()
            if converted:
                return converted

    posix_path = path.as_posix()
    if len(posix_path) >= 3 and posix_path[1] == ":" and posix_path[2] == "/":
        drive = posix_path[0].lower()
        posix_path = "/mnt/" + drive + posix_path[2:]
    return posix_path


async def run_stage(
    cmd: list[str],
    *,
    tool: str,
    stage: str,
    context: SessionContext | None,
    on_record: Callable[[ToolRecord], Awaitable[None]] | None = None,
    on_stderr: Callable[[str], Awaitable[None]] | None = None,
    on_stdout_raw: Callable[[str], Awaitable[None]] | None = None,
    parse: bool = True,
    parse_line: Callable[[str, int], ToolRecord] | None = None,
    parse_buffer: Callable[[str], list[ToolRecord]] | None = None,
) -> list[ToolRecord]:
    """Run ``cmd``, streaming + validating its stdout records.

    Returns the list of validated records. Raises :class:`ExecutionError` if the
    process exits non-zero or dies from a signal/OOM. ``on_record`` is awaited
    per validated record (Rich live table), before persisting to ``context``.
    ``on_stderr`` is awaited per stderr line as it arrives (e.g. ``--no-parse``
    passthrough), independently of the bounded tail kept for error reporting.
    ``parse_line`` may adapt a tool's non-JSON output format. ``parse_buffer``
    is for tools that emit a single JSON document (not JSONL, e.g. gitleaks):
    the whole stdout is collected and parsed once after the process exits.
    """
    logger = LOG
    cmd = _prepare_cmd(cmd)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        raise ExecutionError(
            f"{tool} could not start: {exc}. The installed binary may target another OS or architecture.",
            stderr_tail=[str(exc)],
        ) from exc
    stderr_tail: collections.deque[str] = collections.deque(maxlen=_STDERR_KEEP)
    records: list[ToolRecord] = []
    parser = parse_line
    buffered = parse and parse_buffer is not None
    buffer_lines: list[str] = []
    unparsed = 0

    async def _drain_stderr() -> None:
        assert proc.stderr is not None
        while True:
            raw = await proc.stderr.readline()
            if not raw:
                break
            text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if text:
                stderr_tail.append(text)
                if on_stderr is not None:
                    await on_stderr(text)

    async def _drain_stdout() -> None:
        nonlocal unparsed
        assert proc.stdout is not None
        lineno = 0
        while True:
            raw = await proc.stdout.readline()
            if not raw:
                break
            lineno += 1
            text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if on_stdout_raw is not None:
                # Every stdout line verbatim, independent of parsing — lets a
                # caller show exactly what the tool prints while records are
                # still parsed under the hood (e.g. verbose pipeline view).
                await on_stdout_raw(text)
            if buffered:
                # Whole-document tools: collect now, parse once after exit.
                buffer_lines.append(text)
                continue
            if not text and parse:
                continue
            rec: ToolRecord | None
            if not parse:
                rec = ToolRecord(
                    tool=tool,
                    line_number=lineno,
                    raw=text,
                    target=text,
                    kind="raw",
                )
                records.append(rec)
                if on_record is not None:
                    await on_record(rec)
                if context is not None:
                    context.append(stage, rec)
                continue
            try:
                if parser is None:
                    rec = validate_record(tool, text, lineno)
                else:
                    rec = parser(text, lineno)
            except ParseError as exc:
                logger.debug("%s", exc)
                unparsed += 1
                rec = None
            if rec is not None:
                records.append(rec)
                if on_record is not None:
                    await on_record(rec)
                if context is not None:
                    context.append(stage, rec)

    try:
        try:
            await asyncio.gather(_drain_stdout(), _drain_stderr())
        except asyncio.CancelledError:
            await _stop(proc)
            raise
        exit_code = await proc.wait()
        if exit_code != 0:
            raise ExecutionError(
                f"{tool} {_describe_crash(exit_code)}",
                exit_code=exit_code,
                stderr_tail=list(stderr_tail),
            )
        if buffered and parse_buffer is not None:
            for rec in parse_buffer("\n".join(buffer_lines)):
                records.append(rec)
                if on_record is not None:
                    await on_record(rec)
                if context is not None:
                    context.append(stage, rec)
        if unparsed:
            # One summary, not one line per failure: a tool whose JSON shape
            # drifted would otherwise lose every finding with only DEBUG noise.
            logger.warning(
                "%s: %d stdout line(s) did not match the expected schema and were dropped "
                "(re-run with --no-parse to see the raw output)",
                tool,
                unparsed,
            )
        return records
    finally:
        # Leaving this block with a live child — a callback or Context Store
        # error mid-stream, or a second cancellation during the grace period —
        # must never orphan a scanner. (transport.close() below also kills,
        # but via a private attribute.)
        _kill_if_running(proc)
        # Release pipe transports while the loop is still alive, so their
        # __del__ doesn't fire noisy ResourceWarnings at interpreter shutdown.
        _close_transport(proc)


def _close_transport(proc: asyncio.subprocess.Process) -> None:
    """Close the child's pipe transports so they don't outlive the event loop.

    On Windows the ProactorEventLoop otherwise leaves ``_ProactorBasePipeTransport``
    objects for GC, whose ``__del__`` runs after the loop is closed and prints a
    noisy ``unclosed transport`` / ``I/O operation on closed pipe`` ResourceWarning
    at interpreter shutdown. Closing them here is best-effort and harmless once the
    process has already been drained.
    """
    transport = getattr(proc, "_transport", None)
    if transport is not None:
        try:
            transport.close()
        except Exception:  # noqa: BLE001 - cleanup must never raise
            pass


def _kill_if_running(proc: asyncio.subprocess.Process) -> None:
    """Hard-kill the child if it has not exited yet (best effort, never raises)."""
    if proc.returncode is not None:
        return
    try:
        proc.kill()
    except (ProcessLookupError, PermissionError):  # pragma: no cover - already gone
        pass


async def _stop(proc: asyncio.subprocess.Process, grace: float = _TERM_GRACE) -> None:
    """Ask the child to exit, wait up to ``grace`` seconds, then hard-kill it.

    ``terminate()`` is SIGTERM on POSIX (which well-behaved scanners handle by
    flushing and exiting) and ``TerminateProcess`` on Windows (immediate, so the
    wait returns at once). Awaiting here — instead of scheduling the kill on a
    detached task — means nothing outlives ``run_stage``.
    """
    if proc.returncode is not None:
        return
    try:
        proc.terminate()
    except ProcessLookupError:  # pragma: no cover - already gone
        return
    try:
        await asyncio.wait_for(proc.wait(), grace)
    except asyncio.TimeoutError:
        _kill_if_running(proc)
        await proc.wait()


#: NTSTATUS codes Windows reports as a process exit code when it dies.
_WINDOWS_CRASH_CODES: dict[int, str] = {
    0xC0000005: "crashed with an access violation (0xC0000005)",
    0xC00000FD: "crashed with a stack overflow (0xC00000FD)",
    0xC0000409: "crashed with a stack buffer overrun / fast-fail (0xC0000409)",
}


def _describe_crash(exit_code: int) -> str:
    """Human wording for a non-zero exit: signal name on POSIX, NTSTATUS on Windows."""
    if exit_code < 0:  # POSIX: asyncio reports death-by-signal as -signum
        signum = -exit_code
        try:
            name = signal.Signals(signum).name
        except ValueError:
            return f"killed by signal {signum}"
        if signum == signal.SIGSEGV:
            return f"crashed with {name}"
        return f"killed by {name} (signal {signum})"
    described = _WINDOWS_CRASH_CODES.get(exit_code)
    if described is not None:
        return described
    return f"exited with code {exit_code}"
