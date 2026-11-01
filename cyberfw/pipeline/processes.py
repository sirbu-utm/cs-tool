"""A tool's process tree: whatever a tool starts stops with it.

A scanner is often a wrapper — a shell script, an entry point, a binary that forks
workers — and stopping only the process cyberfw launched leaves the rest running,
still scanning. So each tool runs in a group of its own — a new session (its own
process group) on POSIX, a Job Object on Windows — and stopping the tool stops
the group.
"""

from __future__ import annotations

import os
import signal
import sys
from typing import Any

from cyberfw.logging import get_logger

LOG = get_logger("executor")

#: CreateProcess flag: the process starts with its main thread suspended, so it is in
#: its job before it runs a single instruction — let alone starts a child.
_CREATE_SUSPENDED = 0x00000004


class ProcessGroup:
    """The processes one tool runs as. Spawn the tool with :meth:`spawn_options`,
    hand its pid to :meth:`adopt`, and :meth:`close` the group once it is done."""

    def __init__(self) -> None:
        self._pgid: int | None = None
        self._job: int | None = None

    @staticmethod
    def spawn_options() -> dict[str, Any]:
        """Keyword arguments for ``create_subprocess_exec`` that start the tool in a
        group of its own (on Windows: suspended, until :meth:`adopt` lets it run)."""
        if sys.platform == "win32":
            return {"creationflags": _CREATE_SUSPENDED}
        return {"start_new_session": True}

    def adopt(self, pid: int) -> None:
        """Take the tool's process, just spawned with :meth:`spawn_options`, into the
        group — and on Windows let it run. Raises :class:`OSError` if the process
        cannot even be opened: it is then still suspended, for the caller to kill.
        Where no Job Object can hold it, the tool runs all the same, and stopping it
        stops its own process only."""
        if sys.platform == "win32":
            self._job = _adopt_into_job(pid)
        else:
            self._pgid = pid  # start_new_session made it the leader of a group of its own

    def terminate(self) -> None:
        """Ask every process in the group to exit: SIGTERM on POSIX. Windows has no
        such request, so there the whole job is ended at once."""
        if sys.platform == "win32":
            self.kill()
        elif self._pgid is not None:
            _signal_group(self._pgid, signal.SIGTERM)

    def kill(self) -> None:
        """End every process still in the group, at once."""
        if sys.platform == "win32":
            if self._job is not None:
                _kernel32.TerminateJobObject(self._job, 1)
        elif self._pgid is not None:
            _signal_group(self._pgid, signal.SIGKILL)

    def close(self) -> None:
        """End whatever the tool left running and let go of the group."""
        self.kill()
        if sys.platform == "win32" and self._job is not None:
            _kernel32.CloseHandle(self._job)
        self._job = self._pgid = None


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")

    _PROCESS_TERMINATE = 0x0001
    _PROCESS_SET_QUOTA = 0x0100
    _PROCESS_SUSPEND_RESUME = 0x0800
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    #: The job's last handle closing — cyberfw's, at :meth:`ProcessGroup.close` or
    #: when cyberfw itself dies — ends every process still in it.
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000

    class _BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_uint64)
            for name in ("Reads", "Writes", "Others", "ReadBytes", "WriteBytes", "OtherBytes")
        ]

    class _ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimits),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    _kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    _kernel32.TerminateJobObject.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _ntdll.NtResumeProcess.argtypes = (wintypes.HANDLE,)
    _ntdll.NtResumeProcess.restype = ctypes.c_long

    def _new_job() -> int:
        """A Job Object that ends its processes when its last handle closes."""
        job = _kernel32.CreateJobObjectW(None, None)
        if not job:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not _kernel32.SetInformationJobObject(
            job, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            error = ctypes.WinError(ctypes.get_last_error())
            _kernel32.CloseHandle(job)
            raise error
        return int(job)

    def _adopt_into_job(pid: int) -> int | None:
        """Put the suspended process ``pid`` in a new job, then resume it: the job's
        handle, or None where no job can hold it (it runs all the same)."""
        process = _kernel32.OpenProcess(
            _PROCESS_TERMINATE | _PROCESS_SET_QUOTA | _PROCESS_SUSPEND_RESUME, False, pid
        )
        if not process:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            job: int | None = None
            try:
                job = _new_job()
                if not _kernel32.AssignProcessToJobObject(job, process):
                    raise ctypes.WinError(ctypes.get_last_error())
            except OSError as exc:
                if job is not None:
                    _kernel32.CloseHandle(job)
                job = None
                LOG.debug("pid %d runs outside a job object (%s): stopping it stops its own process only", pid, exc)
            status = _ntdll.NtResumeProcess(process)
            if status < 0:
                if job is not None:
                    _kernel32.CloseHandle(job)  # ends the process, still suspended in it
                raise OSError(f"could not resume the process (NTSTATUS {status & 0xFFFFFFFF:#010x})")
            return job
        finally:
            _kernel32.CloseHandle(process)

else:

    def _signal_group(pgid: int, signum: signal.Signals) -> None:
        """Send ``signum`` to every process in the group ``pgid`` (none left: a no-op)."""
        try:
            os.killpg(pgid, signum)
        except (ProcessLookupError, PermissionError):
            pass
