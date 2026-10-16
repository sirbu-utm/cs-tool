"""Generate (and optionally install) an OS-scheduler entry for a recurring scan.

``cyberfw schedule`` turns a pipeline + target + cadence into a ready-to-use
entry for the host's scheduler — a crontab line on Linux/macOS, a ``schtasks``
command on Windows — that runs ``cyberfw pipeline … --alert`` on a schedule.
The entry carries ``CYBERFW_ROOT_DIR`` so the scheduled run uses this same
workspace from wherever the scheduler fires it, and appends its output to a
log.

Everything here except :func:`install` / :func:`remove` is pure string
building — nothing on the system is touched — so it is easy to test and safe
to print. The crontab edits are pure too (:func:`cron_with` / :func:`cron_without`
take the current crontab text and return the new text); only the thin
:func:`_run` boundary and the two install/remove helpers talk to ``crontab`` /
``schtasks``.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from dataclasses import dataclass, field

__all__ = [
    "Schedule",
    "cron_expr",
    "cron_line",
    "cron_with",
    "cron_without",
    "scan_argv",
    "schtasks_command",
    "tag",
    "validate_target",
    "install_cron",
    "remove_cron",
    "install_schtasks",
    "remove_schtasks",
]

CADENCES = ("daily", "weekly", "hourly")
_TIME = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")

#: A scheduled entry becomes a shell command that cron (``/bin/sh``) or
#: ``schtasks`` (``cmd.exe``) runs later, so the target — the one field a caller
#: controls freely — is restricted to what a host, IP or URL actually needs.
#: Anything else (spaces, quotes, ``;`` ``|`` ``&`` ``$`` backticks, parentheses,
#: redirects, newlines…) is refused rather than interpolated, which is what
#: would otherwise allow command injection when the job fires.
_SAFE_TARGET = re.compile(r"^[A-Za-z0-9._:/-]+$")


def validate_target(target: str) -> None:
    """Refuse a target that could inject a command into the scheduled entry.

    A scan seed is a host, IP or URL; it never needs shell metacharacters.
    Raises :class:`ValueError` for anything outside that safe set."""
    if not _SAFE_TARGET.match(target):
        raise ValueError(
            f"target {target!r} may only contain letters, digits and . _ - : / "
            "(it becomes part of a scheduled shell command)"
        )


@dataclass(frozen=True)
class Schedule:
    """What to run on a schedule, and how often."""

    pipeline: str
    target: str
    every: str = "daily"  # one of CADENCES
    at: str = "09:00"  # HH:MM, 24-hour; ignored for hourly
    alert_severity: str = "low"
    scan_args: tuple[str, ...] = field(default_factory=tuple)  # extra pipeline flags, e.g. ("--ffuf",)


def _hh_mm(at: str) -> tuple[int, int]:
    match = _TIME.match(at)
    if not match:
        raise ValueError(f"time must be HH:MM in 24-hour form, got {at!r}")
    return int(match.group(1)), int(match.group(2))


def cron_expr(every: str, at: str) -> str:
    """The 5-field cron expression for a cadence and a time.

    ``daily``/``weekly`` fire once at ``at`` (weekly on Monday); ``hourly``
    fires at minute 0 and ignores ``at``."""
    if every == "hourly":
        return "0 * * * *"
    hour, minute = _hh_mm(at)
    if every == "daily":
        return f"{minute} {hour} * * *"
    if every == "weekly":
        return f"{minute} {hour} * * 1"
    raise ValueError(f"cadence must be one of {', '.join(CADENCES)}, got {every!r}")


def _slug(target: str) -> str:
    """A filesystem/scheduler-safe form of the target for the task identity."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", target).strip("-")


def tag(schedule: Schedule) -> str:
    """Stable identity for the entry, so install replaces and remove finds it."""
    return f"cyberfw-{schedule.pipeline}-{_slug(schedule.target)}"


def scan_argv(schedule: Schedule, *, program: list[str]) -> list[str]:
    """The inner ``cyberfw pipeline … --alert`` call as an argv (no scheduler
    wrapper, no quoting). ``program`` is the launch prefix as tokens, e.g.
    ``["cyberfw"]`` or ``[sys.executable, "-m", "cyberfw"]``."""
    validate_target(schedule.target)
    return [
        *program, "pipeline", schedule.pipeline, "-t", schedule.target,
        "--alert", "--alert-severity", schedule.alert_severity, *schedule.scan_args,
    ]


def cron_line(schedule: Schedule, *, program: list[str], root: str, log: str, expr: str | None = None) -> str:
    """A full crontab line, tagged so it can be found again.

    Every interpolated value is shell-quoted (``shlex.quote``), so a path with
    a space stays one argument and a target cannot inject a command; ``expr``
    overrides the cadence with a raw 5-field cron expression."""
    schedule_expr = expr if expr is not None else cron_expr(schedule.every, schedule.at)
    cmd = " ".join(shlex.quote(token) for token in scan_argv(schedule, program=program))
    env = f"CYBERFW_ROOT_DIR={shlex.quote(root)}"
    return f"{schedule_expr} {env} {cmd} >> {shlex.quote(log)} 2>&1 # {tag(schedule)}"


def schtasks_command(schedule: Schedule, *, program: list[str], root: str, log: str) -> list[str]:
    """The ``schtasks /Create`` argv for Windows Task Scheduler.

    The inner command is quoted with Windows rules (``list2cmdline``), and the
    target is validated (see :func:`validate_target`) so it cannot break out of
    the ``cmd /c`` string."""
    if schedule.every == "hourly":
        sc = ["/SC", "HOURLY"]
    elif schedule.every == "weekly":
        sc = ["/SC", "WEEKLY", "/D", "MON", "/ST", schedule.at]
    elif schedule.every == "daily":
        sc = ["/SC", "DAILY", "/ST", schedule.at]
    else:
        raise ValueError(f"cadence must be one of {', '.join(CADENCES)}, got {schedule.every!r}")
    inner = subprocess.list2cmdline(scan_argv(schedule, program=program))
    log_part = f'"{log}"' if " " in log else log
    run = f'cmd /c "set CYBERFW_ROOT_DIR={root}&& {inner} >> {log_part} 2>&1"'
    return ["schtasks", "/Create", *sc, "/TN", tag(schedule), "/TR", run, "/F"]


def _tagged(line: str, task: str) -> bool:
    return line.rstrip().endswith(f"# {task}")


def cron_with(current: str, line: str, task: str) -> str:
    """``current`` crontab text with the ``task`` entry set to ``line`` (any
    earlier entry of the same identity dropped, so it never duplicates)."""
    kept = [row for row in current.splitlines() if row.strip() and not _tagged(row, task)]
    kept.append(line)
    return "\n".join(kept) + "\n"


def cron_without(current: str, task: str) -> str:
    """``current`` crontab text with the ``task`` entry removed; empty string
    when nothing is left."""
    kept = [row for row in current.splitlines() if row.strip() and not _tagged(row, task)]
    return "\n".join(kept) + "\n" if kept else ""


# -- system boundary (talks to crontab / schtasks) ------------------------------------------------
def _run(argv: list[str], *, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    """Run a scheduler command, capturing output. Isolated so tests can mock it."""
    return subprocess.run(argv, input=stdin, capture_output=True, text=True, check=False)


def _current_crontab() -> str:
    """The user's crontab, or ``""`` when there is none yet."""
    done = _run(["crontab", "-l"])
    return done.stdout if done.returncode == 0 else ""


def install_cron(schedule: Schedule, *, program: list[str], root: str, log: str, expr: str | None = None) -> None:
    """Replace (or add) this schedule's crontab entry."""
    line = cron_line(schedule, program=program, root=root, log=log, expr=expr)
    updated = cron_with(_current_crontab(), line, tag(schedule))
    done = _run(["crontab", "-"], stdin=updated)
    if done.returncode != 0:
        raise RuntimeError(done.stderr.strip() or "crontab rejected the update")


def remove_cron(schedule: Schedule) -> bool:
    """Drop this schedule's crontab entry; True if one was there."""
    current = _current_crontab()
    task = tag(schedule)
    if not any(_tagged(row, task) for row in current.splitlines()):
        return False
    done = _run(["crontab", "-"], stdin=cron_without(current, task))
    if done.returncode != 0:
        raise RuntimeError(done.stderr.strip() or "crontab rejected the update")
    return True


def install_schtasks(schedule: Schedule, *, program: list[str], root: str, log: str) -> None:
    """Create (or overwrite, via /F) this schedule's Windows task."""
    done = _run(schtasks_command(schedule, program=program, root=root, log=log))
    if done.returncode != 0:
        raise RuntimeError(done.stderr.strip() or done.stdout.strip() or "schtasks failed")


def remove_schtasks(schedule: Schedule) -> bool:
    """Delete this schedule's Windows task; True if it existed."""
    done = _run(["schtasks", "/Delete", "/TN", tag(schedule), "/F"])
    return done.returncode == 0
