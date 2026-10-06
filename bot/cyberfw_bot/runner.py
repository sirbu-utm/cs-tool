"""Run the ``cyberfw`` CLI as a subprocess — the bot's only contact with it.

The bot deliberately shells out to the existing command instead of importing
cyberfw's engine, so it always runs exactly what a human would at the terminal.
The invocation is built as an argv list and launched with
``create_subprocess_exec`` (never a shell), so a target string is data, not code.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path

from cyberfw_bot.config import BotConfig

__all__ = ["ScanOutcome", "CyberfwRunner"]

#: Tail of stdout/stderr kept for diagnostics on failure.
_TAIL = 4000

#: Environment variables that configure the bot itself and are withheld from
#: the cyberfw subprocess (BOT_TOKEN, BOT_*, ALLOWED_USER_IDS).
_BOT_ENV_PREFIXES = ("BOT_", "ALLOWED_USER_IDS")


@dataclass(frozen=True)
class ScanOutcome:
    """What one ``cyberfw pipeline`` invocation produced."""

    exit_code: int
    timed_out: bool
    report_json: Path | None
    report_html: Path | None
    stdout_tail: str
    stderr_tail: str
    log_path: Path | None = None


class CyberfwRunner:
    """Launches ``cyberfw pipeline`` and locates the report it writes."""

    def __init__(self, config: BotConfig) -> None:
        self._config = config

    def _argv(self, target: str, session: str) -> list[str]:
        cfg = self._config
        # --report forces a non-interactive save; --session is validated by
        # cyberfw itself to be a plain directory name under reports/.
        return [
            *cfg.cyberfw_cmd,
            "pipeline",
            cfg.pipeline,
            "--target",
            target,
            "--session",
            session,
            "--report",
            *cfg.extra_pipeline_args,
        ]

    def _env(self) -> dict[str, str]:
        # The bot's own settings — above all BOT_TOKEN — are of no use to cyberfw
        # or the scanners it starts, so they never reach the child environment.
        env = {key: value for key, value in os.environ.items() if not key.startswith(_BOT_ENV_PREFIXES)}
        # Belt and braces: pin the workspace and the per-tool timeout regardless
        # of where the bot process was started from.
        env["CYBERFW_ROOT_DIR"] = str(self._config.workspace)
        env["CYBERFW_STAGE_TIMEOUT"] = str(self._config.stage_timeout_s)
        return env

    async def run(self, target: str, session: str) -> ScanOutcome:
        """Run the pipeline for ``target`` under ``session``; never raises for a scan failure."""
        argv = self._argv(target, session)
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                cwd=str(self._config.workspace),
                env=self._env(),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            return ScanOutcome(
                exit_code=127,
                timed_out=False,
                report_json=None,
                report_html=None,
                stdout_tail="",
                stderr_tail=f"could not launch {argv[0]!r}: {exc}",
            )

        timed_out = False
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), self._config.scan_timeout_s)
        except asyncio.TimeoutError:
            timed_out = True
            await self._terminate(proc)
            stdout, stderr = b"", b"scan exceeded BOT_SCAN_TIMEOUT and was stopped"

        session_dir = self._config.reports_dir / session
        report_json = session_dir / "report.json"
        report_html = session_dir / "report.html"
        log_path = _write_scan_log(session_dir, stdout, stderr)
        return ScanOutcome(
            exit_code=proc.returncode if proc.returncode is not None else -1,
            timed_out=timed_out,
            report_json=report_json if report_json.is_file() else None,
            report_html=report_html if report_html.is_file() else None,
            stdout_tail=_decode_tail(stdout),
            stderr_tail=_decode_tail(stderr),
            log_path=log_path,
        )

    @staticmethod
    async def _terminate(proc: asyncio.subprocess.Process, grace: float = 5.0) -> None:
        """Ask the scan to stop, then kill it if it lingers — cyberfw stops its children."""
        if proc.returncode is not None:
            return
        try:
            proc.terminate()
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(proc.wait(), grace)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()


def _write_scan_log(session_dir: Path, stdout: bytes, stderr: bytes) -> Path | None:
    """Persist the full tool output next to the report, for the UI and triage.

    Best-effort: a scan is not failed just because its log could not be written.
    """
    try:
        session_dir.mkdir(parents=True, exist_ok=True)
        log_path = session_dir / "scan.log"
        with open(log_path, "wb") as handle:
            handle.write(stdout)
            if stderr:
                if stdout and not stdout.endswith(b"\n"):
                    handle.write(b"\n")
                handle.write(b"--- stderr ---\n")
                handle.write(stderr)
        return log_path
    except OSError:
        return None


def _decode_tail(blob: bytes) -> str:
    text = blob.decode("utf-8", errors="replace")
    return text[-_TAIL:]
