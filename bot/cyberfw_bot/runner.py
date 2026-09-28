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


@dataclass(frozen=True)
class ScanOutcome:
    """What one ``cyberfw pipeline`` invocation produced."""

    exit_code: int
    timed_out: bool
    report_json: Path | None
    report_html: Path | None
    stdout_tail: str
    stderr_tail: str


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
        env = dict(os.environ)
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
        return ScanOutcome(
            exit_code=proc.returncode if proc.returncode is not None else -1,
            timed_out=timed_out,
            report_json=report_json if report_json.is_file() else None,
            report_html=report_html if report_html.is_file() else None,
            stdout_tail=_decode_tail(stdout),
            stderr_tail=_decode_tail(stderr),
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


def _decode_tail(blob: bytes) -> str:
    text = blob.decode("utf-8", errors="replace")
    return text[-_TAIL:]
