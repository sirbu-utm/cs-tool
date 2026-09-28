"""Scan orchestration, independent of Telegram.

:class:`ScanService` owns the lifecycle: validate, persist, run cyberfw under a
concurrency limit, summarise, persist the result, and hand the finished
:class:`Scan` to a callback. Keeping it free of any bot API makes the whole flow
testable with a fake runner and an in-memory notifier.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

from cyberfw_bot.config import BotConfig
from cyberfw_bot.models import Scan
from cyberfw_bot.reports import ReportError, load_summary
from cyberfw_bot.runner import CyberfwRunner, ScanOutcome
from cyberfw_bot.storage import ScanStore
from cyberfw_bot.validation import validate_target

__all__ = ["ScanService", "AuthorizationError"]

Notifier = Callable[[Scan], Awaitable[None]]


class AuthorizationError(PermissionError):
    """The user is not on the allow-list."""


class ScanService:
    """Validates, queues and runs scans, then reports them through a notifier."""

    def __init__(
        self,
        config: BotConfig,
        store: ScanStore,
        runner: CyberfwRunner | None = None,
    ) -> None:
        self._config = config
        self._store = store
        self._runner = runner or CyberfwRunner(config)
        self._semaphore = asyncio.Semaphore(config.max_concurrent)
        #: Strong refs to in-flight tasks so they are not garbage-collected.
        self._tasks: set[asyncio.Task[None]] = set()

    def authorize(self, user_id: int) -> None:
        """Raise unless ``user_id`` may run scans (empty allow-list = nobody)."""
        if user_id not in self._config.allowed_user_ids:
            raise AuthorizationError(
                "you are not authorised to use this bot. Ask the operator to add your Telegram id."
            )

    async def submit(self, *, user_id: int, chat_id: int, raw_target: str, notify: Notifier) -> Scan:
        """Validate + queue a scan and start it in the background. Returns the queued scan.

        Raises :class:`AuthorizationError` or
        :class:`~cyberfw_bot.validation.ValidationError` synchronously, so the
        caller can answer the command immediately; anything past acceptance is
        delivered later through ``notify``.
        """
        self.authorize(user_id)
        target = validate_target(raw_target, block_private=self._config.block_private)

        scan = Scan(
            id=_new_id(),
            user_id=user_id,
            chat_id=chat_id,
            target=target,
            status="queued",
            created_at=datetime.now(timezone.utc),
        )
        await self._store.create(scan)

        task = asyncio.create_task(self._run(scan, notify))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return scan

    async def _run(self, scan: Scan, notify: Notifier) -> None:
        async with self._semaphore:
            await self._store.mark_running(scan.id)
            scan.status = "running"
            outcome = await self._runner.run(scan.target, session=f"bot-{scan.id}")
            await self._settle(scan, outcome)
        try:
            await notify(scan)
        except Exception:  # noqa: BLE001 - a delivery failure must not crash the worker
            pass

    async def _settle(self, scan: Scan, outcome: ScanOutcome) -> None:
        """Fold a runner outcome into the scan record and persist it."""
        summary = None
        if outcome.report_json is not None:
            try:
                summary = load_summary(outcome.report_json)
            except ReportError:
                summary = None

        # cyberfw exits non-zero when a stage failed, but the run may still have
        # produced a report; a summary present means there is something to show.
        if outcome.timed_out:
            scan.status, scan.error = "failed", "scan timed out"
        elif summary is not None:
            scan.status = "done"
        else:
            scan.status = "failed"
            scan.error = outcome.stderr_tail.strip() or f"cyberfw exited {outcome.exit_code}"

        scan.exit_code = outcome.exit_code
        scan.finished_at = datetime.now(timezone.utc)
        scan.report_json = str(outcome.report_json) if outcome.report_json else None
        scan.report_html = str(outcome.report_html) if outcome.report_html else None
        scan.summary = summary
        await self._store.finish(
            scan.id,
            status=scan.status,
            exit_code=scan.exit_code,
            error=scan.error,
            report_json=outcome.report_json,
            report_html=outcome.report_html,
            summary=summary,
        )

    async def wait_for_all(self) -> None:
        """Await every in-flight scan — used on shutdown and in tests."""
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)


def _new_id() -> str:
    """A short, filesystem- and session-safe id (also a valid ``--session`` name)."""
    return secrets.token_hex(4)
