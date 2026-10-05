"""Telegram wiring: commands in, messages and files out.

Thin by design — every handler validates the user, delegates to
:class:`~cyberfw_bot.service.ScanService`, and formats the reply with
:mod:`cyberfw_bot.formatting`. The scan itself runs in the background, and its
result is pushed to the chat by the notifier built in :func:`build_application`.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

from telegram import Message, Update
from telegram.constants import ParseMode
from telegram.error import BadRequest, RetryAfter
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from cyberfw_bot.config import BotConfig
from cyberfw_bot.formatting import (
    HELP_TEXT,
    UNKNOWN_COMMAND_TEXT,
    UNRECOGNIZED_TEXT,
    animation_frame,
    did_you_mean_text,
    failed_message,
    queued_message,
    status_message,
    summary_message,
)
from cyberfw_bot.models import Scan
from cyberfw_bot.service import AuthorizationError, ScanService
from cyberfw_bot.storage import ScanStore
from cyberfw_bot.validation import ValidationError, suggest_target

#: Seconds between waiting-animation frame edits.
_ANIMATION_INTERVAL_S = 5.0

LOG = logging.getLogger("cyberfw_bot")

__all__ = ["build_application"]

_HTML = ParseMode.HTML


def build_application(config: BotConfig, store: ScanStore, service: ScanService) -> Application:
    """Assemble the ``python-telegram-bot`` application with all handlers wired."""

    async def notify(scan: Scan) -> None:
        """Push a finished scan to its chat (summary text, then the report file)."""
        try:
            if scan.status == "done" and scan.summary is not None:
                text = summary_message(scan, scan.summary, config.max_findings_in_message)
            else:
                text = failed_message(scan)
            await application.bot.send_message(scan.chat_id, text, parse_mode=_HTML)
            await _send_report(application, scan)
        except Exception:  # noqa: BLE001 - never let delivery crash the worker
            LOG.exception("failed to deliver scan %s", scan.id)

    async def help_cmd(update: Update, _ctx: ContextTypes.DEFAULT_TYPE) -> None:
        await _reply(update, HELP_TEXT)

    async def scan_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        message, user = update.effective_message, update.effective_user
        if message is None or user is None:
            return
        raw_target = " ".join(ctx.args or [])
        try:
            scan = await service.submit(
                user_id=user.id,
                chat_id=message.chat_id,
                raw_target=raw_target,
                notify=notify,
            )
        except AuthorizationError as exc:
            await _reply(update, f"⛔ {exc}")
        except ValidationError as exc:
            await _reply(update, f"⚠️ {exc}")
        else:
            sent = await message.reply_text(queued_message(scan), parse_mode=_HTML)
            application.create_task(_animate(store, scan, sent))

    async def unknown_cmd(update: Update, _ctx: ContextTypes.DEFAULT_TYPE) -> None:
        await _reply(update, UNKNOWN_COMMAND_TEXT)

    async def text_fallback(update: Update, _ctx: ContextTypes.DEFAULT_TYPE) -> None:
        message = update.effective_message
        if message is None or not message.text:
            return
        target = suggest_target(message.text, block_private=config.block_private)
        await _reply(update, did_you_mean_text(target) if target else UNRECOGNIZED_TEXT)

    async def status_cmd(update: Update, _ctx: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        if user is None:
            return
        try:
            service.authorize(user.id)
        except AuthorizationError as exc:
            await _reply(update, f"⛔ {exc}")
            return
        scans = await store.recent_for_user(user.id, limit=10)
        await _reply(update, status_message(scans))

    async def report_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        user = update.effective_user
        if user is None:
            return
        try:
            service.authorize(user.id)
        except AuthorizationError as exc:
            await _reply(update, f"⛔ {exc}")
            return
        if not ctx.args:
            await _reply(update, "Usage: <code>/report &lt;scan_id&gt;</code>")
            return
        scan = await store.get(ctx.args[0])
        if scan is None or scan.user_id != user.id:
            await _reply(update, "No such scan of yours.")
            return
        if scan.status != "done" or scan.summary is None:
            await _reply(update, f"Scan <code>{scan.id}</code> is <b>{scan.status}</b>.")
            return
        await _reply(update, summary_message(scan, scan.summary, config.max_findings_in_message))
        await _send_report(application, scan)

    application = ApplicationBuilder().token(config.token).build()
    application.add_handler(CommandHandler(["start", "help"], help_cmd))
    application.add_handler(CommandHandler("scan", scan_cmd))
    application.add_handler(CommandHandler("status", status_cmd))
    application.add_handler(CommandHandler("report", report_cmd))
    # Fallbacks run last: a known command matches its handler above first, so
    # these only catch an unknown command or a plain, non-command message.
    application.add_handler(MessageHandler(filters.COMMAND, unknown_cmd))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_fallback))

    async def _post_init(_app: Application) -> None:
        """Ready the store, then settle scans a crash/restart left in limbo.

        A scan still ``queued``/``running`` at startup cannot be live (its task
        died with the previous process), so mark it failed and tell its chat —
        otherwise the request would sit "queued" forever.
        """
        await store.init()
        for scan in await store.reclaim_orphans(
            "interrupted by a bot restart — please resend the scan."
        ):
            await notify(scan)

    application.post_init = _post_init
    return application


async def _reply(update: Update, text: str) -> None:
    if update.effective_message is not None:
        await update.effective_message.reply_text(text, parse_mode=_HTML)


async def _animate(store: ScanStore, scan: Scan, sent: Message) -> None:
    """Edit ``sent`` with a waiting animation until the scan reaches a terminal state.

    Lives entirely in the bot layer: it polls the store for the scan's status and
    never touches the service. Any Telegram hiccup is swallowed so a cosmetic
    animation can never crash the worker or the final result delivery.
    """
    start = time.monotonic()
    tick = 0
    try:
        while True:
            current = await store.get(scan.id)
            if current is None or current.status in {"done", "failed"}:
                break
            text = animation_frame(
                current.status, scan.target, scan.id, tick, int(time.monotonic() - start)
            )
            try:
                await sent.edit_text(text, parse_mode=_HTML)
            except RetryAfter as exc:
                await asyncio.sleep(float(exc.retry_after) + 1.0)
                continue
            except BadRequest as exc:
                if "not modified" not in str(exc).lower():
                    return  # message deleted or uneditable — stop quietly
            tick += 1
            await asyncio.sleep(_ANIMATION_INTERVAL_S)
        try:
            await sent.edit_text("📨 Scan finished — sending results…", parse_mode=_HTML)
        except BadRequest:
            pass
    except Exception:  # noqa: BLE001 - a cosmetic animation must never crash the worker
        LOG.exception("waiting animation for scan %s crashed", scan.id)


async def _send_report(application: Application, scan: Scan) -> None:
    """Attach the HTML report (falling back to JSON) when one exists on disk."""
    for path_str in (scan.report_html, scan.report_json):
        if path_str and Path(path_str).is_file():
            with open(path_str, "rb") as handle:
                await application.bot.send_document(
                    scan.chat_id, handle, filename=Path(path_str).name
                )
            return
