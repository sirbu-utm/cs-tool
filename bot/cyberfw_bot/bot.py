"""Telegram wiring: commands in, messages and files out.

Thin by design — every handler validates the user, delegates to
:class:`~cyberfw_bot.service.ScanService`, and formats the reply with
:mod:`cyberfw_bot.formatting`. The scan itself runs in the background, and its
result is pushed to the chat by the notifier built in :func:`build_application`.
"""

from __future__ import annotations

import logging
from pathlib import Path

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import Application, ApplicationBuilder, CommandHandler, ContextTypes

from cyberfw_bot.config import BotConfig
from cyberfw_bot.formatting import HELP_TEXT, status_message, summary_message
from cyberfw_bot.models import Scan
from cyberfw_bot.service import AuthorizationError, ScanService
from cyberfw_bot.storage import ScanStore
from cyberfw_bot.validation import ValidationError

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
                text = (
                    f"❌ Scan <code>{scan.id}</code> failed — {scan.target}\n"
                    f"<code>{(scan.error or 'unknown error')[:500]}</code>"
                )
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
            await _reply(
                update,
                f"🔍 Queued scan <code>{scan.id}</code> for <b>{scan.target}</b>. "
                "I'll message you when it's done.",
            )

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
    return application


async def _reply(update: Update, text: str) -> None:
    if update.effective_message is not None:
        await update.effective_message.reply_text(text, parse_mode=_HTML)


async def _send_report(application: Application, scan: Scan) -> None:
    """Attach the HTML report (falling back to JSON) when one exists on disk."""
    for path_str in (scan.report_html, scan.report_json):
        if path_str and Path(path_str).is_file():
            with open(path_str, "rb") as handle:
                await application.bot.send_document(
                    scan.chat_id, handle, filename=Path(path_str).name
                )
            return
