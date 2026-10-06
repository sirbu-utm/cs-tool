"""Entry point: ``python -m cyberfw_bot``.

Loads config, prepares the sqlite store, builds the application and starts long
polling. The store is initialised before polling so the first ``/scan`` has a
table to write to.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from cyberfw_bot.bot import build_application
from cyberfw_bot.config import ConfigError, load_config
from cyberfw_bot.service import ScanService
from cyberfw_bot.storage import ScanStore

_LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"


def _attach_file_log(path: Path) -> None:
    """Mirror the bot's own log lines to a rotating file for the web UI.

    Only the ``cyberfw_bot`` logger is attached, so the file never carries the
    token-bearing request URLs that ``httpx`` logs.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(path, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    logging.getLogger("cyberfw_bot").addHandler(handler)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format=_LOG_FORMAT)
    # httpx logs every Telegram request at INFO, URL (and bot token) included —
    # keep those out of the log file and the journal.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    log = logging.getLogger("cyberfw_bot")

    try:
        config = load_config()
    except ConfigError as exc:
        raise SystemExit(f"configuration error: {exc}") from exc

    if config.log_path is not None:
        _attach_file_log(config.log_path)

    if not config.allowed_user_ids:
        log.warning(
            "ALLOWED_USER_IDS is empty — the bot will refuse every scan. "
            "Set it to your Telegram numeric id(s) to enable scanning."
        )

    store = ScanStore(config.db_path)
    service = ScanService(config, store)
    application = build_application(config, store, service)

    log.info("cyberfw_bot starting; workspace=%s pipeline=%s", config.workspace, config.pipeline)
    application.run_polling()


if __name__ == "__main__":
    main()
