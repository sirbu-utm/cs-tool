"""Entry point: ``python -m cyberfw_bot``.

Loads config, prepares the sqlite store, builds the application and starts long
polling. The store is initialised before polling so the first ``/scan`` has a
table to write to.
"""

from __future__ import annotations

import logging

from cyberfw_bot.bot import build_application
from cyberfw_bot.config import ConfigError, load_config
from cyberfw_bot.service import ScanService
from cyberfw_bot.storage import ScanStore


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    log = logging.getLogger("cyberfw_bot")

    try:
        config = load_config()
    except ConfigError as exc:
        raise SystemExit(f"configuration error: {exc}") from exc

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
