"""Logging and console output.

The framework renders its UI with a shared :class:`rich.console.Console` and
mirrors structured diagnostics to a rotating log file under ``logs/``. The
console is theme-aware (auto-detect colour support and width).
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

__all__ = ["console", "setup_logging", "get_logger"]

#: Minimal, consistent palette for status messages — classic green/cyan
#: terminal-tool look, matching the startup banner's block-art wordmark.
THEME = Theme(
    {
        "ok": "bold green",
        "err": "bold red",
        "warn": "bold yellow",
        "info": "cyan",
        "muted": "dim",
        "tool": "bold cyan",
        "accent": "bold green",
    }
)

console = Console(theme=THEME, highlight=False)


def setup_logging(
    level: int | str = logging.INFO,
    log_dir: Path | None = None,
    *,
    log_to_file: bool = True,
) -> logging.Logger:
    """Configure the root logger with a Rich stream handler and a file handler.

    The console handler keeps the interactive UI; the file handler persists the
    same records to ``logs/cyberfw.log`` (rotating, 5 MB each, 3 backups) unless
    ``log_to_file`` is false. ``level`` and ``log_to_file`` are re-applied on
    every call, so settings changes take effect without restarting the process.
    """
    logger = logging.getLogger("cyberfw")
    logger.setLevel(level)
    logger.propagate = False

    has_console = any(isinstance(h, RichHandler) for h in logger.handlers)
    if not has_console:
        logger.addHandler(RichHandler(console=console, show_time=False, show_path=False, markup=False))

    file_handlers = [h for h in logger.handlers if isinstance(h, RotatingFileHandler)]
    if log_to_file and log_dir is not None and not file_handlers:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_dir / "cyberfw.log", maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        )
        logger.addHandler(file_handler)
    elif not log_to_file:
        for handler in file_handlers:
            logger.removeHandler(handler)
            handler.close()

    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger used by prepare defensive PyPI checks."""
    return logging.getLogger(f"cyberfw.{name}")
