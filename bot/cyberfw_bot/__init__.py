"""cyberfw_bot — a Telegram front-end that drives the CS-TOOL ``cyberfw`` CLI.

The bot never re-implements a scanner: it shells out to ``cyberfw pipeline`` for
a target the user explicitly gave, reads the JSON report cyberfw writes, and
sends back a severity summary and the report file. See the package README.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
