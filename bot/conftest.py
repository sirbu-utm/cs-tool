"""Make the ``cyberfw_bot`` package importable when tests run from the repo root."""

from __future__ import annotations

import sys
from pathlib import Path

_BOT_DIR = Path(__file__).resolve().parent
if str(_BOT_DIR) not in sys.path:
    sys.path.insert(0, str(_BOT_DIR))
