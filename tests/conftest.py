"""Pytest bootstrap: importable package and a colour-neutral console.

The package is not pip-installed during tests, and pytest rootdir resolution
alone does not guarantee the repo root is on ``sys.path``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Rich picks colour support from the ambient environment, and cyberfw.logging
# builds its Console at import time. A terminal (or CI runner) exporting
# FORCE_COLOR/COLORTERM would therefore inject ANSI codes into the CliRunner
# output the assertions read, splitting substrings like "target: example.com"
# apart. Pin colour off here — before any cyberfw module is imported — so the
# suite behaves the same on a developer's coloured terminal and on CI.
# Tests that check styling render through their own Console instead.
os.environ.pop("FORCE_COLOR", None)
os.environ.pop("COLORTERM", None)
os.environ["NO_COLOR"] = "1"
os.environ["TERM"] = "dumb"
