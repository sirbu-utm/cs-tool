"""Pytest bootstrap: make the repo-root ``cyberfw`` package importable.

The package is not pip-installed during tests, and pytest rootdir resolution
alone does not guarantee the repo root is on ``sys.path``.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
