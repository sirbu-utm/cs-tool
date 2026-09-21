"""Where cyberfw's data lives when it is run from a checkout vs. installed as a package.

Two layouts are supported:

* **Workspace** — a clone of the repository (the launchers ``cd`` into it):
  ``registry.yaml`` and ``pipelines/`` sit at the root, and ``tools_bin/``,
  ``reports/``, ``logs/`` are created next to them.
* **Installed** — ``pip install`` / ``uv tool install`` and ``cyberfw`` run from
  any directory: the wheel carries ``registry.yaml`` and ``pipelines/`` as
  ``cyberfw/data/`` (see ``force-include`` in ``pyproject.toml``), and the
  working directories go to the per-user data dir rather than the CWD.
"""

from __future__ import annotations

import os
import sys
from importlib.resources import files
from pathlib import Path

__all__ = ["APP_NAME", "packaged_data", "user_data_dir", "workspace_root"]

APP_NAME = "cyberfw"


def packaged_data(*parts: str) -> Path | None:
    """``cyberfw/data/<parts>`` from the installed package, or ``None`` when absent.

    A source checkout has no ``data/`` directory — its files are at the repo
    root — so callers fall back to those locations first.
    """
    candidate = Path(str(files(APP_NAME))) / "data"
    for part in parts:
        candidate = candidate / part
    return candidate if candidate.exists() else None


def user_data_dir() -> Path:
    """Per-user data directory following each platform's convention."""
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / APP_NAME


def workspace_root(cwd: Path | None = None) -> Path | None:
    """``cwd`` when it is a cyberfw workspace (holds ``registry.yaml``), else ``None``."""
    root = cwd or Path.cwd()
    return root if (root / "registry.yaml").is_file() else None
