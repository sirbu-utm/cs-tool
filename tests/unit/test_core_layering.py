"""cyberfw.core never reaches for the UI: no CLI, typer, Rich, presentation modules or console."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import cyberfw

CORE = Path(cyberfw.__file__).resolve().parent / "core"
#: Modules the core must not import — nor anything inside them.
FORBIDDEN = ("cyberfw.cli", "cyberfw.ui", "cyberfw.hud", "cyberfw.live_view", "cyberfw.motion", "typer", "rich")
#: Of these, what a fresh interpreter must not have loaded after importing the core
#: (Rich is loaded by the domain modules' logging, so it is left to the check above).
NOT_LOADED = ("cyberfw.cli", "cyberfw.ui", "cyberfw.hud", "cyberfw.live_view", "cyberfw.motion", "typer")


def _imported_names(path: Path) -> list[str]:
    """Every module ``path`` imports, and ``module.name`` for each ``from module import name``."""
    names: list[str] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.append(node.module)
            names.extend(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def _forbidden(name: str) -> bool:
    return name == "cyberfw.logging.console" or any(name == bad or name.startswith(f"{bad}.") for bad in FORBIDDEN)


def test_the_core_imports_no_ui() -> None:
    offenders = [
        f"{path.name} imports {name}"
        for path in sorted(CORE.glob("*.py"))
        for name in _imported_names(path)
        if _forbidden(name)
    ]

    assert offenders == []


def test_importing_the_core_loads_no_ui() -> None:
    modules = [f"cyberfw.core.{path.stem}" for path in sorted(CORE.glob("*.py")) if path.stem != "__init__"]
    code = (
        "import importlib, sys\n"
        f"for name in {modules!r}:\n"
        "    importlib.import_module(name)\n"
        f"print(' '.join(sorted(m for m in sys.modules if m.startswith({NOT_LOADED!r}))))\n"
    )
    run = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONUTF8": "1"},
        timeout=120,
    )

    assert run.returncode == 0, run.stderr
    assert modules, "the core has modules to check"
    assert run.stdout.strip() == ""
