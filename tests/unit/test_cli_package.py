"""cyberfw.cli is a package of focused modules — and splitting it changed nothing a user sees."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import typer.main

import cyberfw

PACKAGE = Path(cyberfw.__file__).resolve().parent / "cli"
#: Each module may import only from modules in a lower layer — no import cycles.
LAYER = {"app": 0, "common": 1, "views": 2, "tools": 3, "reports": 3, "triage": 3, "scan": 3, "schedule": 3, "launcher": 4}


def test_the_cli_is_a_package_of_the_planned_modules() -> None:
    assert PACKAGE.is_dir()
    assert {path.stem for path in PACKAGE.glob("*.py")} == {*LAYER, "__init__", "__main__"}


def test_sibling_imports_only_point_down_the_layers() -> None:
    for name, layer in LAYER.items():
        tree = ast.parse((PACKAGE / f"{name}.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("cyberfw.cli."):
                sibling = (node.module or "").split(".")[2]
                assert LAYER[sibling] < layer, f"{name} imports from {sibling}"


def test_the_commands_keep_their_order() -> None:
    from cyberfw.cli import app

    group = typer.main.get_command(app)
    assert group.list_commands(None) == [  # type: ignore[arg-type]
        "prepare", "init", "lock", "doctor", "status", "vt", "diff", "export",
        "mute", "unmute", "mutes", "run", "pipeline", "schedule",
    ]


def test_python_dash_m_still_runs_the_cli() -> None:
    run = subprocess.run(
        [sys.executable, "-m", "cyberfw.cli", "--help"],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONUTF8": "1"},
        timeout=120,
    )

    assert run.returncode == 0, run.stderr
    assert "pipeline" in run.stdout


#: The core's orchestration: the run commands reach it only through cyberfw.api.
ORCHESTRATION = {
    "cyberfw.core.finish", "cyberfw.core.scan", "cyberfw.core.sessions", "cyberfw.core.steps",
    "cyberfw.core.tool_run", "cyberfw.core.workspace",
}
#: How saved runs are read, compared and exported: `diff` and `export` use the API for it.
SAVED_RUNS = {"cyberfw.report.csv_report", "cyberfw.report.diff", "cyberfw.report.sarif"}


def _imported_modules(module: str) -> set[str]:
    tree = ast.parse((PACKAGE / f"{module}.py").read_text(encoding="utf-8"))
    return {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}


def test_the_run_commands_go_through_the_public_api() -> None:
    # `run` and `pipeline` may use the core's event types — never its orchestration.
    assert _imported_modules("scan") & ORCHESTRATION == set()
    assert _imported_modules("reports") & (ORCHESTRATION | SAVED_RUNS) == set()
