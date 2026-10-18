# CLI Package Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the 2855-line `cyberfw/cli.py` into a `cyberfw/cli/` package of focused modules by moving code verbatim, with nothing a user sees changing.

**Architecture:** First the tests stop reaching into `cyberfw.cli` directly: a small helper (`tests/unit/_cli.py`) reads internals as `cli.<name>` and replaces them with `patch_cli(...)` in every module that binds them, so the tests work the same on one module and on a package. Then a script moves every top-level statement of `cli.py` into its module (with the comments above it), gives each module the original import block plus sibling imports that only point down a fixed layer order, and ruff drops the unused imports.

**Tech Stack:** Python 3.14 via `uv`, Typer + Rich, pytest, ruff, mypy `--strict`.

**Spec:** `docs/superpowers/specs/2026-10-18-core-api-cli-split-design.md` — this plan is **Step 1** of it. Step 2 (the core) and Step 3 (the public API) get their own plans once this lands.

Two departures from the spec's Step 1 text, both to keep its higher rules (behaviour unchanged, tests change only in how they reach the code):

- **`vt` lives in `reports.py`, not `scan.py`.** Typer lists commands in the order they are registered, and the package registers them module by module (`tools` → `reports` → `triage` → `scan` → `schedule`). From `scan.py`, `vt` would move in `cyberfw --help` from between `status` and `diff` to after `mutes`.
- **Tests reach the internals through `tests/unit/_cli.py`, not by naming the new modules.** A function imported into several modules has a binding in each, so patching it where it is defined misses the callers in the other modules (`_is_interactive` is called from four). The helper patches every binding, and the tests stay as they are when Step 2 moves code again.

Every script and test below was run end-to-end, copied out of this file, on a throwaway worktree of `main` at `4633d6d`, and every `Expected:` line is what that run printed: Task 1 ends at 1003 passed, Task 2 at 1007 passed with ruff and mypy `--strict` clean, the help text byte-identical and the wheel carrying the package.

## Global Constraints

- Run everything through `uv run --quiet …`. Suite: `uv run --quiet python -m pytest -q`; lint: `uv run --quiet ruff check .` (what CI runs); types: `uv run --quiet mypy cyberfw`. All clean at the end of each task.
- **No behaviour change:** every command keeps its flags, output, exit codes and its place in `cyberfw --help`; the entry points `cyberfw` / `cs-tool` / `cstool` → `cyberfw.cli:app` and `python -m cyberfw.cli` keep working.
- Code moves verbatim; the only edit to moved code is the checkout-root registry lookup, `Path(__file__).resolve().parent.parent` → `.parents[2]`, because the file moves one directory down.
- Scratchpad: `SCRATCH=C:/Users/DANIIL~1/AppData/Local/Temp/claude/C--Users-DaniilSirbu-Desktop-CS-TOOL-main/6a8b772a-7993-414c-98b5-45500cbb762c/scratchpad` — the scripts below are saved there, never in the repo.
- Commits: **no `Co-Authored-By` trailer** (the user's rule for this repo); multi-line messages via `git commit -F <file in SCRATCH>`; stage only the task's files, never `CS-TOOL_presentation.pdf`. Push to `main` at the end (the user's standing instruction).

## Review Focus

1. `cyberfw --help` lists the same commands, in the same order, with the same text → Task 2's help diff and `test_the_commands_keep_their_order`.
2. `python -m cyberfw.cli …` — which `start.bat` / `start.sh` run as `-m cyberfw.cli prepare` — keeps working → `test_python_dash_m_still_runs_the_cli` (and the existing launcher-script tests).
3. Run from outside the checkout (the user's editable install), the CLI still finds the checkout's `registry.yaml`, now one directory further up from the code → the existing `TestRegistryLookup::test_candidates_prefer_cwd_then_checkout_root_then_packaged_copy`, which pins the checkout root (`parents[2]`).
4. A test that replaces a helper still reaches callers that now live in another module (e.g. `_is_interactive`, used by the launcher and by the VirusTotal-key prompt) → `test_patch_cli_replaces_every_binding`.
5. Someone who installs the wheel instead of running from the checkout gets the whole package → Task 2's wheel check (hatch's `packages = ["cyberfw"]` should pick up the subpackage; the step proves it).

---

### Task 1: Layout-independent test access to the CLI's internals

**Files:**
- Create: `tests/unit/_cli.py`, `tests/unit/test_cli_seams.py`
- Modify (by script): `tests/unit/test_cli.py`, `tests/unit/test_motion.py`, `tests/unit/test_hud.py`

**Interfaces:**
- Produces: in `tests/unit/_cli.py` — `cli` (attribute access `cli.<name>` returns what the CLI module that has `<name>` binds it to), `cli_modules() -> list[ModuleType]` (just `cyberfw.cli` while it is one file; the package's modules after Task 2), `patch_cli(monkeypatch, name, value) -> None` (sets `name` in every CLI module that binds it; asserts at least one does).

- [ ] **Step 1: Write the failing test** — create `tests/unit/test_cli_seams.py`:

```python
"""tests/unit/_cli.py: reading and replacing the CLI's internals wherever they live."""

from __future__ import annotations

import pytest

from ._cli import cli, cli_modules, patch_cli


def test_a_name_is_read_from_the_module_that_has_it() -> None:
    assert callable(cli._is_interactive)
    assert cli.app.info.name == "cyberfw"


def test_an_unknown_name_is_an_attribute_error() -> None:
    with pytest.raises(AttributeError, match="no cyberfw.cli module"):
        cli.no_such_thing  # noqa: B018 - the lookup itself is under test


def test_patch_cli_replaces_every_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_cli(monkeypatch, "_is_interactive", lambda: "patched")

    bound = [vars(module)["_is_interactive"] for module in cli_modules() if "_is_interactive" in vars(module)]
    assert bound and all(function() == "patched" for function in bound)


def test_patch_cli_refuses_a_name_no_module_binds(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(AssertionError, match="binds"):
        patch_cli(monkeypatch, "no_such_thing", None)
```

- [ ] **Step 2: Run it to see it fail**

Run: `uv run --quiet python -m pytest tests/unit/test_cli_seams.py -q`
Expected: collection ERROR — `ModuleNotFoundError` / `ImportError` for `._cli`.

- [ ] **Step 3: Create the helper** — `tests/unit/_cli.py`:

```python
"""The CLI's internals for tests, wherever they live.

`cyberfw.cli` is being split from one module into a package, and every module
that imports a name holds its own reference to it. Tests therefore read
internals through ``cli.<name>`` and replace them through :func:`patch_cli`,
which work the same on the single module and on the package.
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import Any

import pytest

#: The package's modules, the launcher first: it imports the most names.
_SUBMODULES = ("launcher", "scan", "tools", "reports", "triage", "schedule", "views", "common", "app")


def cli_modules() -> list[ModuleType]:
    """Every module of the CLI — just ``cyberfw.cli`` while it is a single file."""
    package = importlib.import_module("cyberfw.cli")
    if not hasattr(package, "__path__"):
        return [package]
    return [importlib.import_module(f"cyberfw.cli.{name}") for name in _SUBMODULES]


class _Cli:
    """``cli.<name>``: what the CLI module that has that name binds it to."""

    def __getattr__(self, name: str) -> Any:
        for module in cli_modules():
            if name in vars(module):
                return vars(module)[name]
        raise AttributeError(f"no cyberfw.cli module has {name!r}")


cli = _Cli()


def patch_cli(monkeypatch: pytest.MonkeyPatch, name: str, value: object) -> None:
    """Replace ``name`` in every CLI module that binds it: patching one module
    would miss the callers that live in the others."""
    bound = [module for module in cli_modules() if name in vars(module)]
    assert bound, f"no cyberfw.cli module binds {name!r}"
    for module in bound:
        monkeypatch.setattr(module, name, value)
```

- [ ] **Step 4: Run the seam tests**

Run: `uv run --quiet python -m pytest tests/unit/test_cli_seams.py -q`
Expected: 4 passed.

- [ ] **Step 5: Rewrite the CLI tests onto the helper** — save as `$SCRATCH/split/rewrite_cli_tests.py`:

```python
"""Point the CLI tests at tests/unit/_cli.py instead of at cyberfw.cli's internals.

Usage: python rewrite_cli_tests.py <test file> [<test file> ...]

- `from cyberfw import cli` and `import cyberfw.cli as cli` go — also `cli` inside
  `from cyberfw import __version__, cli`; a module-level `from ._cli import cli`
  (plus `patch_cli` when used) replaces them.
- `from cyberfw.cli import a, b` becomes `a, b = cli.a, cli.b` — in place inside
  a function, below the import block at module level.
- `<mp>.setattr(cli, "X", ...)` and `<mp>.setattr("cyberfw.cli.X", ...)` become
  `patch_cli(<mp>, "X", ...)`.
- `<mp>.setattr("cyberfw.cli.A.B", ...)` becomes `<mp>.setattr(cli.A, "B", ...)`.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

MODULE_FROM = re.compile(r"^from cyberfw\.cli import (?P<names>[^\n#]+?)[ \t]*\n", re.M)
LOCAL_FROM = re.compile(r"^(?P<indent>[ \t]+)from cyberfw\.cli import (?P<names>[^\n#]+?)[ \t]*$", re.M)
IMPORT_CLI = re.compile(r"^[ \t]*import cyberfw\.cli as cli[ \t]*\n", re.M)
FROM_CYBERFW = re.compile(r"^(?P<indent>[ \t]*)from cyberfw import (?P<names>[^\n#(]+?)[ \t]*\n", re.M)
SETATTR_MODULE = re.compile(r"(?P<mp>\w+)\.setattr\(\s*cli,\s*")
SETATTR_DOTTED = re.compile(r'(?P<mp>\w+)\.setattr\(\s*"cyberfw\.cli\.(?P<path>[A-Za-z_][\w.]*)",\s*')


def _assignment(names: str) -> str:
    listed = [name.strip() for name in names.split(",") if name.strip()]
    return f"{', '.join(listed)} = {', '.join(f'cli.{name}' for name in listed)}"


def _without_cli(match: re.Match[str]) -> str:
    """`from cyberfw import __version__, cli` keeps the other names; a bare `cli` line goes."""
    names = [name.strip() for name in match["names"].split(",") if name.strip()]
    if "cli" not in names:
        return match[0]
    rest = [name for name in names if name != "cli"]
    return f"{match['indent']}from cyberfw import {', '.join(rest)}\n" if rest else ""


def _dotted(match: re.Match[str]) -> str:
    head, _, attr = match["path"].partition(".")
    if not attr:
        return f'patch_cli({match["mp"]}, "{head}", '
    return f'{match["mp"]}.setattr(cli.{head}, "{attr}", '


def rewrite(text: str) -> str:
    module_level: list[str] = []

    def drop_module_level(match: re.Match[str]) -> str:
        module_level.append(_assignment(match["names"]))
        return ""

    text = MODULE_FROM.sub(drop_module_level, text)
    text = LOCAL_FROM.sub(lambda m: m["indent"] + _assignment(m["names"]), text)
    text = IMPORT_CLI.sub("", text)
    text = FROM_CYBERFW.sub(_without_cli, text)
    text = SETATTR_MODULE.sub(lambda m: f"patch_cli({m['mp']}, ", text)
    text = SETATTR_DOTTED.sub(_dotted, text)

    helpers = ["cli"] + (["patch_cli"] if "patch_cli(" in text else [])
    tree = ast.parse(text)
    last_import = max(node.end_lineno or 0 for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom)))
    lines = text.splitlines(keepends=True)
    inserted = [f"from ._cli import {', '.join(helpers)}\n"]
    if module_level:
        inserted.append("\n" + "\n".join(module_level) + "\n")
    lines[last_import:last_import] = inserted
    return "".join(lines)


if __name__ == "__main__":
    for name in sys.argv[1:]:
        path = Path(name)
        path.write_text(rewrite(path.read_text(encoding="utf-8")), encoding="utf-8", newline="\n")
        print("rewrote", path)
```

Run:

```bash
uv run --quiet python "$SCRATCH/split/rewrite_cli_tests.py" tests/unit/test_cli.py tests/unit/test_motion.py tests/unit/test_hud.py
uv run --quiet ruff check --fix --select I001 tests/unit
```

Expected: three "rewrote" lines; ruff sorts the new `from ._cli import …` lines into place.

- [ ] **Step 6: Check nothing reaches into `cyberfw.cli` directly any more**

Run: `grep -rnE 'from cyberfw\.cli import|from cyberfw import .*\bcli\b|import cyberfw\.cli|setattr\(\s*"cyberfw\.cli' tests`
Expected: no output. (`"-m", "cyberfw.cli"` in subprocess calls and `cyberfw.cli prepare` in the launcher-script tests stay: `python -m cyberfw.cli` keeps working.)

- [ ] **Step 7: Run everything**

Run: `uv run --quiet python -m pytest -q`, then `uv run --quiet ruff check .` and `uv run --quiet mypy cyberfw`
Expected: 1003 passed (999 + the 4 seam tests); ruff and mypy clean. `cyberfw/cli.py` is untouched.

- [ ] **Step 8: Commit**

```bash
git add tests/unit/_cli.py tests/unit/test_cli_seams.py tests/unit/test_cli.py tests/unit/test_motion.py tests/unit/test_hud.py
git commit -m "Reach the CLI's internals in tests through one helper, not module paths"
```

---

### Task 2: Split `cyberfw/cli.py` into the package

**Files:**
- Delete: `cyberfw/cli.py`
- Create (by script): `cyberfw/cli/{__init__,__main__,app,common,views,tools,reports,triage,scan,schedule,launcher}.py`
- Create: `tests/unit/test_cli_package.py`
- Modify: `README.md` (project structure), `CHANGELOG.md`

**Interfaces:**
- Consumes: `tests/unit/_cli.py` (Task 1) — the tests need no change in this task.
- Produces: the package. Layers (a module imports siblings only from a lower layer): `app` 0 → `common` 1 → `views` 2 → `tools`, `reports`, `triage`, `scan`, `schedule` 3 → `launcher` 4. `cyberfw.cli.app` is the Typer app; `cyberfw/cli/__init__.py` re-exports it and imports `tools, reports, triage, scan, schedule, launcher` in that order (the commands' order in `--help`; `vt` lives in `reports.py` for that reason).

- [ ] **Step 1: Capture the help text before the move**

Run: `PYTHONUTF8=1 COLUMNS=100 uv run --quiet python -m cyberfw.cli --help > "$SCRATCH/help-before.txt"`
Expected: the usage panel listing `init lock doctor status vt diff export mute unmute mutes run pipeline schedule`.

- [ ] **Step 2: Write the failing tests** — create `tests/unit/test_cli_package.py`:

```python
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
```

(No per-module "imports on its own" test: `import cyberfw.cli.<anything>` runs the package's `__init__` first, which imports every module in one fixed order, so the layering test above is what rules out a cycle.)

- [ ] **Step 3: Run them to see the package tests fail**

Run: `uv run --quiet python -m pytest tests/unit/test_cli_package.py -q`
Expected: 2 failed, 2 passed — `test_the_cli_is_a_package_of_the_planned_modules` and `test_sibling_imports_only_point_down_the_layers` fail (no `cyberfw/cli/` yet); `test_the_commands_keep_their_order` and `test_python_dash_m_still_runs_the_cli` pass already — they are the guards the move must keep green.

- [ ] **Step 4: Move the code** — save as `$SCRATCH/split/split_cli.py` and run `uv run --quiet python "$SCRATCH/split/split_cli.py" .` from the repo root:

```python
"""Split cyberfw/cli.py into the cyberfw/cli/ package — moving code, not changing it.

Usage: python split_cli.py <repo root>

Every top-level statement of cli.py moves verbatim, together with the comment
and blank lines above it, into the module GROUPS names for it. Each module gets
the original import block (ruff then drops what it does not use) plus a
`from cyberfw.cli.<module> import <names>` line for what it uses from sibling
modules. A sibling import that does not point strictly down the layers — the
only way to build an import cycle — stops the split before anything is written.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

GROUPS: dict[str, list[str]] = {
    "app": ["app"],
    "common": [
        "LOG", "Prompt", "Confirm", "_app_console", "VerboseOption", "_bootstrap",
        "_registry_candidates", "_registry_path", "_is_packaged", "_is_interactive",
        "_wants_to_save", "_after_live", "_live_fps", "_session_tag", "_checked_session",
        "_binary_on_disk", "_tool_state", "_tool_version", "_tool_states", "_clear_screen",
        "_fresh_screen",
    ],
    "views": [
        "_sorted_ports", "_SEVERITY_ORDER", "_severity_cell", "_finding_detail", "_record_table",
        "_node_table", "_stage_outcome", "_print_changes", "_plan_view", "_SUMMARY_SEVERITIES",
        "_ASSET_KINDS", "_severity_tally", "_asset_counts", "_fix_first", "_findings_pane",
        "_run_summary", "_clock_text", "_ToolRow", "_tool_rows", "_tools_table", "_inventory_table",
        "_tool_menu", "_dep_row", "_status_view", "_print_reputation",
    ],
    "tools": [
        "prepare_cmd", "_ensure_tools", "init_cmd", "_locked_tags", "_report_lock_additions",
        "_LOCK_CHANGE_STYLES", "_lock_table", "lock_cmd", "_RowSink", "_InstallProgress",
        "_provision_chromium", "_relative_to", "status_cmd",
    ],
    "reports": ["vt_cmd", "_vt_lookup", "diff_cmd", "export_cmd"],
    "triage": ["mute_cmd", "unmute_cmd", "mutes_cmd", "_is_iso_date"],
    "scan": [
        "_read_hosts", "_discard_session", "_write_reports", "_scan_control_overrides",
        "_pipeline_exit_code", "_apply_triage", "_compare_with_earlier", "_run_info", "_preflight",
        "_resolve_gowitness", "_resolve_vt_key", "_check_tls", "_check_mail", "_check_takeover",
        "_enrich_with_intel", "_enrich_with_vt", "run_cmd", "pipeline_cmd", "_run_single",
    ],
    "schedule": ["_is_posix", "_schedule_program", "schedule_cmd", "_schedule_posix", "_schedule_windows"],
    "launcher": [
        "app_callback", "_LOG_LEVELS", "_toggle_setting", "_start_screen", "interactive_menu",
        "_show_launcher", "_goodbye", "_back_to_launcher",
        "_PIPELINE_KEY", "_HELP_KEY", "_EXIT_KEYS", "_SETTINGS_KEYS", "_tool_range", "_ACTION_WORDS",
        "_menu_options", "_prompt_choice", "_help_card", "_show_help", "_dispatch_choice",
        "_launcher_view", "_LauncherView", "_interactive_run", "_tool_facts", "_pipeline_options",
        "_interactive_pipeline",
    ],
}
LAYER = {"app": 0, "common": 1, "views": 2, "tools": 3, "reports": 3, "triage": 3, "scan": 3, "schedule": 3, "launcher": 4}
DOCSTRINGS = {
    "app": "The Typer application every command module registers its commands on.",
    "common": "Plumbing the commands share: bootstrap, registry and lock paths, prompts, terminal and screen helpers.",
    "views": "Rich renderers: record and tool tables, the run summary, the plan, change lists, status.",
    "tools": "`prepare`, `init`, `lock`, `doctor` / `status` — installing, pinning and checking the tools.",
    "reports": "`vt`, `diff`, `export` — looking a target up and working with saved runs.",
    "triage": "`mute`, `unmute`, `mutes` — silencing accepted findings on future scans.",
    "scan": "`run` and `pipeline` — running a tool or a pipeline and finishing the run.",
    "schedule": "`schedule` — recurring monitoring scans through cron / the Windows Task Scheduler.",
    "launcher": "The interactive launcher: menu, help card, prompts and the no-argument entry point.",
}
#: Importing the command modules in this order registers the commands in the
#: order `cyberfw --help` has always listed them; the launcher adds the callback.
REGISTRATION_ORDER = ("tools", "reports", "triage", "scan", "schedule", "launcher")
CHECKOUT_REGISTRY_OLD = 'Path(__file__).resolve().parent.parent / "registry.yaml"'
CHECKOUT_REGISTRY_NEW = 'Path(__file__).resolve().parents[2] / "registry.yaml"'


def _names(node: ast.stmt) -> list[str]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.Assign):
        return [target.id for target in node.targets if isinstance(target, ast.Name)]
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return [node.target.id]
    return []


def _is_main_guard(node: ast.stmt) -> bool:
    test = node.test if isinstance(node, ast.If) else None
    return isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and test.left.id == "__name__"


def main(root: Path) -> None:
    src_path = root / "cyberfw" / "cli.py"
    out_dir = root / "cyberfw" / "cli"
    source = src_path.read_text(encoding="utf-8")
    lines = source.splitlines(keepends=True)
    tree = ast.parse(source)
    module_of = {name: module for module, names in GROUPS.items() for name in names}

    imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    last_import = max(node.end_lineno or 0 for node in imports)
    import_block = "".join(
        "".join(lines[node.lineno - 1 : node.end_lineno])
        for node in imports
        if not (isinstance(node, ast.ImportFrom) and node.module == "__future__")
    )

    chunks: dict[str, list[str]] = {module: [] for module in GROUPS}
    uses: dict[str, set[str]] = {module: set() for module in GROUPS}
    previous_end = last_import
    unmapped: list[str] = []
    for node in tree.body:
        if node.lineno <= last_import:
            continue
        text = "".join(lines[previous_end : node.end_lineno])
        previous_end = node.end_lineno or previous_end
        if _is_main_guard(node):
            continue
        names = _names(node)
        owners = {module_of.get(name) for name in names}
        if not names or None in owners or len(owners) != 1:
            unmapped.append(f"line {node.lineno}: {names or type(node).__name__}")
            continue
        (module,) = owners
        assert module is not None
        chunks[module].append(text)
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in module_of and module_of[sub.id] != module:
                uses[module].add(sub.id)
    if unmapped:
        sys.exit("unmapped top-level statements:\n  " + "\n  ".join(unmapped))
    upward = sorted(
        f"{module} uses {name} from {module_of[name]}"
        for module, names in uses.items()
        for name in names
        if LAYER[module_of[name]] >= LAYER[module]
    )
    if upward:
        sys.exit("imports that do not point down the layers:\n  " + "\n  ".join(upward))

    out_dir.mkdir()
    for module, texts in chunks.items():
        owners_used = sorted({module_of[name] for name in uses[module]})
        sibling_imports = "".join(
            f"from cyberfw.cli.{owner} import {', '.join(sorted(n for n in uses[module] if module_of[n] == owner))}\n"
            for owner in owners_used
        )
        body = "".join(texts)
        if module == "common":
            assert body.count(CHECKOUT_REGISTRY_OLD) == 1, "the checkout-root registry lookup moved"
            body = body.replace(CHECKOUT_REGISTRY_OLD, CHECKOUT_REGISTRY_NEW)
        (out_dir / f"{module}.py").write_text(
            f'"""{DOCSTRINGS[module]}"""\n\nfrom __future__ import annotations\n\n'
            + import_block
            + sibling_imports
            + body.rstrip("\n")
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
    docstring = ast.get_docstring(tree, clean=False) or "cyberfw command-line interface."
    (out_dir / "__init__.py").write_text(
        f'"""{docstring.rstrip()}\n"""\n\n'
        "from __future__ import annotations\n\n"
        "import importlib\n\n"
        "from cyberfw.cli.app import app\n\n"
        "# Importing the command modules registers their commands on `app` in this\n"
        "# order — the order `cyberfw --help` lists them. The launcher comes last: it\n"
        "# adds the callback that opens the menu when no command is given.\n"
        f"for _module in {REGISTRATION_ORDER!r}:\n"
        '    importlib.import_module(f"cyberfw.cli.{_module}")\n\n'
        '__all__ = ["app"]\n',
        encoding="utf-8",
        newline="\n",
    )
    (out_dir / "__main__.py").write_text(
        '"""`python -m cyberfw.cli` — the same app as the `cyberfw` command."""\n\n'
        "from cyberfw.cli import app\n\n"
        "app()\n",
        encoding="utf-8",
        newline="\n",
    )
    src_path.unlink()
    print("wrote", ", ".join(sorted(path.name for path in out_dir.glob("*.py"))))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
```

Expected: `wrote __init__.py, __main__.py, app.py, common.py, launcher.py, reports.py, scan.py, schedule.py, tools.py, triage.py, views.py`; `cyberfw/cli.py` is gone.

- [ ] **Step 5: Drop the unused imports**

Run: `uv run --quiet ruff check --fix --select F401,I001 cyberfw/cli`
Expected: about 750 fixes (each module got the whole original import block), 0 remaining.

- [ ] **Step 6: Run everything**

Run: `uv run --quiet python -m pytest -q`, `uv run --quiet ruff check .`, `uv run --quiet mypy cyberfw`
Expected: 1007 passed (the 1003 from Task 1 plus the 4 in `test_cli_package.py`); ruff and mypy clean (mypy now sees 65 source files).

- [ ] **Step 7: The help text is unchanged**

Run: `PYTHONUTF8=1 COLUMNS=100 uv run --quiet python -m cyberfw.cli --help > "$SCRATCH/help-after.txt" && diff "$SCRATCH/help-before.txt" "$SCRATCH/help-after.txt" && echo identical`
Expected: `identical`.

- [ ] **Step 8: The wheel carries the package**

Run:

```bash
rm -rf "$SCRATCH/dist" && uv build --wheel --out-dir "$SCRATCH/dist"
uv run --quiet python -m zipfile -l "$SCRATCH"/dist/cyberfw-*.whl | grep -o "cyberfw/cli[/.][a-z_]*\(\.py\)\?" | sort
```

Expected: exactly the 11 files `cyberfw/cli/__init__.py`, `__main__.py`, `app.py`, `common.py`, `launcher.py`, `reports.py`, `scan.py`, `schedule.py`, `tools.py`, `triage.py`, `views.py` — and no `cyberfw/cli.py`.

- [ ] **Step 9: Docs** — `README.md`, section "Структура": replace the line

```text
  cli.py                 Typer CLI и интерактивное меню
```

with

```text
  cli/                   Typer CLI: команды по модулям (tools, scan, reports, triage,
                         schedule), общие помощники (common), отрисовка (views), лаунчер
```

and add to `CHANGELOG.md` under `## [Unreleased]` → `### Changed` (top of the list):

```markdown
- `cyberfw/cli.py` (~2850 строк) разрезан на пакет `cyberfw/cli/`: команды
  разложены по модулям (`tools`, `scan`, `reports`, `triage`, `schedule`),
  общие помощники — в `common`, отрисовка — в `views`, интерактивное меню — в
  `launcher`. Код перенесён без изменений: команды, флаги, вывод, коды выхода и
  порядок в `cyberfw --help` прежние; `python -m cyberfw.cli` работает.
```

- [ ] **Step 10: Commit and push**

```bash
git add -A cyberfw/cli cyberfw/cli.py tests/unit/test_cli_package.py README.md CHANGELOG.md
git commit -F "$SCRATCH/commit-msg-cli-split.txt"
git push origin main
```

with `$SCRATCH/commit-msg-cli-split.txt`:

```
Split cyberfw/cli.py into the cyberfw/cli/ package

The 2855-line CLI module becomes a package of focused modules, by moving
code, not changing it: app (the Typer object), common (bootstrap, registry
and lock paths, prompts), views (Rich renderers), tools / reports / triage /
scan / schedule (the commands) and launcher (the interactive menu). A module
imports siblings only from a lower layer, so there is no import cycle, and
the package imports the command modules in the order `cyberfw --help` has
always listed the commands. The only edit to moved code is the
checkout-root registry lookup, one directory deeper now.

Commands, flags, output and exit codes are unchanged; the help text is
byte-identical and `python -m cyberfw.cli` still works.
```
