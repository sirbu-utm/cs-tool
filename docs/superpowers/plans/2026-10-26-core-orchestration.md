# Core Orchestration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the orchestration of a run — preparing, running and finishing a pipeline or a single tool — out of `cyberfw/cli/scan.py` into a `cyberfw/core/` package that never prints, prompts or exits, while the CLI keeps printing exactly what it prints today.

**Architecture:** The core reports everything through a `RunObserver` (`core/events.py`): stage and record events from the engine, raw output, a `StepEvent` for the scan itself and for each step after it (with the step's result object on `done`), and `Note`s for every other line. The CLI gets one observer, `_CliObserver` in `cli/scan.py`, which opens and closes the live view on the scan's events, shows an activity line while a slow step runs and prints each result with the same wording as before. The code moves module by module, and after every task a transcript harness compares the full output of 36 `run` / `pipeline` scenarios — exit codes, console text and saved `report.json` — with the code before the move.

**Tech Stack:** Python 3.14 via `uv`, Typer + Rich, anyio, pytest, ruff, mypy `--strict`.

**Spec:** `docs/superpowers/specs/2026-10-18-core-api-cli-split-design.md` — this plan is **Step 2** of it (Step 1, the CLI package, is done: `f643648..1a21888`). Step 3 (the public API on top of this core) gets its own plan.

Departures from the spec's Step 2 text, each to keep a higher rule (behaviour unchanged, focused files):

- **`runs.py` is four modules, one per stage of a run:** `steps.py` (the checks after a scan), `finish.py` (triage, comparison, reports), `scan.py` (preparing and running a pipeline) and `tool_run.py` (`cyberfw run`). Together they hold what the spec lists for `runs.py`; each task creates one or two whole files instead of growing one 560-line module four times.
- **`StepEvent` has two more fields and two more steps.** `done` (units finished, for `advance`) and `subject` (what the step is about — the mail domain in the activity line) are what the CLI's activity line needs. The `scan` step wraps the engine run, so the CLI can open and close the live view on events: the live view and an activity line are both Rich live displays. The `compare` step carries the `RunDiff` the CLI prints before asking whether to save.
- **A few more helpers than the spec names:** `open_session` / `Session`, `choose_wordlist`, `post_scan`, `check_tool`, `keep_tool_run`, `Finished`, `PreparedPipeline` (with each tool's state, which the plan view now reads). `tool_state` moves into `core/workspace.py`.
- **Left in the CLI for Step 3:** `_pipeline_exit_code` and the alert line (the spec makes them `RunOutcome` methods in Step 3), `_scan_control_overrides`, and everything that asks or reads files: `_resolve_vt_key`, `_wants_to_save`, `_read_hosts`.
- **The only output changes.** (1) Warning notes are escaped, so an error message with `[...]` in it is shown instead of being swallowed as Rich markup — three lines of the transcripts change, in Task 2, and nothing else. (2) If the engine itself raises (it folds stage failures into its result, so this is rare and no test reaches it), the error now prints below the live view's last frame instead of above it. A single tool run's `finished_at` is taken right after the process instead of after its table is printed.

Every file, script and `Expected:` line below comes from running this plan end-to-end on a throwaway worktree of `main` at `1a21888`: Task 1 ends at 1015 passed, Task 2 at 1029, Task 3 at 1046, Task 4 at 1055, Task 5 at 1062; ruff and mypy `--strict` are clean after each, and the transcripts match the baseline except for the three intended lines.

## Global Constraints

- Run everything through `uv run --quiet …`. Suite: `uv run --quiet python -m pytest -q`; lint: `uv run --quiet ruff check .`; types: `uv run --quiet mypy cyberfw`. All clean at the end of every task.
- **Output stays as it is:** every command's console text, exit code and saved reports — checked after every task with the transcript harness. The one intended change is the escaped warnings of Task 2.
- **The core rule** (spec): `core` imports domain modules only — never `cyberfw.cli`, `typer`, Rich, the presentation modules (`cyberfw.ui`, `hud`, `live_view`, `motion`) or the shared `console`. `tests/unit/test_core_layering.py` (Task 1) enforces it for every module added later.
- Tests reach internals through `tests/unit/_cli.py` (`cli.<name>`, `patch_cli`), which after Task 1 covers every module of `cyberfw.cli` **and** `cyberfw.core`.
- Scratchpad: `SCRATCH=C:/Users/DANIIL~1/AppData/Local/Temp/claude/C--Users-DaniilSirbu-Desktop-CS-TOOL-main/6a8b772a-7993-414c-98b5-45500cbb762c/scratchpad`, `W="$SCRATCH/core-plan"`. The plan's scripts and transcripts live in `$W`, never in the repo.
- Commits: **no `Co-Authored-By` trailer** (the user's rule for this repo); stage only the task's files, never `CS-TOOL_presentation.pdf`. Push to `main` at the end (the user's standing instruction).

## Review Focus

1. On a real terminal, the scan's live view and each step's activity line are Rich live displays opened and closed by events; one left open raises nothing (Rich nests them) but keeps redrawing and leaves the cursor hidden → `TestLiveDisplaysOnATerminal` (Task 2), proved to bite in Task 4.
2. Ctrl+C during a step after the scan must take its activity line down: every `start` ends with a `done`, also when interrupted → `test_an_interrupted_step_still_ends` (Task 2).
3. Saved reports keep their content — the `report.json` of a saved pipeline, run, posture scan and alert re-scan → the transcript harness compares them, normalised, after every task.
4. A script driving the core prints nothing, even in a process where the CLI already set up logging → the `prints_nothing` fixture (Task 2), proved necessary in Task 3.
5. An engine that raises mid-scan still ends the scan step, closes the tool manager and exits 1 → `test_a_failing_engine_still_ends_the_scan_and_closes_the_manager` (Task 4).

---

### Before Task 1: the tools and a baseline

Two helpers for every task, kept in the scratchpad: `edit.py`, the checked editor the rewiring scripts use (each edit names how often its pattern must match, so a script that meets code it does not expect stops before writing anything), and the transcript harness.

- [ ] **Step 1: Save the editor** — `mkdir -p "$W"`, then save as `$W/edit.py`:

```python
"""Small, checked source edits for the core move — shared by the plan's rewiring scripts.

Every edit names how many times its pattern must match, so a script that meets
code it does not expect stops before writing anything.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path


class Source:
    """One file, edited in memory and written back only by :meth:`save`."""

    def __init__(self, root: Path, relative: str) -> None:
        self.path = root / relative
        self.text = self.path.read_text(encoding="utf-8")

    def replace(self, old: str, new: str, *, count: int = 1) -> Source:
        found = self.text.count(old)
        if found != count:
            sys.exit(f"{self.path}: expected {count} x {old!r}, found {found}")
        self.text = self.text.replace(old, new)
        return self

    def sub(self, pattern: str, new: str, *, count: int) -> Source:
        found = len(re.findall(pattern, self.text, flags=re.M))
        if found != count:
            sys.exit(f"{self.path}: expected {count} x /{pattern}/, found {found}")
        self.text = re.sub(pattern, new, self.text, flags=re.M)
        return self

    def replace_span(self, first: str, last: str, new: str) -> Source:
        """Replace everything from the line ``first`` through the line ``last`` (both
        whole lines, each found exactly once, ``last`` after ``first``) with ``new``."""
        for marker in (first, last):
            if self.text.count(marker) != 1:
                sys.exit(f"{self.path}: expected 1 x {marker!r}, found {self.text.count(marker)}")
        start, end = self.text.index(first), self.text.index(last) + len(last)
        if end <= start:
            sys.exit(f"{self.path}: {last!r} comes before {first!r}")
        self.text = self.text[:start] + new + self.text[end:]
        return self

    def drop_defs(self, *names: str) -> Source:
        """Remove top-level functions / classes / assignments, with the comment lines just above them."""
        tree = ast.parse(self.text)
        lines = self.text.splitlines(keepends=True)
        spans: list[tuple[int, int]] = []
        missing = set(names)
        for node in tree.body:
            name = getattr(node, "name", None)
            if name is None and isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
            if name in names:
                missing.discard(name)
                start = node.lineno - 1 - len(getattr(node, "decorator_list", []))
                while start > 0 and lines[start - 1].lstrip().startswith("#"):
                    start -= 1
                spans.append((start, node.end_lineno or node.lineno))
        if missing:
            sys.exit(f"{self.path}: no top-level {sorted(missing)}")
        for start, end in sorted(spans, reverse=True):
            del lines[start:end]
        self.text = re.sub(r"\n{3,}", "\n\n\n", "".join(lines)).rstrip("\n") + "\n"
        return self

    def save(self) -> None:
        self.path.write_text(self.text, encoding="utf-8", newline="\n")
        print("edited", self.path.as_posix())
```

- [ ] **Step 2: Save the transcript harness** — save as `$W/test_zz_capture.py`. It is copied into `tests/unit/` only for a capture (it reuses `test_cli.py`'s fake-tools workspace) and removed right after; it is never committed:

```python
"""Transcripts of `run` and `pipeline`, captured before and after the core move.

Not a test of the suite: the plan copies this file into tests/unit/ to capture,
then deletes it. Each scenario writes ``<name>.txt`` — the exit code and the
normalised output — into the directory named by ``CAPTURE_DIR``. Run with a
wide console (``COLUMNS=250``) so no path wraps.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from pathlib import Path

import pytest

from . import test_cli as base
from ._cli import patch_cli
from .test_cli import _workspace  # noqa: F401 - the fake-tools workspace, autouse

app = base.app
runner = base.runner
Setup = Callable[[Path, pytest.MonkeyPatch], list[str]]

PIPE = ["pipeline", "recon-to-vuln", "-t", "example.com"]


def _normalise(text: str, root: Path) -> str:
    for form in sorted({str(root), str(root.resolve()), root.as_posix(), root.resolve().as_posix()}, key=len, reverse=True):
        text = text.replace(form, "<root>")
    text = re.sub(r"\S*pytest-of-[^\\/\s]+[\\/]+pytest-\d+[\\/]+[^\\/\s]+", "<root>", text)
    text = text.replace("\\", "/")
    text = re.sub(r"\d{8}-\d{6}", "<stamp>", text)
    text = re.sub(r"\d{4}-\d{2}-\d{2}", "<date>", text)
    text = re.sub(r"\b\d{1,2}:\d{2}(?::\d{2})?\b", "<clock>", text)
    text = re.sub(r"\b\d+(?:\.\d+)?\s?m?s\b", "<dur>", text)
    text = re.sub(r"\b\d+ day\(s\)", "<n> day(s)", text)
    return text


#: Report fields that differ on every run.
_VOLATILE = {"duration_s", "started_at", "finished_at", "generated_at"}


def _steady(value: object) -> object:
    if isinstance(value, dict):
        return {key: "<t>" if key in _VOLATILE else _steady(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_steady(item) for item in value]
    return value


def _reports(root: Path) -> str:
    """Every saved report.json, its run-to-run noise taken out."""
    parts = []
    for path in sorted((root / "reports").rglob("report.json")) if (root / "reports").is_dir() else []:
        payload = _steady(json.loads(path.read_text(encoding="utf-8")))
        parts.append(f"--- {path.relative_to(root).as_posix()} ---\n"
                     + json.dumps(payload, indent=1, sort_keys=True, ensure_ascii=False))
    return _normalise("\n".join(parts), root)


def _tool_prints(root: Path, tool: str, *lines: dict[str, object]) -> None:
    base.TestBaselineComparison._tool_prints(root, tool, *lines)


def _posture(root: Path, monkeypatch: pytest.MonkeyPatch, *, fail: bool) -> None:
    """TLS, mail, takeover, threat intel and VirusTotal all have something to say."""
    from cyberfw import threatintel, vt
    from cyberfw.posture import mail, takeover

    base.TestPostureChecks._httpx_prints(root, {
        "url": "https://sub.example.com/", "status_code": 200, "title": "Home",
        "tls": {"host": "sub.example.com", "port": "443", "probe_status": True, "tls_version": "tls13",
                "issuer_cn": "R11", "not_after": "2001-01-01T00:00:00Z", "self_signed": True},
    })
    monkeypatch.setattr(vt, "resolve_api_key", lambda _explicit: "key")
    monkeypatch.setattr(threatintel, "cve_ids", lambda record: ["CVE-2024-0001"])
    if fail:
        async def broken(*_a: object, **_k: object) -> object:
            raise RuntimeError("upstream [down]")

        monkeypatch.setattr(mail, "check", broken)
        monkeypatch.setattr(takeover, "scan", broken)
        monkeypatch.setattr(threatintel, "enrich", broken)
        monkeypatch.setattr(vt, "enrich", broken)
        return

    async def fake_mail(domain: str, **_k: object) -> object:
        return mail.assess(domain, mx=[], null_mx=False, spf=[], spf_policy="", dmarc=[], dmarc_domain="")

    async def fake_takeover(hosts: list[str], **kw: object) -> object:
        from cyberfw.pipeline.schemas import PostureFinding

        progress = kw.get("progress")
        if callable(progress):
            progress(1)
        finding = PostureFinding.make(
            takeover.TOOL, "subdomain-takeover", "https://blog.example.com",
            name="Subdomain takeover possible — GitHub Pages", severity="high",
            description="blog.example.com → user.github.io, unclaimed", remediation="remove the record",
        )
        return [finding], ["DNS for x.example.com timed out"]

    async def fake_intel(records: object, cache_dir: object, **_k: object) -> object:
        return threatintel.IntelSummary(cves=1, findings=1, exploited=1, exploits=1, likely=1, errors=["EPSS feed stale"])

    async def fake_vt(targets: list[str], api_key: str, limit: int = 20, *_a: object, **kw: object) -> object:
        progress = kw.get("progress")
        if callable(progress):
            progress(1)
        return [vt.Reputation(target=t, kind="domain", found=True, malicious=index % 2) for index, t in enumerate(targets[:limit])]

    monkeypatch.setattr(mail, "check", fake_mail)
    monkeypatch.setattr(takeover, "scan", fake_takeover)
    monkeypatch.setattr(threatintel, "enrich", fake_intel)
    monkeypatch.setattr(vt, "enrich", fake_vt)


def _saved_then_new_finding(root: Path, _mp: pytest.MonkeyPatch) -> list[str]:
    first = runner.invoke(app, [*PIPE, "--session", "base", "--no-mail"])
    assert first.exit_code == 0, first.output
    _tool_prints(
        root, "nuclei",
        {"template-id": "xss", "matched-at": "https://sub.example.com/", "info": {"name": "XSS", "severity": "medium"}},
        {"template-id": "sqli", "matched-at": "https://sub.example.com/login", "info": {"name": "SQLi", "severity": "high"}},
    )
    return [*PIPE, "--session", "watch", "--no-mail", "--alert"]


def _muted(_root: Path, _mp: pytest.MonkeyPatch) -> list[str]:
    muted = runner.invoke(app, ["mute", "xss", "--reason", "false_positive"])
    assert muted.exit_code == 0, muted.output
    return [*PIPE, "--no-report", "--no-mail"]


def _kept_session(root: Path, _mp: pytest.MonkeyPatch) -> list[str]:
    (root / "reports" / "keep").mkdir(parents=True)
    return [*PIPE, "--session", "keep", "--no-report", "--no-mail"]


def _host_list(root: Path, _mp: pytest.MonkeyPatch) -> list[str]:
    (root / "hosts.txt").write_text("# live hosts\nsub.example.com\n\nwww.example.com\n", encoding="utf-8")
    return ["run", "httpx", "-l", "hosts.txt"]


def _bundled_wordlist(root: Path) -> None:
    (root / "wordlists").mkdir()
    (root / "wordlists" / "common.txt").write_text("admin\nlogin\n", encoding="utf-8")


def _no_bundled_wordlist(_root: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    patch_cli(monkeypatch, "default_wordlist", lambda: None)
    return [*PIPE, "--no-report", "--no-mail", "--ffuf"]


def _plain(argv: list[str]) -> Setup:
    return lambda _root, _mp: argv


def _then(prepare: Callable[[Path], None], argv: list[str]) -> Setup:
    def setup(root: Path, _mp: pytest.MonkeyPatch) -> list[str]:
        prepare(root)
        return argv

    return setup


def _posture_scan(fail: bool, argv: list[str]) -> Setup:
    def setup(root: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
        _posture(root, monkeypatch, fail=fail)
        return argv

    return setup


SCENARIOS: dict[str, Setup] = {
    "pipeline-default": _plain([*PIPE, "--no-report"]),
    "pipeline-saved": _plain([*PIPE, "--session", "cap"]),
    "pipeline-compared-alert": _saved_then_new_finding,
    "pipeline-verbose": _plain([*PIPE, "--no-report", "--no-mail", "--no-parse"]),
    "pipeline-topology": _plain([*PIPE, "--no-report", "--no-mail", "--topology"]),
    "pipeline-topology-verbose": _plain([*PIPE, "--no-report", "--no-mail", "--no-parse", "--topology"]),
    "pipeline-plan": _plain([*PIPE, "--plan"]),
    "pipeline-plan-no-target": _plain(["pipeline", "recon-to-vuln", "--plan"]),
    "pipeline-plan-blocked": _then(lambda root: (root / "tools_bin" / "nuclei").unlink(), [*PIPE, "--plan"]),
    "pipeline-ffuf": _then(_bundled_wordlist, [*PIPE, "--no-report", "--no-mail", "--ffuf"]),
    "pipeline-ffuf-given-wordlist": _plain([*PIPE, "--no-report", "--no-mail", "--ffuf", "-w", "words.txt"]),
    "pipeline-ffuf-no-wordlist": _no_bundled_wordlist,
    "pipeline-excluded": _plain([*PIPE, "--no-report", "--no-mail", "--exclude", "sub.example.com"]),
    "pipeline-broken-stage": _then(lambda root: base._break_tool(root, "httpx"), [*PIPE, "--no-report", "--no-mail"]),
    "pipeline-blocked": _then(lambda root: (root / "tools_bin" / "nuclei").unlink(), [*PIPE, "--no-report", "--no-mail"]),
    "pipeline-force-start": _then(
        lambda root: (root / "tools_bin" / "nuclei").unlink(), [*PIPE, "--no-report", "--no-mail", "--force-start"]
    ),
    "pipeline-posture": _posture_scan(False, [*PIPE, "--session", "posture"]),
    "pipeline-posture-failures": _posture_scan(True, [*PIPE, "--no-report"]),
    "pipeline-muted": _muted,
    "pipeline-kept-session": _kept_session,
    "pipeline-bad-session": _plain([*PIPE, "--session", "../x"]),
    "pipeline-unknown": _plain(["pipeline", "nope", "-t", "example.com"]),
    "pipeline-no-target": _plain(["pipeline", "recon-to-vuln"]),
    "run-default": _plain(["run", "subfinder", "-t", "example.com"]),
    "run-saved": _plain(["run", "subfinder", "-t", "example.com", "--save", "--session", "r1"]),
    "run-raw": _plain(["run", "subfinder", "-t", "example.com", "--no-parse"]),
    "run-raw-saved": _plain(["run", "subfinder", "-t", "example.com", "--no-parse", "--save"]),
    "run-empty": _then(lambda root: base._silence_tool(root, "subfinder"), ["run", "subfinder", "-t", "example.com"]),
    "run-broken": _then(lambda root: base._break_tool(root, "subfinder"), ["run", "subfinder", "-t", "example.com"]),
    "run-missing-binary": _then(
        lambda root: (root / "tools_bin" / "subfinder").unlink(), ["run", "subfinder", "-t", "example.com"]
    ),
    "run-no-target": _plain(["run", "subfinder"]),
    "run-unknown-tool": _plain(["run", "bogus", "-t", "x"]),
    "run-bad-target": _plain(["run", "gitleaks", "-t", "https://utm.md/"]),
    "run-host-list": _host_list,
    "run-controls": _plain(["run", "nuclei", "-t", "https://sub.example.com/", "--severity", "high", "--no-save"]),
    "run-bad-session": _plain(["run", "subfinder", "-t", "example.com", "--session", "a/b"]),
}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_capture(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = Path(os.environ["CAPTURE_DIR"])
    out.mkdir(parents=True, exist_ok=True)
    argv = SCENARIOS[name](tmp_path, monkeypatch)
    result = runner.invoke(app, argv)
    reports = sorted(
        str(path.relative_to(tmp_path)).replace("\\", "/")
        for path in (tmp_path / "reports").rglob("*") if path.is_file()
    ) if (tmp_path / "reports").is_dir() else []
    body = _normalise(result.output, tmp_path)
    (out / f"{name}.txt").write_text(
        f"exit={result.exit_code}\n{body}\n--- files under reports/ ---\n" + _normalise("\n".join(reports), tmp_path)
        + "\n" + _reports(tmp_path) + "\n",
        encoding="utf-8",
    )
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        (out / f"{name}.txt").write_text(
            (out / f"{name}.txt").read_text(encoding="utf-8") + f"--- exception ---\n{result.exception!r}\n",
            encoding="utf-8",
        )
    json.dumps(argv)  # argv must stay plain strings
```

- [ ] **Step 3: Capture the baseline** — on `main`, before any change:

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/0-base" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
git status --short
```

Expected: `36 passed`; `git status` shows only `?? CS-TOOL_presentation.pdf`. `$W/transcripts/0-base/` now holds one `.txt` per scenario.

---

### Task 1: The workspace moves into the core

**Files:**
- Create: `cyberfw/core/__init__.py`, `cyberfw/core/workspace.py`, `tests/unit/test_core_workspace.py`, `tests/unit/test_core_layering.py`
- Replace: `tests/unit/_cli.py`, `tests/unit/test_cli_seams.py`
- Modify (by script): `cyberfw/cli/common.py`, `cyberfw/cli/views.py`, `cyberfw/cli/launcher.py`, `cyberfw/cli/scan.py`, `cyberfw/cli/tools.py`, `tests/unit/test_cli.py`

**Interfaces:**
- Produces, in `cyberfw/core/workspace.py`: `registry_candidates() -> list[Path]`, `registry_path() -> Path` (raises `RegistryError`), `open_manager(settings: Settings) -> ToolManager` (lock next to the registry in use), `is_packaged(path: Path) -> bool`, `tool_state(manager: ToolManager, name: str, tools_dir: Path) -> str` (`ready` / `blocked` / `not installed`), `binary_on_disk(tools_dir: Path, name: str, binary_hint: str | None) -> bool`.
- Produces, in `tests/unit/_cli.py`: `cli_modules()` now returns every module of `cyberfw.cli` and `cyberfw.core`, found on disk (`__main__` left out); `cli.<name>`, `cli.<name> = …` and `patch_cli(...)` reach all of them.
- The CLI's `_registry_candidates`, `_registry_path`, `_is_packaged`, `_tool_state` and `_binary_on_disk` are gone; `_bootstrap` returns `open_manager(settings)`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_core_workspace.py`:

```python
"""cyberfw.core.workspace: the registry in use, the manager over it and the lock next to it."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberfw.config import Settings
from cyberfw.core.workspace import is_packaged, open_manager, registry_path


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "registry.yaml").write_text(
        "subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n  binary: subfinder\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_the_registry_in_the_current_directory_comes_first(workspace: Path) -> None:
    assert registry_path() == workspace / "registry.yaml"


def test_the_manager_keeps_the_lock_next_to_the_registry_in_use(workspace: Path) -> None:
    manager = open_manager(Settings(root_dir=workspace))
    try:
        assert manager.registry.names() == ["subfinder"]
        assert manager.lock_path == workspace / "tools.lock"
    finally:
        manager.close()


def test_a_checkout_file_is_not_a_packaged_copy(workspace: Path) -> None:
    assert not is_packaged(workspace / "tools.lock")
```

- [ ] **Step 2: Run it to see it fail**

Run: `uv run --quiet python -m pytest tests/unit/test_core_workspace.py -q`
Expected: collection error — `ModuleNotFoundError: No module named 'cyberfw.core'`.

- [ ] **Step 3: Create the core and its workspace module**

Create `cyberfw/core/__init__.py`:

```python
"""The core: prepares, runs and finishes scans without printing, prompting or exiting.

It imports domain modules only — never the CLI, typer, Rich, the presentation
modules (ui, hud, live_view, motion) or the shared console — and tells its
caller what happens through a :class:`~cyberfw.core.events.RunObserver`.
Like ``cyberfw.cli``, it is internal.
"""
```

Create `cyberfw/core/workspace.py`:

```python
"""Where cyberfw finds its registry and lock, and whether each registered tool can run."""

from __future__ import annotations

from pathlib import Path

from cyberfw.config import Settings
from cyberfw.exceptions import CyberfwError, RegistryError
from cyberfw.manager import ToolManager, load_registry
from cyberfw.manager.lock import LOCK_NAME
from cyberfw.resources import packaged_data


def registry_candidates() -> list[Path]:
    """Where ``registry.yaml`` may live, most specific first.

    The current directory (a workspace the user may have edited), then the
    checkout root next to the package (running from a clone elsewhere), then
    the copy the wheel ships as ``cyberfw/data/registry.yaml``.
    """
    candidates = [Path.cwd() / "registry.yaml", Path(__file__).resolve().parents[2] / "registry.yaml"]
    packaged = packaged_data("registry.yaml")
    if packaged is not None:
        candidates.append(packaged)
    return candidates


def registry_path() -> Path:
    """Locate ``registry.yaml`` or raise a :class:`RegistryError` naming the places tried."""
    candidates = registry_candidates()
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    tried = ", ".join(str(path) for path in candidates)
    raise RegistryError(f"registry.yaml not found (tried: {tried}). Run cyberfw from the project root.")


def open_manager(settings: Settings) -> ToolManager:
    """A :class:`ToolManager` over the registry in use, with ``tools.lock`` next to it."""
    path = registry_path()
    return ToolManager(settings, load_registry(path), lock_path=path.with_name(LOCK_NAME))


def is_packaged(path: Path) -> bool:
    """True for a file next to the wheel's packaged registry: an installed copy
    in site-packages, with no repository to commit it to."""
    packaged = packaged_data("registry.yaml")
    return packaged is not None and path.resolve().parent == packaged.resolve().parent


def tool_state(manager: ToolManager, name: str, tools_dir: Path) -> str:
    """``ready`` / ``blocked`` / ``not installed`` for one registered tool.

    Readiness is "can this run", so a binary that resolves is ready even
    without an install record (the record only carries the version, shown in
    its own column). ``blocked`` is the narrow case the user must act on: the
    file is on disk but cannot be read or executed — typically an antivirus
    quarantine.
    """
    # binary_path and binary_on_disk both rglob tools_dir; a directory that
    # lists but cannot be entered raises PermissionError (OSError) there on
    # Python 3.10-3.13 (3.14 swallows it). Treat an unreadable tree as "not on
    # disk" rather than letting a traceback replace the banner. OSError around
    # binary_path is the same net is_installed already casts.
    try:
        manager.binary_path(name)
    except (CyberfwError, OSError):
        try:
            on_disk = binary_on_disk(tools_dir, name, manager.spec(name).binary)
        except OSError:
            on_disk = False
        return "blocked" if on_disk else "not installed"
    return "ready"


def binary_on_disk(tools_dir: Path, name: str, binary_hint: str | None) -> bool:
    """True if a binary file for ``name`` exists at all (runnable or not).

    Lets status tell a Defender-blocked/unreadable download (present but broken)
    apart from one that was never fetched.
    """
    search = binary_hint or name
    for candidate in (tools_dir / search, tools_dir / f"{search}.exe"):
        if candidate.is_file():
            return True
    if tools_dir.is_dir():
        for candidate in tools_dir.rglob("*"):
            if candidate.is_file() and (candidate.name == search or candidate.stem == search):
                return True
    return False
```

- [ ] **Step 4: Run it to see it pass**

Run: `uv run --quiet python -m pytest tests/unit/test_core_workspace.py -q`
Expected: `3 passed`.

- [ ] **Step 5: Write down the core rule**

Create `tests/unit/test_core_layering.py`:

```python
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
```

Run: `uv run --quiet python -m pytest tests/unit/test_core_layering.py -q`
Expected: `2 passed` — the rule holds for the core as it is.

- [ ] **Step 6: Prove the rule bites**

```bash
cp cyberfw/core/workspace.py "$W/workspace.keep" && printf 'import typer  # noqa: F401\n' >> cyberfw/core/workspace.py
uv run --quiet python -m pytest tests/unit/test_core_layering.py -q
cp "$W/workspace.keep" cyberfw/core/workspace.py
```

Expected: `2 failed` — `AssertionError: assert ['workspace.py imports typer'] == []` and `assert 'typer typer....s typer.utils' == ''`; after the `cp`, `workspace.py` is back as created.

- [ ] **Step 7: The test helper must reach the core — failing test first**

Replace the whole of `tests/unit/test_cli_seams.py` with:

```python
"""tests/unit/_cli.py: reading and replacing the CLI's internals wherever they live."""

from __future__ import annotations

from pathlib import Path

import pytest

import cyberfw

from ._cli import cli, cli_modules, patch_cli


def test_the_helper_covers_every_cli_and_core_module() -> None:
    # Taken from the files on disk, so a module added later is reached too.
    root = Path(cyberfw.__file__).resolve().parent
    on_disk = {
        f"cyberfw.{package}.{path.stem}"
        for package in ("cli", "core")
        for path in (root / package).glob("*.py")
        if path.stem not in {"__init__", "__main__"}
    }

    assert {module.__name__ for module in cli_modules()} == on_disk


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


def test_monkeypatching_the_helper_rebinds_every_module() -> None:
    # `monkeypatch.setattr(cli, ...)` must reach the CLI modules rather than shadow
    # the name on the helper, and undoing it must put the real function back everywhere.
    real = cli._is_interactive
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(cli, "_is_interactive", lambda: "patched")
        patched = [vars(module)["_is_interactive"] for module in cli_modules() if "_is_interactive" in vars(module)]
        assert patched and all(function() == "patched" for function in patched)

    restored = [vars(module)["_is_interactive"] for module in cli_modules() if "_is_interactive" in vars(module)]
    assert restored and all(function is real for function in restored)
    assert "_is_interactive" not in vars(cli)
```

Run: `uv run --quiet python -m pytest tests/unit/test_cli_seams.py -q`
Expected: `1 failed, 5 passed` — `test_the_helper_covers_every_cli_and_core_module`: `Extra items in the right set: 'cyberfw.core.workspace'`.

- [ ] **Step 8: Extend the helper**

Replace the whole of `tests/unit/_cli.py` with:

```python
"""The internals of the CLI and the core it drives, for tests, wherever they live.

Code keeps moving between the modules of ``cyberfw.cli`` and ``cyberfw.core``,
and every module that imports a name holds its own reference to it. Tests
therefore read internals through ``cli.<name>`` and replace them through
:func:`patch_cli`, which reach every module of both packages.
"""

from __future__ import annotations

import importlib
import pkgutil
from types import ModuleType
from typing import Any

import pytest

#: The packages whose modules tests reach into.
_PACKAGES = ("cyberfw.cli", "cyberfw.core")


def cli_modules() -> list[ModuleType]:
    """Every module of the CLI and the core — found on disk, so a new one is never missed.

    ``__main__`` is left out: importing it would run the CLI."""
    modules: list[ModuleType] = []
    for package_name in _PACKAGES:
        package = importlib.import_module(package_name)
        for info in pkgutil.iter_modules(package.__path__):
            if info.name != "__main__":
                modules.append(importlib.import_module(f"{package_name}.{info.name}"))
    return modules


def _bound(name: str) -> list[ModuleType]:
    """The CLI and core modules that bind ``name``."""
    return [module for module in cli_modules() if name in vars(module)]


class _Cli:
    """``cli.<name>``: what the CLI or core module that has that name binds it to.

    Setting ``cli.<name>`` — as ``monkeypatch.setattr(cli, name, value)`` does —
    rebinds it in every module that has it, never on this object, where it
    would only shadow the real bindings."""

    def __getattr__(self, name: str) -> Any:
        for module in cli_modules():
            if name in vars(module):
                return vars(module)[name]
        raise AttributeError(f"no cyberfw.cli module has {name!r}")

    def __setattr__(self, name: str, value: object) -> None:
        bound = _bound(name)
        if not bound:
            raise AttributeError(f"no cyberfw.cli module has {name!r}")
        for module in bound:
            setattr(module, name, value)


cli = _Cli()


def patch_cli(monkeypatch: pytest.MonkeyPatch, name: str, value: object) -> None:
    """Replace ``name`` in every CLI and core module that binds it: patching one
    module would miss the callers that live in the others."""
    bound = _bound(name)
    assert bound, f"no cyberfw.cli module binds {name!r}"
    for module in bound:
        monkeypatch.setattr(module, name, value)
```

Run: `uv run --quiet python -m pytest tests/unit/test_cli_seams.py -q`
Expected: `6 passed`.

- [ ] **Step 9: The CLI tests name the core's functions — and fail while the CLI keeps its own copies**

Save as `$W/task1_tests.py`:

```python
"""Task 1: CLI tests reach the workspace helpers under their core names.

Usage: python task1_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

tests = Source(Path(sys.argv[1]), "tests/unit/test_cli.py")
tests.sub(r"cli\._registry_candidates\b", "cli.registry_candidates", count=1)
tests.sub(r"cli\._registry_path\b", "cli.registry_path", count=2)
tests.sub(r"cli\._tool_state\b", "cli.tool_state", count=3)
tests.replace('patch_cli(monkeypatch, "_registry_candidates"', 'patch_cli(monkeypatch, "registry_candidates"', count=2)
tests.replace('patch_cli(monkeypatch, "_registry_path"', 'patch_cli(monkeypatch, "registry_path"', count=2)
tests.replace('patch_cli(monkeypatch, "_tool_state"', 'patch_cli(monkeypatch, "tool_state"', count=1)
tests.save()
```

```bash
uv run --quiet python "$W/task1_tests.py" .
uv run --quiet python -m pytest tests/unit/test_cli.py -q -k "Registry or tool_state or startup_resolves or unreadable or runnable_binary or lock or bootstrap or packaged"
```

Expected: `edited tests/unit/test_cli.py`, then `3 failed, 32 passed, 221 deselected` — `test_startup_resolves_each_tool_once`, `test_the_lock_lives_next_to_the_registry_in_use` and `test_a_packaged_lock_is_not_called_something_to_commit` patch the core, which the CLI does not use yet.

- [ ] **Step 10: Rewire the CLI onto the core**

Save as `$W/task1_rewire.py`:

```python
"""Task 1: the CLI uses cyberfw.core.workspace instead of its own copies.

Usage: python task1_rewire.py <repo root>   (then: ruff check --fix --select F401,I001 cyberfw/cli)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])
CONFIG = "from cyberfw.config import "

common = Source(root, "cyberfw/cli/common.py")
common.drop_defs("_registry_candidates", "_registry_path", "_is_packaged", "_tool_state", "_binary_on_disk")
common.replace(
    "    registry_path = _registry_path()\n"
    "    manager = ToolManager(settings, load_registry(registry_path), lock_path=registry_path.with_name(LOCK_NAME))\n"
    "    return settings, manager\n",
    "    return settings, open_manager(settings)\n",
)
common.replace("    return [_tool_state(manager, name", "    return [tool_state(manager, name")
common.replace(CONFIG, "from cyberfw.core.workspace import open_manager, tool_state\n" + CONFIG)

views = Source(root, "cyberfw/cli/views.py")
views.replace(
    "from cyberfw.cli.common import _tool_state, _tool_states, _tool_version\n",
    "from cyberfw.cli.common import _tool_states, _tool_version\n",
)
views.replace("        state = _tool_state(manager, node.tool, tools_dir)", "        state = tool_state(manager, node.tool, tools_dir)")
views.replace(CONFIG, "from cyberfw.core.workspace import tool_state\n" + CONFIG)

launcher = Source(root, "cyberfw/cli/launcher.py")
launcher.replace("    _tool_state,\n", "")
launcher.replace('"state": _tool_state(manager, tool, settings.tools_dir)', '"state": tool_state(manager, tool, settings.tools_dir)')
launcher.replace(CONFIG, "from cyberfw.core.workspace import tool_state\n" + CONFIG)

scan = Source(root, "cyberfw/cli/scan.py")
scan.replace("    _tool_state,\n", "")
scan.replace("        state = _tool_state(manager, node.tool, tools_dir)", "        state = tool_state(manager, node.tool, tools_dir)")
scan.replace(CONFIG, "from cyberfw.core.workspace import tool_state\n" + CONFIG)

tools = Source(root, "cyberfw/cli/tools.py")
tools.replace(
    "from cyberfw.cli.common import VerboseOption, _after_live, _bootstrap, _is_packaged, _live_fps\n",
    "from cyberfw.cli.common import VerboseOption, _after_live, _bootstrap, _live_fps\n",
)
tools.replace('hint = "" if _is_packaged(', 'hint = "" if is_packaged(', count=2)
tools.replace(CONFIG, "from cyberfw.core.workspace import is_packaged\n" + CONFIG)

for source in (common, views, launcher, scan, tools):
    source.save()
```

```bash
uv run --quiet python "$W/task1_rewire.py" .
uv run --quiet ruff check --fix --select F401,I001 cyberfw/cli
uv run --quiet python -m pytest tests/unit/test_cli.py -q -k "Registry or tool_state or startup_resolves or unreadable or runnable_binary or lock or bootstrap or packaged"
```

Expected: five `edited cyberfw/cli/…` lines; `Found 10 errors (10 fixed, 0 remaining).`; `35 passed, 221 deselected`.

- [ ] **Step 11: Run everything**

Run: `uv run --quiet python -m pytest -q`, `uv run --quiet ruff check .`, `uv run --quiet mypy cyberfw`
Expected: `1015 passed, 5 skipped, 8 deselected`; ruff clean; mypy `Success: no issues found in 68 source files`.

- [ ] **Step 12: The output is unchanged**

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/1-workspace" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -r "$W/transcripts/0-base" "$W/transcripts/1-workspace" && echo identical
```

Expected: `36 passed`, then `identical`.

- [ ] **Step 13: Commit**

```bash
git add cyberfw/core tests/unit/_cli.py tests/unit/test_cli_seams.py tests/unit/test_core_layering.py tests/unit/test_core_workspace.py tests/unit/test_cli.py cyberfw/cli
git commit -m "Move the registry, lock and tool-state lookups into cyberfw/core/workspace.py"
```

---

### Task 2: The checks after a scan move into the core, as events

**Files:**
- Create: `cyberfw/core/events.py`, `cyberfw/core/steps.py`, `tests/unit/test_core_steps.py`
- Modify (by script): `tests/conftest.py` and `tests/unit/test_cli.py` (`task2_tests.py`); `cyberfw/cli/views.py` and `cyberfw/cli/scan.py` (`task2_cli.py`)

**Interfaces:**
- Consumes: Task 1's helper (`patch_cli` reaches `cyberfw.core`).
- Produces, in `cyberfw/core/events.py`: `RunObserver` (no-op `on_stage(StageEvent)`, `on_record(ToolRecord)`, `on_output(line: str, stream: str)`, `on_step(StepEvent)`, `on_note(Note)`); `StepEvent(kind: Literal["start", "advance", "done"], step: str, total: int | None = None, done: int = 0, subject: str | None = None, summary: StepSummary | None = None)`; `Note(level: Literal["info", "warn"], text: str)`; `TlsSummary(certificates, expired, soon, untrusted)`, `MailSummary(domain, verdict, worst)`, `TakeoverSummary(checked, possible, hosts)`, `VtSummary(looked_up, flagged)`; `StepSummary` = those, `threatintel.IntelSummary` or `report.diff.RunDiff`.
- Produces, in `cyberfw/core/steps.py`: `check_tls(result, observer)`, `check_mail(result, seed, observer)`, `check_takeover(result, observer)`, `rate_cves(result, cache_dir, observer)`, `enrich_vt(result, api_key, limit, observer)`, `post_scan(result, *, seed, settings, mail, takeover, intel, vt_key, vt_limit, observer)`.
- Produces, in `tests/conftest.py`: the `prints_nothing` fixture. In `cyberfw/cli/views.py`: `_print_note(Note)`, `_print_step_start(StepEvent)`, `_print_step_summary(StepSummary)`. In `cyberfw/cli/scan.py`: `_ACTIVITIES` and `_CliObserver(animate=...)` (steps and notes; Task 4 gives it the scan).

- [ ] **Step 1: A shared "prints nothing" fixture, and a guard for the terminal**

Save as `$W/task2_tests.py`:

```python
"""Task 2: a shared `prints_nothing` fixture, and a guard that a run leaves no live display open.

Usage: python task2_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

PRINTS_NOTHING = '''

@pytest.fixture
def prints_nothing(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Fail the test if the code under test writes to stdout.

    Logging is the caller's to set up — the CLI does, a script may not — so the
    ``cyberfw`` logger's handlers are detached for the test: a console handler
    another test installed must not count as the code printing.
    """
    monkeypatch.setattr(logging.getLogger("cyberfw"), "handlers", [])
    yield
    assert capsys.readouterr().out == "", "the code under test printed to stdout"
'''

TERMINAL_GUARD = r'''

class TestLiveDisplaysOnATerminal:
    """On a terminal the scan's live view and each step's activity line are Rich
    live displays, opened and closed by the run's events."""

    def test_every_live_display_is_closed_when_the_run_ends(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Rich nests live displays, so one left open raises nothing — it keeps
        # redrawing and leaves the cursor hidden. Every hidden cursor comes back.
        monkeypatch.setenv("TERM", "xterm-256color")
        monkeypatch.setenv("CYBERFW_ANIMATIONS", "true")
        terminal = Console(file=io.StringIO(), force_terminal=True, width=120, theme=THEME)
        patch_cli(monkeypatch, "console", terminal)

        result = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report"])

        assert result.exit_code == 0, repr(result.exception)
        raw = terminal.file.getvalue()  # type: ignore[attr-defined]
        assert raw.count("\x1b[?25l") == raw.count("\x1b[?25h") > 1, "a live display was left open"
        drawn = Text.from_ansi(raw).plain
        assert "recon-to-vuln · example.com" in drawn and "Email check skipped" in drawn
'''

conftest = Source(root, "tests/conftest.py")
conftest.replace("import os\nimport sys\n", "import logging\nimport os\nimport sys\n")
conftest.replace("from collections.abc import Callable\n", "from collections.abc import Callable, Iterator\n")
conftest.replace(
    '    monkeypatch.setattr(takeover, "doh", no_dns)\n',
    '    monkeypatch.setattr(takeover, "doh", no_dns)\n' + PRINTS_NOTHING,
)

cli_tests = Source(root, "tests/unit/test_cli.py")
cli_tests.replace("from rich.console import Console\n", "from rich.console import Console\nfrom rich.text import Text\n")
cli_tests.text = cli_tests.text.rstrip("\n") + "\n" + TERMINAL_GUARD

conftest.save()
cli_tests.save()
```

```bash
uv run --quiet python "$W/task2_tests.py" .
uv run --quiet python -m pytest tests/unit/test_cli.py -q -k TestLiveDisplaysOnATerminal
```

Expected: `edited tests/conftest.py`, `edited tests/unit/test_cli.py`, then `1 passed, 256 deselected` — the guard describes today's behaviour and must stay green; Task 4 proves it catches a live display left open.

- [ ] **Step 2: Write the failing tests**

Create `tests/unit/test_core_steps.py`:

```python
"""The steps after a scan, in cyberfw.core.steps: records added, events and notes sent, nothing printed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberfw import threatintel, vt
from cyberfw.config import Settings
from cyberfw.core import steps
from cyberfw.core.events import (
    MailSummary,
    Note,
    RunObserver,
    StepEvent,
    TakeoverSummary,
    TlsSummary,
    VtSummary,
)
from cyberfw.pipeline.engine import PipelineResult
from cyberfw.pipeline.schemas import PostureFinding, ToolRecord, validate_record
from cyberfw.posture import mail, takeover


class Recorder(RunObserver):
    """Keeps every step event and note it is sent."""

    def __init__(self) -> None:
        self.steps: list[StepEvent] = []
        self.notes: list[Note] = []

    def on_step(self, event: StepEvent) -> None:
        self.steps.append(event)

    def on_note(self, note: Note) -> None:
        self.notes.append(note)


def _record(tool: str, payload: dict[str, object]) -> ToolRecord:
    return validate_record(tool, json.dumps(payload), 1)


def _host() -> ToolRecord:
    return _record("subfinder", {"host": "sub.example.com", "source": "stub"})


def _finding() -> ToolRecord:
    return _record("nuclei", {"template-id": "xss", "matched-at": "https://sub.example.com/",
                              "info": {"name": "XSS", "severity": "medium"}})


pytestmark = pytest.mark.usefixtures("prints_nothing")


@pytest.fixture
def seen() -> Recorder:
    return Recorder()


def test_tls_reports_expired_and_untrusted_certificates(seen: Recorder) -> None:
    result = PipelineResult(records=[_record("httpx", {
        "url": "https://sub.example.com/", "status_code": 200, "title": "Home",
        "tls": {"host": "sub.example.com", "port": "443", "probe_status": True, "tls_version": "tls13",
                "issuer_cn": "R11", "not_after": "2001-01-01T00:00:00Z", "self_signed": True},
    })])

    steps.check_tls(result, seen)

    assert [event.kind for event in seen.steps] == ["start", "done"]
    assert seen.steps[-1].summary == TlsSummary(certificates=1, expired=1, soon=0, untrusted=1)
    added = {getattr(record, "template_id", "") for record in result.records[1:]}
    assert {"tls-cert-expired", "tls-cert-self-signed"} <= added


def test_a_step_with_nothing_to_do_sends_nothing(seen: Recorder) -> None:
    result = PipelineResult(records=[_finding()])

    steps.check_tls(result, seen)
    steps.check_takeover(result, seen)

    assert seen.steps == [] and seen.notes == []


def test_mail_reports_the_verdict_and_the_worst_finding(seen: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_check(domain: str, **_kw: object) -> object:
        return mail.assess(domain, mx=[], null_mx=False, spf=[], spf_policy="", dmarc=[], dmarc_domain="")

    monkeypatch.setattr(mail, "check", fake_check)
    result = PipelineResult()

    steps.check_mail(result, "https://www.example.com/", seen)

    start, done = seen.steps
    assert start == StepEvent("start", "mail", subject="example.com")
    assert done.summary == MailSummary("example.com", "spoofable", "No DMARC record — the domain can be spoofed")
    assert [record.kind for record in result.records][0] == "mail"


def test_an_unreachable_dns_is_a_note_not_a_failure(seen: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    async def offline(domain: str, **_kw: object) -> object:
        raise mail.DnsError("no resolver answered")

    monkeypatch.setattr(mail, "check", offline)

    steps.check_mail(PipelineResult(), "example.com", seen)

    assert seen.notes == [Note("warn", "Email check skipped — DNS-over-HTTPS unreachable: no resolver answered")]
    assert [(event.kind, event.summary) for event in seen.steps] == [("start", None), ("done", None)]


def test_an_interrupted_step_still_ends(seen: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    # A caller showing a live line for the step must get its "done" to take it down.
    async def interrupted(domain: str, **_kw: object) -> object:
        raise KeyboardInterrupt

    monkeypatch.setattr(mail, "check", interrupted)

    with pytest.raises(KeyboardInterrupt):
        steps.check_mail(PipelineResult(), "example.com", seen)

    assert [event.kind for event in seen.steps] == ["start", "done"]


def test_takeover_reports_progress_findings_and_notes(seen: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_scan(hosts: list[str], **kw: object) -> object:
        progress = kw["progress"]
        assert callable(progress)
        progress(1)
        finding = PostureFinding.make(
            takeover.TOOL, "subdomain-takeover", "https://blog.example.com",
            name="Subdomain takeover possible — GitHub Pages", severity="high",
            description="blog.example.com → user.github.io, unclaimed", remediation="remove the record",
        )
        return [finding], ["DNS for x.example.com timed out"]

    monkeypatch.setattr(takeover, "scan", fake_scan)
    result = PipelineResult(records=[_host()])

    steps.check_takeover(result, seen)

    assert [(event.kind, event.total, event.done) for event in seen.steps] == [
        ("start", 1, 0), ("advance", 1, 1), ("done", None, 0),
    ]
    assert seen.notes == [Note("warn", "Takeover: DNS for x.example.com timed out")]
    assert seen.steps[-1].summary == TakeoverSummary(checked=1, possible=1, hosts=("blog.example.com",))
    assert result.records[-1].tool == takeover.TOOL


def test_intel_passes_source_errors_on_as_notes(
    seen: Recorder, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rated = threatintel.IntelSummary(cves=1, findings=1, exploited=1, errors=["EPSS feed stale"])

    async def fake_enrich(records: object, cache_dir: Path, **_kw: object) -> threatintel.IntelSummary:
        return rated

    monkeypatch.setattr(threatintel, "cve_ids", lambda record: ["CVE-2024-0001"])
    monkeypatch.setattr(threatintel, "enrich", fake_enrich)

    steps.rate_cves(PipelineResult(records=[_finding()]), tmp_path, seen)

    assert seen.notes == [Note("warn", "Threat intel — EPSS feed stale")]
    assert seen.steps[-1] == StepEvent("done", "intel", summary=rated)


def test_virustotal_adds_reputation_records(seen: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_enrich(targets: list[str], api_key: str, limit: int = 20, **kw: object) -> list[vt.Reputation]:
        progress = kw["progress"]
        assert callable(progress)
        for done in range(1, len(targets) + 1):
            progress(done)
        return [vt.Reputation(target=t, kind="domain", found=True, malicious=i % 2) for i, t in enumerate(targets)]

    monkeypatch.setattr(vt, "enrichment_targets", lambda records: ["a.example.com", "b.example.com"])
    monkeypatch.setattr(vt, "enrich", fake_enrich)
    result = PipelineResult(records=[_host()])

    steps.enrich_vt(result, "key", 20, seen)

    assert [(event.kind, event.done) for event in seen.steps] == [("start", 0), ("advance", 1), ("advance", 2), ("done", 0)]
    assert seen.steps[0].total == 2
    assert seen.steps[-1].summary == VtSummary(looked_up=2, flagged=1)
    assert [record.tool for record in result.records[1:]] == ["virustotal", "virustotal"]


@pytest.mark.parametrize(
    ("step", "patch", "message"),
    [
        ("mail", (mail, "check"), "Email check failed: upstream [down]"),
        ("takeover", (takeover, "scan"), "Subdomain-takeover check failed: upstream [down]"),
        ("intel", (threatintel, "enrich"), "Threat intel failed: upstream [down]"),
        ("vt", (vt, "enrich"), "VirusTotal enrichment failed: upstream [down]"),
    ],
)
def test_a_failing_step_never_fails_the_scan(
    step: str, patch: tuple[object, str], message: str,
    seen: Recorder, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    async def broken(*_a: object, **_k: object) -> object:
        raise RuntimeError("upstream [down]")

    monkeypatch.setattr(*patch, broken)
    monkeypatch.setattr(threatintel, "cve_ids", lambda record: ["CVE-2024-0001"])
    monkeypatch.setattr(vt, "enrichment_targets", lambda records: ["a.example.com"])
    result = PipelineResult(records=[_host(), _finding()])

    steps.post_scan(
        result, seed="example.com", settings=Settings(root_dir=tmp_path), observer=seen,
        mail=step == "mail", takeover=step == "takeover", intel=step == "intel",
        vt_key="key" if step == "vt" else None, vt_limit=20,
    )

    assert seen.notes == [Note("warn", message)]
    assert [(event.step, event.kind, event.summary) for event in seen.steps if event.kind != "advance"] == [
        (step, "start", None), (step, "done", None),
    ]
    assert len(result.records) == 2  # nothing added, nothing lost


def test_post_scan_runs_the_steps_in_order_and_skips_what_is_off(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[str] = []
    for name, label in [("check_tls", "tls"), ("check_mail", "mail"), ("check_takeover", "takeover"),
                        ("rate_cves", "intel"), ("enrich_vt", "vt")]:
        monkeypatch.setattr(steps, name, lambda *_a, label=label: calls.append(label))
    settings = Settings(root_dir=tmp_path)

    def run(**flags: object) -> list[str]:
        calls.clear()
        options: dict[str, object] = {"mail": True, "takeover": True, "intel": True, "vt_key": "key", "vt_limit": 20}
        options.update(flags)
        steps.post_scan(PipelineResult(), seed="example.com", settings=settings, observer=RunObserver(), **options)  # type: ignore[arg-type]
        return list(calls)

    assert run() == ["tls", "mail", "takeover", "intel", "vt"]
    assert run(mail=False, intel=False, vt_key=None) == ["tls", "takeover"]
```

- [ ] **Step 3: Run them to see them fail**

Run: `uv run --quiet python -m pytest tests/unit/test_core_steps.py -q`
Expected: collection error — `ImportError: cannot import name 'steps' from 'cyberfw.core'`.

- [ ] **Step 4: Create the events and the steps**

Create `cyberfw/core/events.py`:

```python
"""What a run tells its caller as it goes, through a :class:`RunObserver`.

Stage and record events come from the engine as they happen; raw tool output
when a caller wants it; :class:`StepEvent` for the scan itself and each step
after it, with the step's result object on ``done``; :class:`Note` for every
other line worth showing — a skipped step, a warning, a hint.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypeAlias

from cyberfw.pipeline.engine import StageEvent
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.report.diff import RunDiff
from cyberfw.threatintel import IntelSummary


@dataclass(frozen=True)
class TlsSummary:
    """Certificate health from what httpx's ``-tls-grab`` collected."""

    certificates: int
    expired: int
    #: Still valid, but expiring within ``posture.tls.SOON_DAYS``.
    soon: int
    #: Self-signed, or issued for another name.
    untrusted: int


@dataclass(frozen=True)
class MailSummary:
    """Whether mail can be forged as the seed domain."""

    domain: str
    verdict: str
    #: The name of the worst finding, when there is one.
    worst: str | None


@dataclass(frozen=True)
class TakeoverSummary:
    """Subdomains with a dangling CNAME to an unclaimed third-party service."""

    checked: int
    possible: int
    #: Up to three of the hosts concerned, sorted.
    hosts: tuple[str, ...]


@dataclass(frozen=True)
class VtSummary:
    """VirusTotal reputation lookups."""

    looked_up: int
    flagged: int


#: A step's result, sent with its ``done`` event: the comparison with an earlier
#: run is a :class:`~cyberfw.report.diff.RunDiff`, threat intel a
#: :class:`~cyberfw.threatintel.IntelSummary`.
StepSummary: TypeAlias = TlsSummary | MailSummary | TakeoverSummary | IntelSummary | VtSummary | RunDiff


@dataclass(frozen=True)
class StepEvent:
    """The scan, or a step after it, starting, advancing or done.

    ``step`` is ``scan``, ``tls``, ``mail``, ``takeover``, ``intel``, ``vt`` or
    ``compare``. A step with nothing to do sends no events; one that starts
    always ends with ``done``, after its notes — also when it fails or is
    interrupted.
    """

    kind: Literal["start", "advance", "done"]
    step: str
    #: Units of work, when known (takeover hosts, VirusTotal lookups).
    total: int | None = None
    #: Units finished so far, on ``advance``.
    done: int = 0
    #: What the step is about, on ``start`` (the mail domain).
    subject: str | None = None
    #: The step's result on ``done``, when it has one.
    summary: StepSummary | None = None


@dataclass(frozen=True)
class Note:
    """A line for the user that is not a step's result."""

    level: Literal["info", "warn"]
    text: str


class RunObserver:
    """Receives a run's events. Every method does nothing: override what you need."""

    def on_stage(self, event: StageEvent) -> None:
        """A pipeline stage started, progressed or finished."""

    def on_record(self, record: ToolRecord) -> None:
        """A tool produced a record."""

    def on_output(self, line: str, stream: str) -> None:
        """A tool printed ``line`` on ``stream`` (``stdout`` or ``stderr``)."""

    def on_step(self, event: StepEvent) -> None:
        """The scan or a step after it started, advanced or finished."""

    def on_note(self, note: Note) -> None:
        """Something worth telling the user."""
```

Create `cyberfw/core/steps.py`:

```python
"""The checks after a scan — TLS, mail, takeover, threat intel, VirusTotal — without printing.

Each step adds its records to the run's result and reports through the
observer: ``start``, then any notes, then ``done`` — sent even when the step
fails or is interrupted. None of them ever fails the scan: a step that cannot
finish sends a warning :class:`~cyberfw.core.events.Note` instead.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import anyio

from cyberfw import threatintel, vt
from cyberfw.config import Settings
from cyberfw.core.events import (
    MailSummary,
    Note,
    RunObserver,
    StepEvent,
    StepSummary,
    TakeoverSummary,
    TlsSummary,
    VtSummary,
)
from cyberfw.pipeline.engine import PipelineResult
from cyberfw.pipeline.schemas import validate_record
from cyberfw.posture import mail as mailcheck
from cyberfw.posture import takeover as takeovercheck
from cyberfw.posture import tls as tlscheck

#: The most subdomains the takeover check looks at in one run.
_TAKEOVER_LIMIT = 300
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _advance(observer: RunObserver, step: str, total: int) -> Callable[[int], None]:
    """A ``progress`` callback that reports ``done`` units of ``step`` to the observer."""
    return lambda done: observer.on_step(StepEvent("advance", step, total=total, done=done))


def check_tls(result: PipelineResult, observer: RunObserver) -> None:
    """Certificate health from what httpx's -tls-grab already collected (no network)."""
    certs = tlscheck.certificates(result.records)
    if not certs:
        return
    summary: StepSummary | None = None
    observer.on_step(StepEvent("start", "tls"))
    try:
        now = datetime.now(timezone.utc)
        result.records.extend(tlscheck.findings(certs, result.records, now=now))
        expired = sum(1 for cert in certs if cert.is_expired(now))
        soon = sum(
            1
            for cert in certs
            if not cert.is_expired(now) and (days := cert.days_left(now)) is not None
            and days <= tlscheck.SOON_DAYS
        )
        untrusted = sum(1 for cert in certs if cert.self_signed or cert.mismatched)
        summary = TlsSummary(certificates=len(certs), expired=expired, soon=soon, untrusted=untrusted)
    finally:
        observer.on_step(StepEvent("done", "tls", summary=summary))


def check_mail(result: PipelineResult, seed: str, observer: RunObserver) -> None:
    """Whether mail can be forged as the seed domain (SPF / DMARC over DNS-over-HTTPS)."""
    domain = mailcheck.mail_domain(seed)
    if domain is None:
        return
    summary: StepSummary | None = None
    observer.on_step(StepEvent("start", "mail", subject=domain))
    try:
        record, found = anyio.run(mailcheck.check, domain)
        result.records.append(record)
        result.records.extend(found)
        worst = min(found, key=lambda f: _SEVERITY_RANK.get(f.severity, 4)).name if found else None
        summary = MailSummary(domain=domain, verdict=record.verdict, worst=worst)
    except mailcheck.DnsError as exc:
        observer.on_note(Note("warn", f"Email check skipped — DNS-over-HTTPS unreachable: {exc}"))
    except Exception as exc:  # noqa: BLE001 - a posture check must never fail the scan
        observer.on_note(Note("warn", f"Email check failed: {exc}"))
    finally:
        observer.on_step(StepEvent("done", "mail", summary=summary))


def check_takeover(result: PipelineResult, observer: RunObserver) -> None:
    """Flag subdomains with a dangling CNAME to an unclaimed third-party service."""
    hosts = takeovercheck.candidates(result.records)
    if not hosts:
        return
    total = min(len(hosts), _TAKEOVER_LIMIT)
    summary: StepSummary | None = None
    observer.on_step(StepEvent("start", "takeover", total=total))
    try:
        findings, notes = anyio.run(
            functools.partial(takeovercheck.scan, hosts, progress=_advance(observer, "takeover", total))
        )
        result.records.extend(findings)
        for note in notes:
            observer.on_note(Note("warn", f"Takeover: {note}"))
        hit = tuple(sorted({f.target.split("//", 1)[-1] for f in findings})[:3])
        summary = TakeoverSummary(checked=len(hosts), possible=len(findings), hosts=hit)
    except Exception as exc:  # noqa: BLE001 - a posture check must never fail the scan
        observer.on_note(Note("warn", f"Subdomain-takeover check failed: {exc}"))
    finally:
        observer.on_step(StepEvent("done", "takeover", summary=summary))


def rate_cves(result: PipelineResult, cache_dir: Path, observer: RunObserver) -> None:
    """Rate CVE findings by real-world exploitation (CISA KEV, EPSS, Exploit-DB)."""
    if not any(threatintel.cve_ids(r) for r in result.records if r.kind == "vuln"):
        return
    summary: StepSummary | None = None
    observer.on_step(StepEvent("start", "intel"))
    try:
        rated = anyio.run(threatintel.enrich, result.records, cache_dir)
        for error in rated.errors:
            observer.on_note(Note("warn", f"Threat intel — {error}"))
        summary = rated
    except Exception as exc:  # noqa: BLE001 - intel must never fail the scan
        observer.on_note(Note("warn", f"Threat intel failed: {exc}"))
    finally:
        observer.on_step(StepEvent("done", "intel", summary=summary))


def enrich_vt(result: PipelineResult, api_key: str, limit: int, observer: RunObserver) -> None:
    """Append VirusTotal reputation records for the run's discovered targets."""
    targets = vt.enrichment_targets(result.records)
    if not targets:
        return
    count = min(len(targets), limit)
    summary: StepSummary | None = None
    observer.on_step(StepEvent("start", "vt", total=count))
    try:
        reps = anyio.run(
            functools.partial(vt.enrich, targets, api_key, limit, progress=_advance(observer, "vt", count))
        )
        for index, rep in enumerate(reps, 1):
            result.records.append(validate_record("virustotal", json.dumps(rep.as_record()), index))
        summary = VtSummary(looked_up=len(reps), flagged=sum(1 for rep in reps if rep.flagged))
    except Exception as exc:  # noqa: BLE001 - enrichment must never fail the scan
        observer.on_note(Note("warn", f"VirusTotal enrichment failed: {exc}"))
    finally:
        observer.on_step(StepEvent("done", "vt", summary=summary))


def post_scan(
    result: PipelineResult,
    *,
    seed: str,
    settings: Settings,
    mail: bool,
    takeover: bool,
    intel: bool,
    vt_key: str | None,
    vt_limit: int,
    observer: RunObserver,
) -> None:
    """The checks after the scan, in order: TLS always, the others when asked for
    (VirusTotal only with a key). Each adds its records to ``result``."""
    check_tls(result, observer)
    if mail:
        check_mail(result, seed, observer)
    if takeover:
        check_takeover(result, observer)
    if intel:
        rate_cves(result, settings.cache_dir, observer)
    if vt_key:
        enrich_vt(result, vt_key, vt_limit, observer)
```

- [ ] **Step 5: Run them to see them pass**

Run: `uv run --quiet python -m pytest tests/unit/test_core_steps.py -q`
Expected: `13 passed`.

- [ ] **Step 6: The CLI runs the steps through the core and renders their events**

Save as `$W/task2_cli.py`:

```python
"""Task 2: the CLI runs the post-scan steps through cyberfw.core.steps and renders their events.

Usage: python task2_cli.py <repo root>   (then: ruff check --fix --select F401,I001 cyberfw/cli)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

RENDERERS = '''

def _print_note(note: Note) -> None:
    """A note from the core: a warning, or a muted aside."""
    style = "warn" if note.level == "warn" else "muted"
    console.print(f"[{style}]{escape(note.text)}[/{style}]")


def _print_step_start(event: StepEvent) -> None:
    """The lead-in a slow step prints before it starts, so a wait is never silent."""
    if event.step == "intel":
        console.print("[muted]Threat intel: checking CVEs against CISA KEV, EPSS and Exploit-DB…[/muted]")
    elif event.step == "vt":
        console.print(f"[muted]VirusTotal: looking up {event.total} target(s), throttled to 4/min…[/muted]")


def _print_step_summary(summary: StepSummary) -> None:
    """The line a finished step leaves on the console."""
    if isinstance(summary, TlsSummary):
        parts = [f"{summary.certificates} certificate(s)"]
        if summary.expired:
            parts.append(f"[err]{summary.expired} expired[/err]")
        if summary.soon:
            parts.append(f"[warn]{summary.soon} expire within {tlscheck.SOON_DAYS} days[/warn]")
        if summary.untrusted:
            parts.append(f"[warn]{summary.untrusted} untrusted or for another name[/warn]")
        if len(parts) == 1:
            parts.append(f"[ok]all valid for {tlscheck.SOON_DAYS}+ days[/ok]")
        console.print("TLS: " + " · ".join(parts))
    elif isinstance(summary, MailSummary):
        style = {"protected": "ok", "partial": "warn"}.get(summary.verdict, "err")
        reason = f" — {summary.worst}" if summary.worst else ""
        console.print(f"Email ({summary.domain}): [{style}]{summary.verdict}[/{style}]{reason}")
    elif isinstance(summary, TakeoverSummary):
        if summary.possible:
            hosts = escape(", ".join(summary.hosts))
            console.print(f"Subdomain takeover: [err]{summary.possible} possible[/err] — {hosts}")
        else:
            console.print(f"Subdomain takeover: [ok]none[/ok] in {summary.checked} host(s)")
    elif isinstance(summary, threatintel.IntelSummary):
        parts = [f"{summary.cves} CVE(s) in {summary.findings} finding(s)"]
        if summary.exploited:
            parts.append(f"[err]{summary.exploited} exploited in the wild (CISA KEV)[/err]")
        if summary.exploits:
            parts.append(f"{summary.exploits} with a public exploit")
        if summary.likely:
            parts.append(f"{summary.likely} with EPSS ≥ {threatintel.EPSS_HIGH:.0%}")
        console.print("Threat intel: " + " · ".join(parts))
    elif isinstance(summary, VtSummary):
        console.print(f"[muted]VirusTotal: {summary.looked_up} looked up, {summary.flagged} flagged.[/muted]")
'''

OBSERVER = '''#: Steps that show a live activity line while they run: its label and detail.
_ACTIVITIES = {
    "mail": ("Email {subject}", "SPF · DMARC · MX"),
    "takeover": ("Subdomain takeover", "dangling CNAMEs"),
    "intel": ("Rating CVEs", "KEV · EPSS · Exploit-DB"),
    "vt": ("VirusTotal", "free tier: 4 lookups/min"),
}


class _CliObserver(RunObserver):
    """Shows a run on the console: a live activity line while a slow step runs,
    the step's result line when it ends, and notes as warning or muted lines."""

    def __init__(self, *, animate: bool) -> None:
        self.animate = animate
        self._activity: motion.Activity | None = None

    def on_step(self, event: StepEvent) -> None:
        if event.kind == "start":
            _print_step_start(event)
            if event.step in _ACTIVITIES:
                label, detail = _ACTIVITIES[event.step]
                self._activity = motion.Activity(
                    console, label.format(subject=event.subject), animate=self.animate,
                    total=event.total, detail=detail,
                )
                self._activity.__enter__()
        elif event.kind == "advance":
            if self._activity is not None:
                self._activity.advance(event.done)
        else:
            if self._activity is not None:
                self._activity.__exit__(None, None, None)
                self._activity = None
            if event.summary is not None:
                _print_step_summary(event.summary)

    def on_note(self, note: Note) -> None:
        _print_note(note)


'''

views = Source(root, "cyberfw/cli/views.py")
views.replace("from cyberfw import motion, vt\n", "from cyberfw import motion, threatintel, vt\n")
views.replace(
    "from cyberfw.core.workspace import tool_state\n",
    "from cyberfw.core.events import MailSummary, Note, StepEvent, StepSummary, TakeoverSummary, TlsSummary, VtSummary\n"
    "from cyberfw.core.workspace import tool_state\n",
)
views.replace("from cyberfw.report import diff as rundiff\n",
              "from cyberfw.posture import tls as tlscheck\nfrom cyberfw.report import diff as rundiff\n")
views.replace("\n\ndef _plan_view(", RENDERERS + "\n\ndef _plan_view(")

scan = Source(root, "cyberfw/cli/scan.py")
scan.drop_defs("_check_tls", "_check_mail", "_check_takeover", "_enrich_with_intel", "_enrich_with_vt")
scan.replace(
    "    animate = settings.animations\n"
    "    _check_tls(result)\n"
    "    if mail:\n"
    "        _check_mail(result, target, animate=animate)\n"
    "    if takeover:\n"
    "        _check_takeover(result, animate=animate)\n"
    "    if intel:\n"
    "        _enrich_with_intel(result, settings.cache_dir, animate=animate)\n"
    "    if vt_key:\n"
    "        _enrich_with_vt(result, vt_key, vt_limit, animate=animate)\n",
    "    post_scan(\n"
    "        result, seed=target, settings=settings, mail=mail, takeover=takeover, intel=intel,\n"
    "        vt_key=vt_key, vt_limit=vt_limit, observer=_CliObserver(animate=settings.animations),\n"
    "    )\n",
)
scan.replace('@app.command("run")\n', OBSERVER + '@app.command("run")\n')
scan.replace(
    "from cyberfw.cli.views import _node_table, _plan_view, _print_changes, _record_table, _run_summary\n",
    "from cyberfw.cli.views import (\n"
    "    _node_table,\n    _plan_view,\n    _print_changes,\n    _print_note,\n    _print_step_start,\n"
    "    _print_step_summary,\n    _record_table,\n    _run_summary,\n)\n",
)
scan.replace(
    "from cyberfw.core.workspace import tool_state\n",
    "from cyberfw.core.events import Note, RunObserver, StepEvent\n"
    "from cyberfw.core.steps import post_scan\n"
    "from cyberfw.core.workspace import tool_state\n",
)

views.save()
scan.save()
```

```bash
uv run --quiet python "$W/task2_cli.py" .
uv run --quiet ruff check --fix --select F401,I001 cyberfw/cli
```

Expected: `edited cyberfw/cli/views.py`, `edited cyberfw/cli/scan.py`; `Found 7 errors (7 fixed, 0 remaining).`

- [ ] **Step 7: Run everything**

Run: `uv run --quiet python -m pytest -q`, `uv run --quiet ruff check .`, `uv run --quiet mypy cyberfw`
Expected: `1029 passed, 5 skipped, 8 deselected`; ruff clean; mypy `Success: no issues found in 70 source files`.

- [ ] **Step 8: The output changes in exactly the three intended lines**

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/2-steps" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -r "$W/transcripts/1-workspace" "$W/transcripts/2-steps" && echo identical
```

Expected: `36 passed`, then a diff of `pipeline-posture-failures.txt` only — no `identical`:
```text
8c8
< Email check failed: upstream
---
> Email check failed: upstream [down]
11c11
< Threat intel failed: upstream
---
> Threat intel failed: upstream [down]
13c13
< VirusTotal enrichment failed: upstream
---
> VirusTotal enrichment failed: upstream [down]
```

From here on, every task compares with `2-steps`.

- [ ] **Step 9: Commit**

```bash
git add cyberfw/core/events.py cyberfw/core/steps.py tests/unit/test_core_steps.py tests/conftest.py tests/unit/test_cli.py cyberfw/cli/views.py cyberfw/cli/scan.py
git commit -m "Run the checks after a scan in cyberfw/core/steps.py and report them as events"
```

---

### Task 3: Sessions and finishing a run move into the core

**Files:**
- Create: `cyberfw/core/sessions.py`, `cyberfw/core/finish.py`, `tests/unit/test_core_finish.py`
- Modify (by script): `cyberfw/cli/common.py`, `cyberfw/cli/views.py`, `cyberfw/cli/scan.py` (`task3_cli.py`)

**Interfaces:**
- Consumes: Task 2's `RunObserver`, `StepEvent`, `Note`, `_CliObserver`, `_print_step_summary`.
- Produces, in `cyberfw/core/sessions.py`: `Session(id: str, dir: Path, created: bool, context: SessionContext | None = None)`, `session_tag(kind, name) -> str`, `checked_session(session) -> str` (raises `ValueError`), `open_session(reports_dir, *, kind, name, session, stream) -> Session`, `discard_session(session_dir, *, created) -> bool`.
- Produces, in `cyberfw/core/finish.py`: `apply_triage(result, triage_file, observer)`, `run_info(manager, *, name, seed, session_id, tools) -> RunInfo`, `compare_with_earlier(result, run, reports_dir, explicit, observer) -> RunDiff | None` (sends the `compare` step), `write_reports(result, *, session_id, settings, run, changes=None) -> dict[str, Path]`, `Finished(run, changes, reports)`, `finalize(result, *, manager, settings, name, seed, tools, session, compare, baseline, save: bool | Callable[[], bool], observer) -> Finished` (raises `CyberfwError` when a report cannot be written).
- The CLI's `_session_tag`, `_discard_session`, `_write_reports`, `_apply_triage`, `_compare_with_earlier` and `_run_info` are gone; `_checked_session` wraps `checked_session`; `_print_step_summary` prints a `RunDiff` with `_print_changes(…, limit=8)`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_core_finish.py`:

```python
"""Sessions and finishing a run in cyberfw.core: triage, the comparison, keeping or discarding the reports."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cyberfw.config import Settings
from cyberfw.core.events import Note, RunObserver, StepEvent
from cyberfw.core.finish import Finished, finalize
from cyberfw.core.sessions import checked_session, discard_session, open_session, session_tag
from cyberfw.core.workspace import open_manager
from cyberfw.manager import ToolManager
from cyberfw.pipeline.engine import Node, NodeResult, PipelineResult
from cyberfw.pipeline.schemas import validate_record
from cyberfw.report.diff import RunDiff


class Recorder(RunObserver):
    """Keeps every step event and note, and the moment the save question came."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.notes: list[Note] = []
        self.changes: list[RunDiff] = []

    def on_step(self, event: StepEvent) -> None:
        self.events.append(f"{event.step}:{event.kind}")
        if isinstance(event.summary, RunDiff):
            self.changes.append(event.summary)

    def on_note(self, note: Note) -> None:
        self.events.append(f"note:{note.level}")
        self.notes.append(note)


@pytest.fixture
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    (tmp_path / "registry.yaml").write_text(
        "nuclei:\n  repo: org/nuclei\n  asset_patterns: []\n  binary: nuclei\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    return Settings(root_dir=tmp_path)


@pytest.fixture
def manager(settings: Settings) -> Iterator[ToolManager]:
    manager = open_manager(settings)
    yield manager
    manager.close()


pytestmark = pytest.mark.usefixtures("prints_nothing")


def _scan(minutes_ago: int, *findings: tuple[str, str]) -> PipelineResult:
    """A finished one-stage nuclei run with the given (template id, severity) findings."""
    started = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    records = [
        validate_record("nuclei", json.dumps({"template-id": template, "matched-at": "https://sub.example.com/",
                                              "info": {"name": template, "severity": severity}}), index)
        for index, (template, severity) in enumerate(findings, 1)
    ]
    node = Node(tool="nuclei", stage="vulns")
    return PipelineResult(nodes=[NodeResult(node=node, count=len(records))], records=records,
                          started_at=started, finished_at=started + timedelta(seconds=5))


def _finish(result: PipelineResult, settings: Settings, manager: ToolManager, seen: RunObserver, *,
            session: str | None = None, save: object = True, compare: bool = True) -> Finished:
    run_session = open_session(settings.reports_dir, kind="pipeline", name="scan", session=session, stream=True)
    return finalize(
        result, manager=manager, settings=settings, name="scan", seed="example.com", tools={"nuclei"},
        session=run_session, compare=compare, baseline=None, save=save, observer=seen,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize("name", ["scan-1", "nightly_run", "a.b"])
def test_a_plain_session_name_is_accepted(name: str) -> None:
    assert checked_session(name) == name


@pytest.mark.parametrize("name", [".", "..", "../x", "a/b", "a\\b", "C:x"])
def test_a_session_that_is_not_a_plain_name_is_refused(name: str) -> None:
    with pytest.raises(ValueError, match="plain directory name"):
        checked_session(name)


def test_a_fresh_session_is_named_after_its_run() -> None:
    assert session_tag("pipeline", "recon").startswith("pipeline-recon-20")


def test_an_existing_session_directory_is_never_removed(tmp_path: Path) -> None:
    (tmp_path / "earlier").mkdir()
    session = open_session(tmp_path, kind="run", name="x", session="earlier", stream=False)

    assert session.created is False and session.context is None
    assert discard_session(session.dir, created=session.created) is False
    assert (tmp_path / "earlier").is_dir()


def test_a_saved_run_writes_both_reports(settings: Settings, manager: ToolManager) -> None:
    seen = Recorder()

    finished = _finish(_scan(1, ("xss", "medium")), settings, manager, seen, session="kept")

    assert sorted(finished.reports) == ["html", "json"]
    assert all(path.is_file() for path in finished.reports.values())
    assert finished.run.session_id == "kept" and finished.run.seed == "example.com"
    assert seen.notes == []


def test_declining_removes_the_session_this_run_made(settings: Settings, manager: ToolManager) -> None:
    seen = Recorder()

    finished = _finish(_scan(1), settings, manager, seen, session="mine", save=False)

    assert finished.reports == {}
    assert not (settings.reports_dir / "mine").exists()
    assert seen.notes == [Note("info", "report not saved")]


def test_declining_leaves_an_earlier_session_alone(settings: Settings, manager: ToolManager) -> None:
    (settings.reports_dir / "earlier").mkdir(parents=True)
    seen = Recorder()

    _finish(_scan(1), settings, manager, seen, session="earlier", save=False)

    assert (settings.reports_dir / "earlier").is_dir()
    assert seen.notes == [Note("info", f"report not saved; {settings.reports_dir / 'earlier'} was left as it was")]


def test_the_save_question_comes_after_the_comparison(settings: Settings, manager: ToolManager) -> None:
    _finish(_scan(10, ("xss", "medium")), settings, manager, Recorder(), session="first")
    seen = Recorder()

    def ask() -> bool:
        seen.events.append("asked")
        return True

    finished = _finish(_scan(1, ("xss", "medium"), ("sqli", "high")), settings, manager, seen, save=ask)

    assert seen.events == ["compare:start", "compare:done", "asked"]
    assert seen.changes == [finished.changes]
    assert finished.changes is not None and finished.changes.new_findings_at_least("high") == 1


def test_a_first_scan_or_no_comparison_sends_no_compare_events(settings: Settings, manager: ToolManager) -> None:
    first, unasked = Recorder(), Recorder()

    _finish(_scan(10, ("xss", "medium")), settings, manager, first)
    finished = _finish(_scan(1, ("xss", "medium")), settings, manager, unasked, compare=False)

    assert first.events == [] and unasked.events == []
    assert finished.changes is None


def test_muted_findings_are_noted(settings: Settings, manager: ToolManager) -> None:
    settings.triage_file.parent.mkdir(parents=True, exist_ok=True)
    settings.triage_file.write_text("mutes:\n  - {id: m1, template: xss, reason: false_positive}\n", encoding="utf-8")
    seen = Recorder()

    _finish(_scan(1, ("xss", "medium")), settings, manager, seen, save=False)

    assert seen.notes[0].level == "info" and seen.notes[0].text.startswith("Triage: 1 finding(s) muted")
```

- [ ] **Step 2: Run them to see them fail**

Run: `uv run --quiet python -m pytest tests/unit/test_core_finish.py -q`
Expected: collection error — `ModuleNotFoundError: No module named 'cyberfw.core.finish'`.

- [ ] **Step 3: Create sessions and finishing**

Create `cyberfw/core/sessions.py`:

```python
"""A run's session: its id, its directory under ``reports/``, and whether this run made it."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from time import strftime

from cyberfw.pipeline.context import SessionContext


@dataclass
class Session:
    """Where a run keeps its records and reports."""

    id: str
    dir: Path
    #: True when this run made ``dir``: declining to save may then remove it.
    created: bool
    #: The store records stream into as they arrive; ``None`` when they are kept in memory.
    context: SessionContext | None = None


def session_tag(kind: str, name: str) -> str:
    """A fresh session id: ``<kind>-<name>-<YYYYmmdd-HHMMSS>``."""
    return f"{kind}-{name}-{strftime('%Y%m%d-%H%M%S')}"


def checked_session(session: str) -> str:
    """Accept a session only as a plain directory name under ``reports/``.

    It is joined onto the reports directory, and a session this run created is
    removed when the user declines to save — so ``../x``, ``a/b`` or ``C:x``
    must never get as far as a path. Anything else raises :class:`ValueError`.
    """
    if session in {".", ".."} or any(ch in session for ch in "/\\:"):
        raise ValueError(f"a session must be a plain directory name under reports/, got {session!r}")
    return session


def open_session(reports_dir: Path, *, kind: str, name: str, session: str | None, stream: bool) -> Session:
    """The run's session: the id given, else a fresh one. With ``stream`` its
    records go to disk as they arrive (crash-safe); without, nothing is written yet."""
    session_id = session or session_tag(kind, name)
    session_dir = reports_dir / session_id
    created = not session_dir.exists()
    context = SessionContext(reports_dir, session_id) if stream else None
    return Session(id=session_id, dir=session_dir, created=created, context=context)


def discard_session(session_dir: Path, *, created: bool) -> bool:
    """Remove a session directory this run created; never touch a pre-existing one.
    True when it was removed."""
    if not created:
        return False
    shutil.rmtree(session_dir, ignore_errors=True)
    return True
```

Create `cyberfw/core/finish.py`:

```python
"""Finishing a run without printing: triage, its facts, the comparison with an
earlier run, and keeping its reports — or removing the session it made."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cyberfw import triage
from cyberfw.config import Settings
from cyberfw.core.events import Note, RunObserver, StepEvent
from cyberfw.core.sessions import Session, discard_session
from cyberfw.manager import ToolManager
from cyberfw.pipeline.engine import PipelineResult
from cyberfw.report import diff as rundiff
from cyberfw.report.diff import RunDiff
from cyberfw.report.html_report import generate_html_report
from cyberfw.report.json_report import generate_json_report, report_payload
from cyberfw.report.run_info import RunInfo


def apply_triage(result: PipelineResult, triage_file: Path, observer: RunObserver) -> None:
    """Silence findings the triage file has muted, and say how many."""
    try:
        rules = triage.load_rules(triage_file)
    except triage.TriageError as exc:
        observer.on_note(Note("warn", f"Triage skipped — {exc}"))
        return
    if not rules:
        return
    summary = triage.apply(result.records, rules)
    if summary.muted:
        observer.on_note(Note("info", f"Triage: {summary.line()}"))
    if summary.expired:
        observer.on_note(Note("warn", f"Triage: {len(summary.expired)} rule(s) expired — {', '.join(summary.expired)}"))


def run_info(manager: ToolManager, *, name: str, seed: str | None, session_id: str, tools: set[str]) -> RunInfo:
    """The facts a report records about its run: what ran, against what, where, with which versions."""
    return RunInfo(
        pipeline=name,
        seed=seed,
        session_id=session_id,
        platform=manager.mapping.label,
        tool_versions={tool: (manager.install_state(tool) or {}).get("version") for tool in sorted(tools)},
    )


def compare_with_earlier(
    result: PipelineResult, run: RunInfo, reports_dir: Path, explicit: str | None, observer: RunObserver
) -> RunDiff | None:
    """Compare this run with an earlier one — the one named, else the newest
    earlier run of the same pipeline and seed. A first scan has nothing to compare
    with and sends no events; the changes go out with the ``compare`` step's ``done``."""
    try:
        if explicit:
            path: Path | None = rundiff.resolve_report(explicit, reports_dir)
        else:
            path = rundiff.find_baseline(reports_dir, seed=run.seed, pipeline=run.pipeline, before=result.started_at)
    except (FileNotFoundError, ValueError) as exc:
        observer.on_note(Note("warn", f"Not compared with an earlier run: {exc}"))
        return None
    if path is None:
        return None
    changes: RunDiff | None = None
    observer.on_step(StepEvent("start", "compare"))
    try:
        changes = rundiff.compare(rundiff.load_report(path), report_payload(result, run))
    except (FileNotFoundError, ValueError) as exc:
        observer.on_note(Note("warn", f"Not compared with an earlier run: {exc}"))
    finally:
        observer.on_step(StepEvent("done", "compare", summary=changes))
    return changes


def write_reports(
    result: PipelineResult, *, session_id: str, settings: Settings, run: RunInfo, changes: RunDiff | None = None
) -> dict[str, Path]:
    """Render both reports into the session directory: ``{"json": path, "html": path}``."""
    json_path = generate_json_report(
        result, session_id=session_id, reports_dir=settings.reports_dir, run=run, changes=changes
    )
    html_path = generate_html_report(
        result, session_id=session_id, reports_dir=settings.reports_dir, run=run, changes=changes
    )
    return {"json": json_path, "html": html_path}


@dataclass
class Finished:
    """What finishing a run left: its facts, what changed since the earlier run, the reports."""

    run: RunInfo
    changes: RunDiff | None
    #: The reports written, by format (``json``, ``html``); empty when the run was not saved.
    reports: dict[str, Path]


def finalize(
    result: PipelineResult,
    *,
    manager: ToolManager,
    settings: Settings,
    name: str,
    seed: str | None,
    tools: set[str],
    session: Session,
    compare: bool,
    baseline: str | None,
    save: bool | Callable[[], bool],
    observer: RunObserver,
) -> Finished:
    """Finish a pipeline run: triage, the run's facts, the comparison with an
    earlier run — then keep the reports, or remove the session if this run made it.

    A callable ``save`` is asked after the comparison and before anything is
    written. A report that cannot be written raises :class:`CyberfwError`.
    """
    apply_triage(result, settings.triage_file, observer)
    run = run_info(manager, name=name, seed=seed, session_id=session.id, tools=tools)
    changes = compare_with_earlier(result, run, settings.reports_dir, baseline, observer) if compare else None
    if session.context is not None:
        session.context.close()
    if not (save() if callable(save) else save):
        if discard_session(session.dir, created=session.created):
            observer.on_note(Note("info", "report not saved"))
        else:
            observer.on_note(Note("info", f"report not saved; {session.dir} was left as it was"))
        return Finished(run=run, changes=changes, reports={})
    reports = write_reports(result, session_id=session.id, settings=settings, run=run, changes=changes)
    return Finished(run=run, changes=changes, reports=reports)
```

- [ ] **Step 4: Run them to see them pass**

Run: `uv run --quiet python -m pytest tests/unit/test_core_finish.py -q`
Expected: `17 passed`.

- [ ] **Step 5: Prove `prints_nothing` must detach the log handlers**

Saving a report logs `INFO … report written`; once a CLI test has set up logging in the process, that line reaches stdout.

```bash
cp tests/conftest.py "$W/conftest.keep"
uv run --quiet python -c "from pathlib import Path; p = Path('tests/conftest.py'); t = p.read_text(encoding='utf-8'); old = '    monkeypatch.setattr(logging.getLogger(\"cyberfw\"), \"handlers\", [])\n'; assert t.count(old) == 1; p.write_text(t.replace(old, ''), encoding='utf-8', newline='\n')"
uv run --quiet python -m pytest tests/unit/test_cli.py::TestInventoryPresentation::test_status_opens_with_the_readiness_summary tests/unit/test_core_finish.py -q
cp "$W/conftest.keep" tests/conftest.py
```

Expected: `18 passed, 3 errors` — the three tests that save reports; after the `cp`, `tests/conftest.py` is back.

- [ ] **Step 6: The CLI opens sessions and finishes runs through the core**

Save as `$W/task3_cli.py`:

```python
"""Task 3: the CLI opens sessions and finishes runs through cyberfw.core.

Usage: python task3_cli.py <repo root>   (then: ruff check --fix --select F401,I001 cyberfw/cli)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

CHECKED_SESSION = '''

def _checked_session(session: str) -> str:
    """``--session`` as a plain directory name under ``reports/``, else a usage error (exit 2)."""
    try:
        return checked_session(session)
    except ValueError:
        console.print(f"[err]--session must be a plain directory name under reports/, got {session!r}.[/err]")
        raise typer.Exit(2) from None
'''

common = Source(root, "cyberfw/cli/common.py")
common.drop_defs("_session_tag", "_checked_session")
common.replace("\n\ndef _tool_version(", CHECKED_SESSION + "\n\ndef _tool_version(")
common.replace(
    "from cyberfw.core.workspace import open_manager, tool_state\n",
    "from cyberfw.core.sessions import checked_session\nfrom cyberfw.core.workspace import open_manager, tool_state\n",
)

views = Source(root, "cyberfw/cli/views.py")
views.replace(
    '        console.print(f"[muted]VirusTotal: {summary.looked_up} looked up, {summary.flagged} flagged.[/muted]")\n',
    '        console.print(f"[muted]VirusTotal: {summary.looked_up} looked up, {summary.flagged} flagged.[/muted]")\n'
    "    elif isinstance(summary, rundiff.RunDiff):\n"
    "        _print_changes(summary, limit=8)\n",
)

scan = Source(root, "cyberfw/cli/scan.py")
scan.drop_defs("_discard_session", "_write_reports", "_apply_triage", "_compare_with_earlier", "_run_info")
scan.replace("    _session_tag,\n", "")
scan.replace(
    "from cyberfw.core.steps import post_scan\n",
    "from cyberfw.core.finish import finalize, run_info, write_reports\n"
    "from cyberfw.core.sessions import open_session\n"
    "from cyberfw.core.steps import post_scan\n",
)

# run: the session, closing the store, archiving and writing the reports.
scan.replace('    session_id = session or _session_tag("run", tool)\n', "")
scan.replace(
    "    context = SessionContext(settings.reports_dir, session_id) if save else None\n"
    "    engine = PipelineEngine(settings, manager, context=context)\n",
    '    run_session = open_session(settings.reports_dir, kind="run", name=tool, session=session, stream=bool(save))\n'
    "    engine = PipelineEngine(settings, manager, context=run_session.context)\n",
)
scan.replace(
    "    if context is not None:\n        context.close()\n",
    "    if run_session.context is not None:\n        run_session.context.close()\n",
)
scan.replace(
    "        if context is None:\n"
    "            # Nothing was streamed, so archive the records now.\n"
    "            with SessionContext(settings.reports_dir, session_id) as store:\n",
    "        if run_session.context is None:\n"
    "            # Nothing was streamed, so archive the records now.\n"
    "            with SessionContext(settings.reports_dir, run_session.id) as store:\n",
)
scan.replace(
    "        written = _write_reports(\n"
    "            result,\n"
    "            session_id=session_id,\n"
    "            settings=settings,\n"
    "            run=_run_info(manager, name=tool, seed=target, session_id=session_id, tools={tool}),\n"
    "        )\n"
    '        console.print(f"[ok]saved:[/ok] {settings.reports_dir / session_id}")\n'
    "        for label, path in written:\n",
    "        written = write_reports(\n"
    "            result,\n"
    "            session_id=run_session.id,\n"
    "            settings=settings,\n"
    "            run=run_info(manager, name=tool, seed=target, session_id=run_session.id, tools={tool}),\n"
    "        )\n"
    '        console.print(f"[ok]saved:[/ok] {run_session.dir}")\n'
    "        for label, path in written.items():\n",
)

# pipeline: the session, then triage / comparison / save-or-discard through finalize.
scan.replace(
    '    session_id = session or _session_tag("pipeline", name)\n'
    "    # Remember whether the directory is ours: declining to save may remove it,\n"
    "    # and a --session pointing at an earlier run must never be deleted.\n"
    "    session_dir = settings.reports_dir / session_id\n"
    "    session_is_new = not session_dir.exists()\n"
    "    context = SessionContext(settings.reports_dir, session_id)\n"
    "    # The pre-flight above already reported any missing optional dependency.\n"
    "    engine = PipelineEngine(settings, manager, context=context, report_missing_deps=False)\n",
    "    # The session knows whether its directory is ours: declining to save may\n"
    "    # remove it, and a --session pointing at an earlier run must never be deleted.\n"
    '    run_session = open_session(settings.reports_dir, kind="pipeline", name=name, session=session, stream=True)\n'
    "    # The pre-flight above already reported any missing optional dependency.\n"
    "    engine = PipelineEngine(settings, manager, context=run_session.context, report_missing_deps=False)\n",
)
scan.replace(
    "    post_scan(\n"
    "        result, seed=target, settings=settings, mail=mail, takeover=takeover, intel=intel,\n"
    "        vt_key=vt_key, vt_limit=vt_limit, observer=_CliObserver(animate=settings.animations),\n"
    "    )\n"
    "\n"
    "    _apply_triage(result, settings.triage_file)\n"
    "    run_info = _run_info(manager, name=name, seed=target, session_id=session_id, tools={n.tool for n in nodes})\n"
    "    changes = None if no_baseline else _compare_with_earlier(result, run_info, settings.reports_dir, baseline)\n"
    "\n"
    "    if verbose:\n"
    "        console.print(_node_table(result))\n"
    "\n"
    "    context.close()\n"
    "    written: list[tuple[str, Path]] = []\n"
    "    if _wants_to_save(report, default=True, what=name):\n"
    "        try:\n"
    "            written = _write_reports(\n"
    "                result, session_id=session_id, settings=settings, run=run_info, changes=changes\n"
    "            )\n"
    "        except CyberfwError as exc:\n"
    '            console.print(f"[err]report failed:[/err] {exc}")\n'
    "            return\n"
    "    else:\n"
    "        _discard_session(session_dir, created=session_is_new)\n",
    "    observer = _CliObserver(animate=settings.animations)\n"
    "    post_scan(\n"
    "        result, seed=target, settings=settings, mail=mail, takeover=takeover, intel=intel,\n"
    "        vt_key=vt_key, vt_limit=vt_limit, observer=observer,\n"
    "    )\n"
    "\n"
    "    def _decide() -> bool:\n"
    "        # Asked once the comparison is on screen; the raw stream's stage table comes first.\n"
    "        if verbose:\n"
    "            console.print(_node_table(result))\n"
    "        return _wants_to_save(report, default=True, what=name)\n"
    "\n"
    "    try:\n"
    "        finished = finalize(\n"
    "            result, manager=manager, settings=settings, name=name, seed=target,\n"
    "            tools={n.tool for n in nodes}, session=run_session, compare=not no_baseline,\n"
    "            baseline=baseline, save=_decide, observer=observer,\n"
    "        )\n"
    "    except CyberfwError as exc:\n"
    '        console.print(f"[err]report failed:[/err] {exc}")\n'
    "        return\n"
    "    changes = finished.changes\n"
    "    written = list(finished.reports.items())\n",
)
scan.replace(
    "            result, name=name, session_id=session_id, reports=written, progress=progress\n",
    "            result, name=name, session_id=run_session.id, reports=written, progress=progress\n",
)

for source in (common, views, scan):
    source.save()
```

```bash
uv run --quiet python "$W/task3_cli.py" .
uv run --quiet ruff check --fix --select F401,I001 cyberfw/cli
```

Expected: `edited cyberfw/cli/common.py`, `…/views.py`, `…/scan.py`; `Found 7 errors (7 fixed, 0 remaining).`

- [ ] **Step 7: Run everything**

Run: `uv run --quiet python -m pytest -q`, `uv run --quiet ruff check .`, `uv run --quiet mypy cyberfw`
Expected: `1046 passed, 5 skipped, 8 deselected`; ruff clean; mypy `Success: no issues found in 72 source files`.

- [ ] **Step 8: The output is unchanged**

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/3-finish" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -r "$W/transcripts/2-steps" "$W/transcripts/3-finish" && echo identical
```

Expected: `36 passed`, then `identical`.

- [ ] **Step 9: Commit**

```bash
git add cyberfw/core/sessions.py cyberfw/core/finish.py tests/unit/test_core_finish.py cyberfw/cli
git commit -m "Open sessions and finish runs in cyberfw/core: triage, comparison, save or discard"
```

---

### Task 4: Preparing and running a pipeline move into the core

**Files:**
- Create: `cyberfw/core/scan.py`, `tests/unit/test_core_pipeline.py`
- Modify (by script): `cyberfw/cli/scan.py`, `cyberfw/cli/views.py`, `tests/unit/test_cli.py` (`task4_cli.py`)

**Interfaces:**
- Consumes: Task 3's `Session` / `open_session`, `finalize`; Task 1's `tool_state`.
- Produces, in `cyberfw/core/scan.py`: `PreparedPipeline(name, target, nodes, blocking, warnings, states, settings, manager)` with `.ready`; `resolve_gowitness(flag, manager, tools_dir) -> bool`; `prepare_pipeline(name, target, *, settings, manager, ffuf=False, gowitness=None, max_httpx=0) -> PreparedPipeline` (raises `RegistryError`); `choose_wordlist(settings, wordlist, *, ffuf, observer) -> str | None`; `wire_observer(engine, observer)`; `execute_pipeline(prepared, *, session, wordlist, observer) -> PipelineResult` (sends the `scan` step, closes the manager, notes out-of-scope hosts).
- `_CliObserver(animate, view=None, echo_output=False, fps=4)` now opens the live view on `scan` / `start` and leaves its final frame on `scan` / `done`; `_plan_view(prepared: PreparedPipeline)`. The CLI's `_preflight` and `_resolve_gowitness` are gone (tests read `cli.resolve_gowitness`).

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_core_pipeline.py`:

```python
"""Preparing and running a pipeline in cyberfw.core, against the fake tools the CLI tests use."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from cyberfw.config import Settings
from cyberfw.core import scan
from cyberfw.core.events import Note, RunObserver, StepEvent
from cyberfw.core.scan import choose_wordlist, execute_pipeline, prepare_pipeline
from cyberfw.core.sessions import open_session
from cyberfw.core.workspace import open_manager
from cyberfw.exceptions import CyberfwError, RegistryError
from cyberfw.manager import ToolManager
from cyberfw.pipeline.engine import PipelineEngine, StageEvent
from cyberfw.pipeline.schemas import ToolRecord

from .test_cli import _write_fake_binaries, _write_registry

pytestmark = pytest.mark.usefixtures("prints_nothing")


class Recorder(RunObserver):
    """Everything the run sends, in order, as short labels."""

    def __init__(self) -> None:
        self.log: list[str] = []
        self.records: list[ToolRecord] = []
        self.notes: list[Note] = []

    def on_stage(self, event: StageEvent) -> None:
        self.log.append(f"stage:{event.stage}:{event.kind}")

    def on_record(self, record: ToolRecord) -> None:
        self.records.append(record)

    def on_output(self, line: str, stream: str) -> None:
        self.log.append(f"output:{stream}")

    def on_step(self, event: StepEvent) -> None:
        self.log.append(f"{event.step}:{event.kind}")

    def on_note(self, note: Note) -> None:
        self.log.append(f"note:{note.level}")
        self.notes.append(note)


@pytest.fixture
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    _write_fake_binaries(tmp_path / "tools_bin")
    _write_registry(tmp_path)
    monkeypatch.chdir(tmp_path)
    return Settings(root_dir=tmp_path)


@pytest.fixture
def manager(settings: Settings) -> Iterator[ToolManager]:
    manager = open_manager(settings)
    yield manager
    manager.close()


def test_an_unknown_pipeline_is_a_registry_error(settings: Settings, manager: ToolManager) -> None:
    with pytest.raises(RegistryError):
        prepare_pipeline("no-such-pipeline", "example.com", settings=settings, manager=manager)


def test_a_ready_pipeline_lists_its_stages_and_their_tools(settings: Settings, manager: ToolManager) -> None:
    prepared = prepare_pipeline("recon-to-vuln", "example.com", settings=settings, manager=manager)

    assert [node.tool for node in prepared.nodes] == ["subfinder", "httpx", "nuclei"]
    assert prepared.states == {"subfinder": "ready", "httpx": "ready", "nuclei": "ready"}
    assert prepared.ready and prepared.blocking == [] and prepared.warnings == []


def test_a_missing_binary_blocks_its_stage(settings: Settings, manager: ToolManager) -> None:
    (settings.tools_dir / "nuclei").unlink()

    prepared = prepare_pipeline("recon-to-vuln", "example.com", settings=settings, manager=manager)

    assert prepared.blocking == [("vulns", "nuclei", "not installed")]
    assert prepared.states["nuclei"] == "not installed" and not prepared.ready


def test_a_missing_optional_dependency_is_only_a_warning(
    settings: Settings, manager: ToolManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(manager.spec("subfinder"), "check_deps", ["nmap"])
    monkeypatch.setattr(scan.shutil, "which", lambda _name: None)

    prepared = prepare_pipeline("recon-to-vuln", "example.com", settings=settings, manager=manager)

    assert prepared.ready
    assert len(prepared.warnings) == 1 and prepared.warnings[0].startswith("subfinder works best with `nmap`")


def test_the_scan_is_a_step_around_every_stage_event(settings: Settings, manager: ToolManager) -> None:
    prepared = prepare_pipeline("recon-to-vuln", "example.com", settings=settings, manager=manager)
    session = open_session(settings.reports_dir, kind="pipeline", name="recon-to-vuln", session="s", stream=True)
    seen = Recorder()

    result = execute_pipeline(prepared, session=session, wordlist=None, observer=seen)

    assert seen.log[0] == "scan:start" and seen.log[-1] == "scan:done"
    assert "stage:vulns:done" in seen.log and "output:stdout" in seen.log
    assert [record.tool for record in seen.records] == [record.tool for record in result.records]
    assert result.succeeded() and len(result.records) == 3


def test_hosts_kept_out_of_scope_are_noted_after_the_scan(
    settings: Settings, manager: ToolManager
) -> None:
    scoped = settings.model_copy(update={"exclude": ["sub.example.com"]})
    prepared = prepare_pipeline("recon-to-vuln", "example.com", settings=scoped, manager=manager)
    session = open_session(scoped.reports_dir, kind="pipeline", name="recon-to-vuln", session=None, stream=True)
    seen = Recorder()

    execute_pipeline(prepared, session=session, wordlist=None, observer=seen)

    assert seen.log[-2:] == ["scan:done", "note:info"]
    assert seen.notes == [Note("info", "scope: 1 host(s) excluded")]


def test_a_failing_engine_still_ends_the_scan_and_closes_the_manager(
    settings: Settings, manager: ToolManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(self: PipelineEngine, *_a: object, **_k: object) -> object:
        raise CyberfwError("the engine broke")

    closed: list[bool] = []
    monkeypatch.setattr(PipelineEngine, "run", broken)
    monkeypatch.setattr(manager, "close", lambda: closed.append(True))
    prepared = prepare_pipeline("recon-to-vuln", "example.com", settings=settings, manager=manager)
    session = open_session(settings.reports_dir, kind="pipeline", name="recon-to-vuln", session=None, stream=True)
    seen = Recorder()

    with pytest.raises(CyberfwError, match="the engine broke"):
        execute_pipeline(prepared, session=session, wordlist=None, observer=seen)

    assert seen.log == ["scan:start", "scan:done"] and closed == [True]


def test_a_given_wordlist_is_used_as_is(settings: Settings) -> None:
    seen = Recorder()

    assert choose_wordlist(settings, "mine.txt", ffuf=True, observer=seen) == "mine.txt"
    assert seen.notes == []


def test_ffuf_without_a_wordlist_says_which_list_it_falls_back_to(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    (settings.root_dir / "wordlists").mkdir()
    (settings.root_dir / "wordlists" / "common.txt").write_text("admin\n", encoding="utf-8")
    seen = Recorder()

    assert choose_wordlist(settings, None, ffuf=True, observer=seen) is None
    assert seen.notes[0] == Note(
        "info", "--ffuf: no wordlist given, using the bundled common.txt (pass --wordlist <path> to override)"
    )

    monkeypatch.setattr(scan, "default_wordlist", lambda: None)
    choose_wordlist(settings, None, ffuf=True, observer=seen)
    assert seen.notes[1].level == "warn" and "the fuzz stage will be skipped" in seen.notes[1].text
```

- [ ] **Step 2: Run them to see them fail**

Run: `uv run --quiet python -m pytest tests/unit/test_core_pipeline.py -q`
Expected: collection error — `ImportError: cannot import name 'scan' from 'cyberfw.core'`.

- [ ] **Step 3: Create the pipeline module**

Create `cyberfw/core/scan.py`:

```python
"""Preparing and running a pipeline scan without printing.

:func:`prepare_pipeline` builds the stages and checks them before anything
runs — what blocks a stage, what only weakens it; :func:`execute_pipeline` runs
them, sending every stage, record and output line to the observer, with the scan
itself as a ``scan`` step around them.
"""

from __future__ import annotations

import functools
import shutil
from dataclasses import dataclass
from pathlib import Path

import anyio

from cyberfw.config import Settings
from cyberfw.core.events import Note, RunObserver, StepEvent
from cyberfw.core.sessions import Session
from cyberfw.core.workspace import tool_state
from cyberfw.manager import ToolManager
from cyberfw.pipeline.engine import (
    Node,
    PipelineEngine,
    PipelineResult,
    StageEvent,
    dependency_hint,
)
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.pipelines import build
from cyberfw.resources import default_wordlist
from cyberfw.tools import adapter_class


@dataclass
class PreparedPipeline:
    """A pipeline ready to run — or to show as a plan: its stages and what stands in their way."""

    name: str
    target: str | None
    nodes: list[Node]
    #: ``(stage, tool, reason)`` for each stage that cannot run as things stand.
    blocking: list[tuple[str, str, str]]
    #: Missing optional dependencies: they cost capability, not the run.
    warnings: list[str]
    #: ``ready`` / ``blocked`` / ``not installed`` for each tool the stages use.
    states: dict[str, str]
    settings: Settings
    manager: ToolManager

    @property
    def ready(self) -> bool:
        return not self.blocking


def resolve_gowitness(flag: bool | None, manager: ToolManager, tools_dir: Path) -> bool:
    """Whether recon-to-vuln should run gowitness.

    An explicit ``--gowitness`` / ``--no-gowitness`` is taken as given. The
    vanilla default (``None``) includes it only when it can actually run —
    registered, installed, and a Chrome/Chromium present — so a plain run gains
    screenshots where possible and never fails for the lack of a browser."""
    if flag is not None:
        return flag
    from cyberfw.tools.gowitness import _find_chrome

    return (
        "gowitness" in manager.registry.names()
        and manager.is_installed("gowitness")
        and _find_chrome(tools_dir) is not None
    )


def _preflight(
    manager: ToolManager, nodes: list[Node], tools_dir: Path
) -> tuple[list[tuple[str, str, str]], list[str], dict[str, str]]:
    """What stands between this plan and a useful run, in plan order.

    Returns ``(blocking, warnings, states)``. Blocking: a binary that cannot run,
    or a hard external requirement the adapter reports missing (gowitness without
    Chrome) — the stage could only fail. Warnings: a ``check_deps`` entry that is
    not on PATH (RustScan's Nmap), which costs capability, not the run.
    """
    blocking: list[tuple[str, str, str]] = []
    warnings: list[str] = []
    states: dict[str, str] = {}
    for node in nodes:
        if node.tool in states:
            continue
        state = states[node.tool] = tool_state(manager, node.tool, tools_dir)
        if state != "ready":
            blocking.append((node.stage, node.tool, state))
            continue
        requirement = adapter_class(node.tool).missing_requirement(tools_dir)
        if requirement is not None:
            blocking.append((node.stage, node.tool, requirement))
        for dep in manager.spec(node.tool).check_deps:
            if shutil.which(dep) is None:
                warnings.append(
                    f"{node.tool} works best with `{dep}`, which is not on PATH — {dependency_hint(dep)}"
                )
    return blocking, warnings, states


def prepare_pipeline(
    name: str,
    target: str | None,
    *,
    settings: Settings,
    manager: ToolManager,
    ffuf: bool = False,
    gowitness: bool | None = None,
    max_httpx: int = 0,
) -> PreparedPipeline:
    """Build the pipeline's stages and check them before anything runs.

    Every tool must be registered and have an adapter — a YAML pipeline may name
    one the registry (or the code) lacks — else :class:`RegistryError`. Then each
    tool's state, what blocks a stage and what only weakens it.
    """
    nodes = build(
        name,
        pipelines_dir=settings.pipelines_dir,
        include_ffuf=ffuf,
        include_gowitness=resolve_gowitness(gowitness, manager, settings.tools_dir),
        max_httpx=max_httpx,
    )
    for node in nodes:
        manager.spec(node.tool)
        adapter_class(node.tool)
    blocking, warnings, states = _preflight(manager, nodes, settings.tools_dir)
    return PreparedPipeline(
        name=name, target=target, nodes=nodes, blocking=blocking, warnings=warnings, states=states,
        settings=settings, manager=manager,
    )


def choose_wordlist(settings: Settings, wordlist: str | None, *, ffuf: bool, observer: RunObserver) -> str | None:
    """The wordlist every stage is offered: the one given, else the configured one.

    With ``ffuf`` and neither, the fuzz stage falls back to the bundled list — the
    note says which, or that there is none and the stage will be skipped."""
    chosen = wordlist or settings.wordlist
    if ffuf and not chosen:
        bundled = default_wordlist()
        if bundled is not None:
            observer.on_note(Note(
                "info", f"--ffuf: no wordlist given, using the bundled {bundled.name} (pass --wordlist <path> to override)"
            ))
        else:
            observer.on_note(Note(
                "warn",
                "--ffuf needs a wordlist and the bundled default was not found; "
                "the fuzz stage will be skipped. Re-run with --wordlist <path>.",
            ))
    return chosen


def wire_observer(engine: PipelineEngine, observer: RunObserver) -> None:
    """Send the engine's stage, record and raw-output callbacks to ``observer``."""

    async def on_stage(event: StageEvent) -> None:
        observer.on_stage(event)

    async def on_record(record: ToolRecord) -> None:
        observer.on_record(record)

    async def on_stdout(line: str) -> None:
        observer.on_output(line, "stdout")

    async def on_stderr(line: str) -> None:
        observer.on_output(line, "stderr")

    engine.set_stage_callback(on_stage)
    engine.set_record_callback(on_record)
    engine.set_stdout_raw_callback(on_stdout)
    engine.set_stderr_callback(on_stderr)


def execute_pipeline(
    prepared: PreparedPipeline, *, session: Session, wordlist: str | None, observer: RunObserver
) -> PipelineResult:
    """Run the prepared stages, streaming every stage, record and output line to the observer.

    The scan is a step of its own: ``start`` before the engine runs and ``done``
    after it — also when it raises — then a note for any hosts kept out of scope.
    The tool manager is closed once the stages have run.
    """
    # The pre-flight already reported any missing optional dependency.
    engine = PipelineEngine(prepared.settings, prepared.manager, context=session.context, report_missing_deps=False)
    wire_observer(engine, observer)
    observer.on_step(StepEvent("start", "scan"))
    try:
        result = anyio.run(functools.partial(engine.run, extra_input=wordlist), prepared.nodes, prepared.target)
    finally:
        prepared.manager.close()
        observer.on_step(StepEvent("done", "scan"))
    if result.excluded:
        observer.on_note(Note("info", f"scope: {len(result.excluded)} host(s) excluded"))
    return result
```

- [ ] **Step 4: Run them to see them pass**

Run: `uv run --quiet python -m pytest tests/unit/test_core_pipeline.py -q`
Expected: `9 passed`.

- [ ] **Step 5: `cyberfw pipeline` prepares and runs through the core; its observer draws the scan**

Save as `$W/task4_cli.py`:

```python
"""Task 4: `cyberfw pipeline` prepares and runs through cyberfw.core; the observer drives the live view.

Usage: python task4_cli.py <repo root>   (then: ruff check --fix --select F401,I001 cyberfw/cli)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

OBSERVER = '''#: Steps that show a live activity line while they run: its label and detail.
_ACTIVITIES = {
    "mail": ("Email {subject}", "SPF · DMARC · MX"),
    "takeover": ("Subdomain takeover", "dangling CNAMEs"),
    "intel": ("Rating CVEs", "KEV · EPSS · Exploit-DB"),
    "vt": ("VirusTotal", "free tier: 4 lookups/min"),
}


class _CliObserver(RunObserver):
    """Shows a run on the console.

    During the scan, stages and records go to the live view when there is one.
    The view IS the final frame, so it is not reprinted afterwards: Live leaves
    its last frame on screen, and on a non-TTY (CI, a pipe) Rich prints that
    frame once instead of redrawing. Both views are renderables driven by
    auto-refresh, so spinners, bars, timers and the growth pulse animate between
    events — events only change their state. With ``echo_output`` the scan prints
    every raw stdout/stderr line instead. After the scan: a live activity line
    while a slow step runs, its result line when it ends, notes as warning or
    muted lines.
    """

    def __init__(
        self,
        *,
        animate: bool,
        view: PipelineLiveView | TopologyView | None = None,
        echo_output: bool = False,
        fps: int = 4,
    ) -> None:
        self.animate = animate
        self.view = view
        self.echo_output = echo_output
        self.fps = fps
        self._live: Live | None = None
        self._activity: motion.Activity | None = None

    def on_stage(self, event: StageEvent) -> None:
        if self.view is not None:
            self.view.on_stage(event)

    def on_record(self, record: ToolRecord) -> None:
        if self.view is not None:
            self.view.on_record(record)

    def on_output(self, line: str, stream: str) -> None:
        if not self.echo_output:
            return
        if stream == "stderr":
            console.print(line, style="dim")
        else:
            console.print(line)

    def on_step(self, event: StepEvent) -> None:
        if event.step == "scan":
            self._scan(event)
        elif event.kind == "start":
            _print_step_start(event)
            if event.step in _ACTIVITIES:
                label, detail = _ACTIVITIES[event.step]
                self._activity = motion.Activity(
                    console, label.format(subject=event.subject), animate=self.animate,
                    total=event.total, detail=detail,
                )
                self._activity.__enter__()
        elif event.kind == "advance":
            if self._activity is not None:
                self._activity.advance(event.done)
        else:
            if self._activity is not None:
                self._activity.__exit__(None, None, None)
                self._activity = None
            if event.summary is not None:
                _print_step_summary(event.summary)

    def on_note(self, note: Note) -> None:
        _print_note(note)

    def _scan(self, event: StepEvent) -> None:
        """Open the live view as the scan starts; leave its final frame when it ends."""
        if self.view is None:
            return
        if event.kind == "start":
            self._live = Live(self.view, console=console, refresh_per_second=self.fps, transient=False)
            self._live.start(refresh=True)
        elif event.kind == "done" and self._live is not None:
            self.view.finish()
            self._live.refresh()
            self._live.stop()
            self._live = None
            _after_live()


'''

PREPARE_AND_RUN = '''    # Whether the run can happen at all is knowable now, and a scan takes
    # minutes: report what is unavailable up front instead of spending the
    # time only to say that a stage never ran.
    try:
        prepared = prepare_pipeline(
            name, target, settings=settings, manager=manager, ffuf=ffuf, gowitness=gowitness, max_httpx=max_httpx
        )
    except RegistryError as exc:
        console.print(f"[err]{exc}[/err]")
        manager.close()
        raise typer.Exit(2) from exc
    if plan:
        console.print(_plan_view(prepared))
        manager.close()
        return
    assert target is not None  # a non-plan run required --target above; narrows for the scan path
    for warning in prepared.warnings:
        console.print(f"[warn]{warning}[/warn]")
    if prepared.blocking and not force_start:
        for stage, tool, reason in prepared.blocking:
            console.print(f"[err]{tool}[/err] ({stage}): [err]{reason}[/err]")
        console.print(
            "[warn]Fix the above (`cyberfw init`, `cyberfw status`), "
            "or pass --force-start to run the stages that can.[/warn]"
        )
        manager.close()
        raise typer.Exit(2)

    # Verbose view when parsing is disabled (config parse=false or --no-parse):
    # stream each stage's raw stdout/stderr live instead of the quiet spinner.
    # Stages are still parsed internally so results thread from one to the next.
    verbose = no_parse or not settings.parse
    # The flag overrides the `view` setting for this run; unset falls back to it.
    use_topology = topology if topology is not None else settings.view == "topology"
    view: PipelineLiveView | TopologyView | None = None
    if not verbose:
        if use_topology:
            view = TopologyView(prepared.nodes, seed=target, title=f"{name} · {target}", animate=settings.animations)
        else:
            view = PipelineLiveView(prepared.nodes, title=f"pipeline {name} · {target}", animate=settings.animations)
    observer = _CliObserver(animate=settings.animations, view=view, echo_output=verbose, fps=_live_fps(settings))

    wordlist = choose_wordlist(settings, wordlist, ffuf=ffuf, observer=observer)
    # The session knows whether its directory is ours: declining to save may
    # remove it, and a --session pointing at an earlier run must never be deleted.
    run_session = open_session(settings.reports_dir, kind="pipeline", name=name, session=session, stream=True)
    if topology is True and verbose:
        # Only when the user explicitly asked: the config default silently yields
        # to the raw stream under --no-parse rather than nagging every run.
        why = "--no-parse" if no_parse else "config parse=false"
        console.print(f"[warn]--topology needs the parsed view; ignored under {why}.[/warn]")
    if verbose:
        why = "--no-parse" if no_parse else "config parse=false"
        console.print(f"[muted]{why}: streaming raw stdout/stderr from every stage[/muted]")
    try:
        result = execute_pipeline(prepared, session=run_session, wordlist=wordlist, observer=observer)
    except CyberfwError as exc:
        console.print(f"[err]{exc}[/err]")
        raise typer.Exit(1) from exc

'''

scan = Source(root, "cyberfw/cli/scan.py")
scan.drop_defs("_preflight", "_resolve_gowitness")
scan.replace_span(
    "#: Steps that show a live activity line while they run: its label and detail.\n",
    "    def on_note(self, note: Note) -> None:\n        _print_note(note)\n\n\n",
    OBSERVER,
)
scan.replace_span(
    "    include_gowitness = _resolve_gowitness(gowitness, manager, settings.tools_dir)\n",
    "    observer = _CliObserver(animate=settings.animations)\n",
    PREPARE_AND_RUN,
)
scan.replace(
    "            tools={n.tool for n in nodes}, session=run_session, compare=not no_baseline,\n",
    "            tools={n.tool for n in prepared.nodes}, session=run_session, compare=not no_baseline,\n",
)
scan.replace(
    "from cyberfw.core.finish import finalize, run_info, write_reports\n",
    "from cyberfw.core.finish import finalize, run_info, write_reports\n"
    "from cyberfw.core.scan import choose_wordlist, execute_pipeline, prepare_pipeline\n",
)

views = Source(root, "cyberfw/cli/views.py")
views.replace(
    "def _plan_view(\n"
    "    manager: ToolManager,\n"
    "    name: str,\n"
    "    seed: str | None,\n"
    "    nodes: list[Node],\n"
    "    blocking: list[tuple[str, str, str]],\n"
    "    warnings: list[str],\n"
    "    tools_dir: Path,\n"
    ") -> HudFrame:\n",
    "def _plan_view(prepared: PreparedPipeline) -> HudFrame:\n",
)
views.replace("    for index, node in enumerate(nodes, start=1):\n", "    for index, node in enumerate(prepared.nodes, start=1):\n")
views.replace("        state = tool_state(manager, node.tool, tools_dir)\n", "        state = prepared.states[node.tool]\n")
views.replace("        if blocking\n", "        if prepared.blocking\n")
views.replace('Text(f"{len(blocking)} stage(s) cannot run', 'Text(f"{len(prepared.blocking)} stage(s) cannot run')
views.replace('footer = join([Text(f"plan · {seed or \'<target>\'}"', 'footer = join([Text(f"plan · {prepared.target or \'<target>\'}"')
views.replace('panes = [Pane(table, title=f"Plan · {name}", pad=0)]', 'panes = [Pane(table, title=f"Plan · {prepared.name}", pad=0)]')
views.replace(
    "    if warnings:\n        panes.append(Pane(Group(*(Text(w, style=\"warn\") for w in warnings)), title=\"Notes\"))\n",
    "    if prepared.warnings:\n"
    "        panes.append(Pane(Group(*(Text(w, style=\"warn\") for w in prepared.warnings)), title=\"Notes\"))\n",
)
views.replace(
    "from cyberfw.core.workspace import tool_state\n",
    "from cyberfw.core.scan import PreparedPipeline\nfrom cyberfw.core.workspace import tool_state\n",
)

tests = Source(root, "tests/unit/test_cli.py")
tests.sub(r"cli\._resolve_gowitness\b", "cli.resolve_gowitness", count=2)

for source in (scan, views, tests):
    source.save()
```

```bash
uv run --quiet python "$W/task4_cli.py" .
uv run --quiet ruff check --fix --select F401,I001 cyberfw/cli
```

Expected: `edited cyberfw/cli/scan.py`, `…/views.py`, `edited tests/unit/test_cli.py`; `Found 9 errors (9 fixed, 0 remaining).`

- [ ] **Step 6: Run everything**

Run: `uv run --quiet python -m pytest -q`, `uv run --quiet ruff check .`, `uv run --quiet mypy cyberfw`
Expected: `1055 passed, 5 skipped, 8 deselected`; ruff clean; mypy `Success: no issues found in 73 source files`.

- [ ] **Step 7: The output is unchanged**

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/4-scan" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -r "$W/transcripts/2-steps" "$W/transcripts/4-scan" && echo identical
```

Expected: `36 passed`, then `identical` — the plain, verbose (`--no-parse`), topology, plan, blocked, `--force-start`, excluded and ffuf scenarios included.

- [ ] **Step 8: Prove the terminal guard catches a live view left open**

```bash
cp cyberfw/cli/scan.py "$W/cli-scan.keep"
uv run --quiet python -c "from pathlib import Path; p = Path('cyberfw/cli/scan.py'); t = p.read_text(encoding='utf-8'); old = '            self._live.stop()\n'; assert t.count(old) == 1; p.write_text(t.replace(old, ''), encoding='utf-8', newline='\n')"
uv run --quiet python -m pytest tests/unit/test_cli.py -q -k TestLiveDisplaysOnATerminal
cp "$W/cli-scan.keep" cyberfw/cli/scan.py
```

Expected: `1 failed` — `AssertionError: a live display was left open` / `assert 1 == 0`; after the `cp`, `cyberfw/cli/scan.py` is back.

- [ ] **Step 9: Commit**

```bash
git add cyberfw/core/scan.py tests/unit/test_core_pipeline.py cyberfw/cli tests/unit/test_cli.py
git commit -m "Prepare and run pipelines in cyberfw/core/scan.py; the CLI draws the scan from its events"
```

---

### Task 5: A single tool run moves into the core

**Files:**
- Create: `cyberfw/core/tool_run.py`, `tests/unit/test_core_tool.py`
- Modify (by script): `cyberfw/cli/scan.py` (`task5_cli.py`); `README.md`, `CHANGELOG.md` (`task5_docs.py`)

**Interfaces:**
- Consumes: Task 4's `wire_observer`; Task 3's `run_info`, `write_reports`, `Session`.
- Produces, in `cyberfw/core/tool_run.py`: `check_tool(manager, tool, target)` (raises `ValueError` for a target the tool cannot take, then `RegistryError`, then `ToolNotFoundError`); `ToolRun(tool, target, node, records, started_at, finished_at, session)`; `run_tool_once(tool, *, settings, manager, target, inputs=(), wordlist=None, parse=True, session, observer) -> ToolRun`; `keep_tool_run(run, *, settings, manager) -> dict[str, Path]`.
- `_CliObserver` gains `raw_records=False` (`run --no-parse`: each record's raw line, stderr dimmed). The CLI's `_run_single` is gone.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_core_tool.py`:

```python
"""One tool on its own in cyberfw.core: checked, run, kept — against the CLI tests' fake tools."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from cyberfw.config import Settings
from cyberfw.core.events import RunObserver, StepEvent
from cyberfw.core.sessions import open_session
from cyberfw.core.tool_run import check_tool, keep_tool_run, run_tool_once
from cyberfw.core.workspace import open_manager
from cyberfw.exceptions import RegistryError, ToolNotFoundError
from cyberfw.manager import ToolManager
from cyberfw.pipeline.schemas import ToolRecord

from .test_cli import _write_fake_binaries, _write_registry

pytestmark = pytest.mark.usefixtures("prints_nothing")


class Recorder(RunObserver):
    def __init__(self) -> None:
        self.steps: list[str] = []
        self.records: list[ToolRecord] = []

    def on_step(self, event: StepEvent) -> None:
        self.steps.append(f"{event.step}:{event.kind}")

    def on_record(self, record: ToolRecord) -> None:
        self.records.append(record)


@pytest.fixture
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    _write_fake_binaries(tmp_path / "tools_bin")
    _write_registry(tmp_path)
    monkeypatch.chdir(tmp_path)
    return Settings(root_dir=tmp_path)


@pytest.fixture
def manager(settings: Settings) -> Iterator[ToolManager]:
    manager = open_manager(settings)
    yield manager
    manager.close()


def test_a_target_the_tool_cannot_take_is_a_value_error(manager: ToolManager) -> None:
    with pytest.raises(ValueError, match="local repository directory"):
        check_tool(manager, "gitleaks", "https://utm.md/")


def test_an_unknown_tool_is_a_registry_error(manager: ToolManager) -> None:
    with pytest.raises(RegistryError):
        check_tool(manager, "bogus", "example.com")


def test_a_tool_without_its_binary_is_not_found(settings: Settings, manager: ToolManager) -> None:
    (settings.tools_dir / "subfinder").unlink()

    with pytest.raises(ToolNotFoundError):
        check_tool(manager, "subfinder", "example.com")


def test_a_run_returns_its_records_between_scan_events(settings: Settings, manager: ToolManager) -> None:
    session = open_session(settings.reports_dir, kind="run", name="subfinder", session=None, stream=False)
    seen = Recorder()

    ran = run_tool_once("subfinder", settings=settings, manager=manager, target="example.com",
                        session=session, observer=seen)

    assert ran.node.ok and [record.target for record in ran.records] == ["sub.example.com"]
    assert seen.steps == ["scan:start", "scan:done"] and seen.records == ran.records
    assert ran.started_at <= ran.finished_at
    assert not session.dir.exists()  # undecided: nothing written yet


def test_without_parsing_every_line_is_a_raw_record(settings: Settings, manager: ToolManager) -> None:
    session = open_session(settings.reports_dir, kind="run", name="subfinder", session=None, stream=False)

    ran = run_tool_once("subfinder", settings=settings, manager=manager, target="example.com",
                        parse=False, session=session, observer=RunObserver())

    assert [record.raw for record in ran.records] == ['{"host": "sub.example.com", "source": "stub"}']


def test_keeping_an_undecided_run_archives_its_records_and_writes_reports(
    settings: Settings, manager: ToolManager
) -> None:
    session = open_session(settings.reports_dir, kind="run", name="subfinder", session="later", stream=False)
    ran = run_tool_once("subfinder", settings=settings, manager=manager, target="example.com",
                        session=session, observer=RunObserver())

    reports = keep_tool_run(ran, settings=settings, manager=manager)

    assert sorted(reports) == ["html", "json"] and all(path.is_file() for path in reports.values())
    archived = list(session.dir.glob("*.jsonl"))
    assert len(archived) == 1 and len(archived[0].read_text(encoding="utf-8").splitlines()) == 1


def test_a_streamed_run_is_not_archived_twice(settings: Settings, manager: ToolManager) -> None:
    session = open_session(settings.reports_dir, kind="run", name="subfinder", session="now", stream=True)
    ran = run_tool_once("subfinder", settings=settings, manager=manager, target="example.com",
                        session=session, observer=RunObserver())

    keep_tool_run(ran, settings=settings, manager=manager)

    archived = list(session.dir.glob("*.jsonl"))
    assert len(archived) == 1 and len(archived[0].read_text(encoding="utf-8").splitlines()) == 1
```

- [ ] **Step 2: Run them to see them fail**

Run: `uv run --quiet python -m pytest tests/unit/test_core_tool.py -q`
Expected: collection error — `ModuleNotFoundError: No module named 'cyberfw.core.tool_run'`.

- [ ] **Step 3: Create the single-tool module**

Create `cyberfw/core/tool_run.py`:

```python
"""One registered tool run on its own (``cyberfw run``), without printing: checked, run, kept."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import anyio

from cyberfw.config import Settings
from cyberfw.core.events import RunObserver, StepEvent
from cyberfw.core.finish import run_info, write_reports
from cyberfw.core.scan import wire_observer
from cyberfw.core.sessions import Session
from cyberfw.manager import ToolManager
from cyberfw.pipeline.context import SessionContext
from cyberfw.pipeline.engine import Node, NodeResult, PipelineEngine, PipelineResult
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.tools import adapter_class
from cyberfw.tools.base import ToolContext


def check_tool(manager: ToolManager, tool: str, target: str | None) -> None:
    """What must hold before ``tool`` runs on its own, checked in this order: a
    target of the kind it takes (else :class:`ValueError` — a usage error), a
    registered tool with an adapter (else :class:`RegistryError`), and its binary
    (else :class:`ToolNotFoundError`)."""
    if target is not None:
        adapter_class(tool).validate_target(target)
    manager.binary_path(tool)


@dataclass
class ToolRun:
    """One tool run on its own: its outcome, records and timing."""

    tool: str
    target: str | None
    node: NodeResult
    records: list[ToolRecord]
    started_at: datetime
    finished_at: datetime
    session: Session


async def _run_single(
    engine: PipelineEngine, ctx: ToolContext, tool: str, parse: bool
) -> tuple[NodeResult, list[ToolRecord]]:
    """Run one tool stage through the engine (handles fan-out and crashes)."""
    return await engine.run_single(Node(tool=tool, stage=tool), ctx, parse=parse)


def run_tool_once(
    tool: str,
    *,
    settings: Settings,
    manager: ToolManager,
    target: str | None,
    inputs: Sequence[str] = (),
    wordlist: str | None = None,
    parse: bool = True,
    session: Session,
    observer: RunObserver,
) -> ToolRun:
    """Run one registered tool on its own, streaming its events to the observer.

    Like a pipeline stage — same fan-out, timeout and failure handling — with
    ``inputs`` in place of a previous stage. Without ``parse`` every stdout line
    is a raw record. The run is a ``scan`` step, timed around the process; the
    manager is closed afterwards, and the session's store if records streamed.
    """
    engine = PipelineEngine(settings, manager, context=session.context)
    wire_observer(engine, observer)
    ctx = ToolContext(
        target=target, inputs=list(inputs), extra_input=wordlist or settings.wordlist, controls=engine._controls()
    )
    started_at = datetime.now(timezone.utc)
    observer.on_step(StepEvent("start", "scan"))
    try:
        node, records = anyio.run(_run_single, engine, ctx, tool, parse)
    finally:
        manager.close()
        observer.on_step(StepEvent("done", "scan"))
    finished_at = datetime.now(timezone.utc)
    if session.context is not None:
        session.context.close()
    return ToolRun(
        tool=tool, target=target, node=node, records=records, started_at=started_at, finished_at=finished_at,
        session=session,
    )


def keep_tool_run(run: ToolRun, *, settings: Settings, manager: ToolManager) -> dict[str, Path]:
    """Save a tool run: its records — archived now, unless they streamed as they
    came — and both reports. Returns the reports by format, as :func:`write_reports`."""
    if run.session.context is None:
        with SessionContext(settings.reports_dir, run.session.id) as store:
            for record in run.records:
                store.append(run.tool, record)
    result = PipelineResult(nodes=[run.node], records=run.records, started_at=run.started_at, finished_at=run.finished_at)
    info = run_info(manager, name=run.tool, seed=run.target, session_id=run.session.id, tools={run.tool})
    return write_reports(result, session_id=run.session.id, settings=settings, run=info)
```

- [ ] **Step 4: Run them to see them pass**

Run: `uv run --quiet python -m pytest tests/unit/test_core_tool.py -q`
Expected: `7 passed`.

- [ ] **Step 5: `cyberfw run` checks, runs and saves through the core; the docs**

Save as `$W/task5_cli.py`:

```python
"""Task 5: `cyberfw run` checks, runs and saves one tool through cyberfw.core.

Usage: python task5_cli.py <repo root>   (then: ruff check --fix --select F401,I001 cyberfw/cli)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

RUN_BODY = '''    try:
        # The adapter knows what kind of target it takes; check that before
        # looking for the binary so a wrong target is a usage error (exit 2).
        check_tool(manager, tool, target)
    except ValueError as exc:
        console.print(f"[err]{exc}[/err]")
        raise typer.Exit(2) from exc
    except ToolNotFoundError as exc:
        console.print(f"[err]{exc}[/err]")
        console.print("[warn]Run `cyberfw init` first (or export CYBERFW_GITHUB_TOKEN).[/warn]")
        raise typer.Exit(1) from exc
    except CyberfwError as exc:
        console.print(f"[err]{exc}[/err]")
        raise typer.Exit(1) from exc

    # Only --save streams into reports/<session>/ as records arrive (crash-safe).
    # Undecided runs write nothing until the user has answered, so an ad-hoc
    # `run` never litters the filesystem with a folder nobody asked for.
    run_session = open_session(settings.reports_dir, kind="run", name=tool, session=session, stream=bool(save))
    hosts = _read_hosts(list_file) if list_file is not None else []
    target_label = target or f"{len(hosts)} host(s) from {list_file}"
    console.print(f"[info]tool:[/info] [tool]{tool}[/tool]  [info]target:[/info] {target_label}")

    # Parsing is on by default; disable it via the config `parse:` setting
    # (CYBERFW_PARSE=false) or override per-run with --no-parse.
    do_parse = settings.parse and not no_parse
    if do_parse:
        view = PipelineLiveView(
            [Node(tool=tool, stage=tool)], title=f"{tool} · {target_label}", animate=settings.animations
        )
        observer = _CliObserver(animate=settings.animations, view=view, fps=_live_fps(settings))
    else:
        why = "--no-parse" if no_parse else "config parse=false"
        console.print(f"[muted]{why}: streaming raw stdout/stderr exactly as the tool prints it[/muted]")
        observer = _CliObserver(animate=settings.animations, raw_records=True)
    ran = run_tool_once(
        tool, settings=settings, manager=manager, target=target, inputs=hosts, wordlist=wordlist,
        parse=do_parse, session=run_session, observer=observer,
    )
    records = ran.records
    if not do_parse:
        console.print(f"[info]{len(records)} line(s) captured[/info]")
    elif records:
        console.print(_record_table(records, tool=tool, target=target_label))
    else:
        console.print("[muted]No records found.[/muted]")

    # --save decided up front (and streamed the records as they came); an
    # undecided run asks now, and only when there is something to keep.
    if save or (save is None and records and _wants_to_save(save, default=False, what=tool)):
        written = keep_tool_run(ran, settings=settings, manager=manager)
        console.print(f"[ok]saved:[/ok] {run_session.dir}")
        for label, path in written.items():
            console.print(f"[ok]{label}:[/ok] {path}")

    if not ran.node.ok:
        console.print(f"[err]{ran.node.error or 'stage failed'}[/err]")
        raise typer.Exit(1)
'''

scan = Source(root, "cyberfw/cli/scan.py")
scan.drop_defs("_run_single")
scan.replace_span(
    "    try:\n        # The adapter knows what kind of target it takes; check that before\n",
    "    if not node_result.ok:\n"
    "        console.print(f\"[err]{node_result.error or 'stage failed'}[/err]\")\n"
    "        raise typer.Exit(1)\n",
    RUN_BODY,
)
# The observer learns run --no-parse: each record's raw line, stderr dimmed.
scan.replace(
    "        echo_output: bool = False,\n",
    "        echo_output: bool = False,\n        raw_records: bool = False,\n",
)
scan.replace(
    "        self.echo_output = echo_output\n",
    "        self.echo_output = echo_output\n        self.raw_records = raw_records\n",
)
scan.replace(
    "        if self.view is not None:\n            self.view.on_record(record)\n",
    "        if self.view is not None:\n            self.view.on_record(record)\n"
    "        elif self.raw_records:\n            console.print(record.raw)\n",
)
scan.replace(
    "        if not self.echo_output:\n"
    "            return\n"
    "        if stream == \"stderr\":\n"
    "            console.print(line, style=\"dim\")\n"
    "        else:\n"
    "            console.print(line)\n",
    "        if stream == \"stderr\" and (self.echo_output or self.raw_records):\n"
    "            console.print(line, style=\"dim\")\n"
    "        elif stream == \"stdout\" and self.echo_output:\n"
    "            console.print(line)\n",
)
scan.replace(
    "events only change their state. With ``echo_output`` the scan prints\n"
    "    every raw stdout/stderr line instead.",
    "events only change their state. With ``echo_output`` the scan prints\n"
    "    every raw stdout/stderr line instead; with ``raw_records`` (``run\n"
    "    --no-parse``) each record's raw line, and stderr dimmed.",
)
scan.replace(
    "from cyberfw.core.scan import choose_wordlist, execute_pipeline, prepare_pipeline\n",
    "from cyberfw.core.scan import choose_wordlist, execute_pipeline, prepare_pipeline\n"
    "from cyberfw.core.tool_run import check_tool, keep_tool_run, run_tool_once\n",
)
scan.replace(
    '"""`run` and `pipeline` — running a tool or a pipeline and finishing the run."""\n',
    '"""`run` and `pipeline`: their flags, questions and rendering — the runs themselves are cyberfw.core\'s."""\n',
)
scan.save()
```

Save as `$W/task5_docs.py`:

```python
"""Task 5: README structure and CHANGELOG for the core move.

Usage: python task5_docs.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

readme = Source(root, "README.md")
readme.replace(
    "                         schedule), общие помощники (common), отрисовка (views), лаунчер\n",
    "                         schedule), общие помощники (common), отрисовка (views), лаунчер\n"
    "  core/                  прогон без интерфейса: реестр и lock (workspace), сессии, события\n"
    "                         (events), подготовка, запуск и завершение скана (runs)\n",
)

changelog = Source(root, "CHANGELOG.md")
changelog.replace(
    "## [Unreleased]\n\n### Changed\n",
    "## [Unreleased]\n\n### Changed\n"
    "- Оркестрация прогона переехала из CLI в ядро `cyberfw/core/`: подготовка и\n"
    "  запуск пайплайна, одиночный `run`, проверки после скана, триаж, сравнение с\n"
    "  прошлым прогоном и запись отчётов. Ядро ничего не печатает и не спрашивает, а\n"
    "  сообщает о ходе работы событиями; CLI рисует их тем же текстом, что и раньше.\n"
    "  Это основа будущего публичного Python API.\n",
)
changelog.replace(
    "### Fixed\n",
    "### Fixed\n"
    "- Предупреждения проверок после скана (почта, threat intel, VirusTotal) теряли\n"
    "  часть текста ошибки в квадратных скобках: Rich принимал её за разметку.\n"
    "  Теперь текст показывается как есть.\n",
)

readme.save()
changelog.save()
```

```bash
uv run --quiet python "$W/task5_cli.py" .
uv run --quiet ruff check --fix --select F401,I001 cyberfw/cli
uv run --quiet python "$W/task5_docs.py" .
```

Expected: `edited cyberfw/cli/scan.py`; `Found 12 errors (12 fixed, 0 remaining).`; `edited README.md`, `edited CHANGELOG.md`.

- [ ] **Step 6: Run everything**

Run: `uv run --quiet python -m pytest -q`, `uv run --quiet ruff check .`, `uv run --quiet mypy cyberfw`
Expected: `1062 passed, 5 skipped, 8 deselected`; ruff clean; mypy `Success: no issues found in 74 source files`.

- [ ] **Step 7: The output is unchanged**

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/5-tool" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -r "$W/transcripts/2-steps" "$W/transcripts/5-tool" && echo identical
```

Expected: `36 passed`, then `identical` — the `run` scenarios (live, raw, saved, empty, broken, missing binary, bad target, host list) included.

- [ ] **Step 8: Commit and push**

```bash
git add cyberfw/core/tool_run.py tests/unit/test_core_tool.py cyberfw/cli/scan.py README.md CHANGELOG.md
git commit -m "Run single tools through cyberfw/core/tool_run.py"
git push origin main
```
