# Dependent Stages Get No Seed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A pipeline stage that reads another stage scans only what that stage found in scope — and when that is nothing, its tool does not run at all, least of all on the seed.

**Architecture:** `PipelineEngine._run_in_graph` (`cyberfw/pipeline/engine.py`) hands the seed only to a node that reads no other stage — the root. A node with a source gets no seed, only its source's in-scope targets, so `_dispatch` and `_fan_out` find nothing to scan when there are none and return without launching a process. A stage left with nothing to scan has still run: `ok`, not skipped, 0 results — what reads it runs by the same rule. `run_single` (`cyberfw run <tool>`) is untouched: there the target is the user's.

**Tech Stack:** Python 3.14 via `uv`, asyncio, pytest (`asyncio_mode = auto`), ruff, mypy `--strict`.

**Spec:** `upgrades.md`, item 2 ("Не подставляйте seed при пустом результате предыдущего этапа") — the user's review, staged by the user in the main checkout (`C:/Users/DaniilSirbu/Desktop/CS-TOOL_main/upgrades.md`) and not part of `main`, so a worktree of `main` does not have it — its proposal and its check: an empty and a fully excluded upstream, for an ordinary and a `per_target` adapter; no later process may run on the seed.

Scope, as agreed with the user and with Codex (`CLAUDE_HANDOFF.local.md`):

- Items 1, 4, 7, 9, 11 and 12 are Codex's. Item 3 (stopping the whole process tree) gets a plan of its own once Codex's executor work (items 4 and 7) has landed: both change `cyberfw/pipeline/executor.py`.
- This plan touches `cyberfw/pipeline/engine.py`, `tests/unit/test_engine.py` and `CHANGELOG.md` only — none of them Codex's.
- The behaviour change is user-visible (a pipeline after an empty or fully excluded stage reports less), so the CHANGELOG says so under «Fixed», as for the previous fixes.

Every script and `Expected:` line below comes from running this plan on a throwaway worktree of `main` at `53a3f70`: the suite goes 1243 → 1247 passed; ruff and mypy `--strict` are clean; the transcripts of 49 of the 50 scenarios are identical to the baseline, and the 50th (`pipeline-excluded`) changes exactly as the fix means it to.

## Global Constraints

- Run everything through `uv run --quiet …`. Suite: `uv run --quiet python -m pytest -q`; lint: `uv run --quiet ruff check .`; types: `uv run --quiet mypy cyberfw`. All clean at the end of the task.
- **Everything else behaves as before** — every command's console text, exit code and saved reports, checked with the transcript harness (50 scenarios); the one scenario that changes is the fix itself (Task 1, Step 5).
- **Work in a clean worktree of `main`, never in the main checkout**: the main checkout holds the user's staged `.gitignore` and `upgrades.md` and Codex's uncommitted work (`cyberfw/core/steps.py`, `cyberfw/manager/__init__.py`, `cyberfw/pipeline/executor.py`, `cyberfw/report/diff.py`, `cyberfw/tools/gitleaks.py` and their new tests). Push with `git push origin HEAD:main`; the main checkout then moves only by `git merge --ff-only`, which leaves those files as they are.
- Commits: by path only (`git commit -m "…" -- <paths>`); **no `Co-Authored-By` trailer** (the user's rule for this repo); never `CS-TOOL_presentation.pdf` or `CLAUDE_HANDOFF.local.md`.
- Before the commit and before the push, reread `CLAUDE_HANDOFF.local.md`: if Codex has reserved `cyberfw/pipeline/engine.py` or `tests/unit/test_engine.py` meanwhile, stop and ask the user.
- Scratchpad: `SCRATCH=C:/Users/DANIIL~1/AppData/Local/Temp/claude/C--Users-DaniilSirbu-Desktop-CS-TOOL-main/6a8b772a-7993-414c-98b5-45500cbb762c/scratchpad`, `W="$SCRATCH/p1a-exec"`. The plan's scripts and transcripts live in `$W`, never in the repo.

## Review Focus

1. A pipeline file without `input_from` — each stage reading the one before it, the common case — follows the same rule: after a stage that found nothing, nothing runs → `test_a_stage_reading_the_previous_one_by_default_follows_the_same_rule` (Task 1).
2. A stage left with nothing to scan is no failure: `ok`, not skipped, 0 results, so the report, `--fail-on` and the coverage of a diff count it as having run, and what reads it is not skipped → `test_a_source_that_found_nothing_runs_nothing_after_it` (Task 1) and the existing `test_an_empty_but_successful_source_still_runs_the_next_stage`.
3. The root stage still scans the seed, and a stage with hosts gets those hosts, not the seed → the existing `test_the_first_stage_still_uses_the_seed` and `test_stage2_uses_input_file_not_seed`, and `test_a_source_that_found_hosts_hands_over_those_and_not_the_seed` (Task 1).
4. A source whose every host is out of scope (`--exclude`) leaves nothing to scan — for an ordinary and a `per_target` adapter → `test_a_source_whose_every_host_is_out_of_scope_runs_nothing_after_it` (Task 1).
5. A stage whose source failed is still skipped, with its reason → the existing `test_next_stage_is_skipped_when_its_source_failed` and `test_skip_propagates_down_the_chain`.

---

### Before Task 1: the worktree, the tools and a baseline

- [ ] **Step 1: A clean worktree of `main`** — from the main checkout:

```bash
mkdir -p "$W"
git fetch origin && git worktree add --detach "$W/repo" origin/main
cd "$W/repo" && uv sync --quiet --extra dev && git log --oneline -1
```

Expected: `53a3f70 No disabled package, stray pin or unreadable distribution breaks plugin loading; an exit on import is a broken plugin` (a later commit of `main` is fine if `git log 53a3f70..origin/main` touches neither file of this plan). Every later command runs in `$W/repo`.

- [ ] **Step 2: Save the editor** — the same checked-edit helper as the previous plans (each edit names how often its pattern must match). Save as `$W/edit.py`:

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

- [ ] **Step 3: Save the transcript harness** — save as `$W/test_zz_capture.py` (copied into `tests/unit/` only for a capture, never committed):

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
    text = re.sub(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})?", "<datetime>", text)
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


def _engine_raises(_root: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    from cyberfw.exceptions import CyberfwError
    from cyberfw.pipeline.engine import PipelineEngine

    async def broken(self: object, *_a: object, **_k: object) -> object:
        raise CyberfwError("the engine [broke]")

    monkeypatch.setattr(PipelineEngine, "run", broken)
    return [*PIPE, "--no-report", "--no-mail"]


def _report_unwritable(_root: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    from cyberfw.exceptions import ReportError

    def refuse(*_a: object, **_k: object) -> object:
        raise ReportError("cannot write report.json: [denied]")

    patch_cli(monkeypatch, "generate_json_report", refuse)
    return [*PIPE, "--session", "unwritable", "--no-mail"]


def _missing_dependency(root: Path) -> None:
    """subfinder declares an optional dependency nobody has on PATH."""
    registry = (root / "registry.yaml").read_text(encoding="utf-8")
    registry = registry.replace("  binary: subfinder\n", "  binary: subfinder\n  check_deps: [cyberfw-test-missing-dep]\n")
    (root / "registry.yaml").write_text(registry, encoding="utf-8")


def _dependency_and_blocked(root: Path) -> None:
    _missing_dependency(root)
    (root / "tools_bin" / "nuclei").unlink()


def _two_saved_runs(root: Path) -> None:
    first = runner.invoke(app, [*PIPE, "--session", "one", "--no-mail"])
    assert first.exit_code == 0, first.output
    _tool_prints(
        root, "nuclei",
        {"template-id": "xss", "matched-at": "https://sub.example.com/", "info": {"name": "XSS", "severity": "medium"}},
        {"template-id": "sqli", "matched-at": "https://sub.example.com/login", "info": {"name": "SQLi", "severity": "high"}},
    )
    second = runner.invoke(app, [*PIPE, "--session", "two", "--no-mail"])
    assert second.exit_code == 0, second.output


SCENARIOS: dict[str, Setup] = {
    "pipeline-engine-raises": _engine_raises,
    "pipeline-report-unwritable": _report_unwritable,
    "pipeline-dependency-warning": _then(_missing_dependency, [*PIPE, "--no-report", "--no-mail"]),
    "pipeline-dependency-warning-blocked": _then(_dependency_and_blocked, [*PIPE, "--no-report", "--no-mail"]),
    "pipeline-plan-dependency-warning": _then(_missing_dependency, [*PIPE, "--plan"]),
    "pipeline-ffuf-verbose-topology": _then(
        _bundled_wordlist, [*PIPE, "--no-report", "--no-mail", "--ffuf", "--no-parse", "--topology"]
    ),
    "diff-two-runs": _then(_two_saved_runs, ["diff", "one", "two"]),
    "diff-json": _then(_two_saved_runs, ["diff", "one", "two", "--json"]),
    "diff-missing": _plain(["diff", "nope", "gone"]),
    "export-sarif": _then(_two_saved_runs, ["export", "two", "--sarif"]),
    "export-csv": _then(_two_saved_runs, ["export", "two", "--csv"]),
    "export-to-file": _then(_two_saved_runs, ["export", "two", "--csv", "-o", "out.csv"]),
    "export-no-format": _plain(["export", "two"]),
    "export-missing": _plain(["export", "nope", "--sarif"]),
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

- [ ] **Step 4: Capture the baseline** — before any change:

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/0-base" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
uv run --quiet python -m pytest -q
git status --short
```

Expected: `50 passed`; `1243 passed, 5 skipped, 8 deselected`; `git status` shows nothing.

---

### Task 1: A stage that reads another never runs on the seed

**Files:**
- Modify (by script): `cyberfw/pipeline/engine.py` (`_run_in_graph`), `CHANGELOG.md`; tests `tests/unit/test_engine.py`

**Interfaces:**
- Produces: `_run_in_graph` calls `_run_node(node, seed, [], …)` for a node with no source, and `_run_node(node, None, <the source's in-scope targets>, …)` for every other node. `_run_node`, `_dispatch`, `_fan_out` and `run_single` keep their signatures.

- [ ] **Step 1: Write the failing tests**

Save as `$W/task1_tests.py`:

```python
"""Task 1, test first: a stage that reads another never runs on the seed.

Usage: python task1_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

TESTS = '''

class TestADependentStageNeverRunsOnTheSeed:
    """A stage scans what the stage it reads found. When that is nothing — it found
    nothing, or every host it found is out of scope — the stage has nothing to scan:
    its tool does not run, least of all on the seed."""

    @staticmethod
    def _engine(tmp_path: Path, launched: list[tuple[str, str | None]], *, finds: bool = True) -> PipelineEngine:
        """httpx and nuclei (one process per target) record each process they would
        launch; subfinder finds ``sub.example.com`` — or, without ``finds``, nothing."""
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text(
            "".join(f"{tool}:\\n  repo: org/{tool}\\n  asset_patterns: []\\n" for tool in ("subfinder", "httpx", "nuclei")),
            encoding="utf-8",
        )
        engine = _make_engine(tmp_path, registry_path)

        class Launching(BaseTool):
            """Records each process its stage would launch, then launches a no-op."""

            def build_cmd(self, ctx: ToolContext) -> list[str]:
                launched.append((self.name, ctx.target))
                return [sys.executable, "-c", "pass"]

        class LaunchingPerTarget(Launching):
            per_target = True

        source = tmp_path / "source.py"
        source.write_text(
            "print('{\\"host\\": \\"sub.example.com\\", \\"source\\": \\"stub\\"}')\\n" if finds else "pass\\n",
            encoding="utf-8",
        )
        tools = {
            "httpx": lambda spec: Launching(spec, tmp_path / "httpx"),
            "nuclei": lambda spec: LaunchingPerTarget(spec, tmp_path / "nuclei"),
        }
        engine.build_tool = lambda name: (  # type: ignore[method-assign]
            tools[name](engine.tool_manager.spec(name)) if name in tools
            else _StubTool(engine.tool_manager.spec(name), source)
        )
        return engine

    _NODES = [
        Node(tool="subfinder", stage="subdomains"),
        Node(tool="httpx", stage="live_http", input_from="subdomains"),
        Node(tool="nuclei", stage="vulns", input_from="subdomains"),
    ]

    async def test_a_source_that_found_nothing_runs_nothing_after_it(self, tmp_path: Path) -> None:
        launched: list[tuple[str, str | None]] = []
        engine = self._engine(tmp_path, launched, finds=False)

        result = await engine.run(self._NODES, seed="example.com")

        assert launched == []
        # Nothing to scan is no failure: each stage ran, found nothing, and is no
        # reason to skip what reads it.
        assert [(node.ok, node.skipped, node.count) for node in result.nodes] == [(True, False, 0)] * 3

    async def test_a_stage_reading_the_previous_one_by_default_follows_the_same_rule(self, tmp_path: Path) -> None:
        # Without ``input_from`` a stage reads the stage before it: a chain where the
        # first finds nothing runs nothing at all after it.
        launched: list[tuple[str, str | None]] = []
        engine = self._engine(tmp_path, launched, finds=False)
        chain = [
            Node(tool="subfinder", stage="subdomains"),
            Node(tool="httpx", stage="live_http"),
            Node(tool="nuclei", stage="vulns"),
        ]

        await engine.run(chain, seed="example.com")

        assert launched == []

    async def test_a_source_whose_every_host_is_out_of_scope_runs_nothing_after_it(self, tmp_path: Path) -> None:
        launched: list[tuple[str, str | None]] = []
        engine = self._engine(tmp_path, launched)
        engine.settings.exclude = ["*.example.com"]

        result = await engine.run(self._NODES, seed="example.com")

        assert launched == []
        assert result.excluded and all(node.ok for node in result.nodes)

    async def test_a_source_that_found_hosts_hands_over_those_and_not_the_seed(self, tmp_path: Path) -> None:
        launched: list[tuple[str, str | None]] = []
        engine = self._engine(tmp_path, launched)

        await engine.run(self._NODES, seed="example.com")

        assert sorted(launched) == [("httpx", None), ("nuclei", "sub.example.com")]
'''

tests = Source(root, "tests/unit/test_engine.py")
tests.text = tests.text.rstrip("\n") + "\n" + TESTS
tests.save()
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python "$W/task1_tests.py" .
uv run --quiet python -m pytest "tests/unit/test_engine.py::TestADependentStageNeverRunsOnTheSeed" -q -p no:cacheprovider
```

Expected: `edited tests/unit/test_engine.py`; then `3 failed, 1 passed` — each failure an `AssertionError: assert [('httpx', 'e...example.com')] == []`: httpx and nuclei launched on the seed `example.com` after an empty source, an implicit empty source, and a fully excluded one. The fourth test (`…hands_over_those_and_not_the_seed`) passes already: it guards that the fix keeps found hosts flowing.

- [ ] **Step 3: Hand the seed to the root only, and say so in the CHANGELOG**

Save as `$W/task1_seed.py`:

```python
"""Task 1: only a stage that reads no other one runs on the seed.

Usage: python task1_seed.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

engine = Source(root, "cyberfw/pipeline/engine.py")
engine.replace(
    '        """Run one node against its upstream stage\'s in-scope targets (or the seed)."""\n'
    "        source = deps[node.stage]\n"
    "        inputs = outputs.get(source, []) if source is not None else []\n"
    "        return node, await self._run_node(node, seed, inputs, extra_input=extra_input)\n",
    '        """Run one node against its upstream stage\'s in-scope targets — or, for a node\n'
    "        that reads no stage, the seed. A node whose source found nothing in scope has\n"
    "        nothing to scan: it gets no seed instead, so its tool does not run.\"\"\"\n"
    "        source = deps[node.stage]\n"
    "        if source is None:\n"
    "            return node, await self._run_node(node, seed, [], extra_input=extra_input)\n"
    "        return node, await self._run_node(node, None, outputs.get(source, []), extra_input=extra_input)\n",
)
engine.save()
```

Save as `$W/task1_docs.py`:

```python
"""Task 1: the CHANGELOG says a stage after an empty or fully excluded one no longer runs on the seed.

Usage: python task1_docs.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

changelog = Source(root, "CHANGELOG.md")
changelog.replace(
    "### Fixed\n- Строка вывода, которую не принимает схема инструмента",
    "### Fixed\n"
    "- Этап, читающий другой этап, запускался на исходной цели, если тот ничего\n"
    "  не нашёл или всё найденное отсёк `--exclude`: после naabu без портов httpx\n"
    "  сканировал seed, после пустого httpx — nuclei. Теперь исходную цель\n"
    "  получает только корневой этап; этапу без входов сканировать нечего — его\n"
    "  инструмент не запускается, а сам этап считается отработавшим с 0 записей.\n"
    "- Строка вывода, которую не принимает схема инструмента",
)
changelog.save()
```

```bash
uv run --quiet python "$W/task1_seed.py" .
uv run --quiet python "$W/task1_docs.py" .
```

Expected: `edited cyberfw/pipeline/engine.py`, `edited CHANGELOG.md`.

- [ ] **Step 4: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_engine.py -q -p no:cacheprovider
```

Expected: `54 passed`.

- [ ] **Step 5: The whole suite, lint, types, and the output**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1247 passed, 5 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 79 source files`.

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/1-seed" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -r --exclude=pipeline-excluded.txt "$W/transcripts/0-base" "$W/transcripts/1-seed" && echo identical
grep -c "1 hosts  ·  0 live  ·  0 vulns" "$W/transcripts/1-seed/pipeline-excluded.txt"; grep -c "XSS" "$W/transcripts/1-seed/pipeline-excluded.txt"
```

Expected: `50 passed`, then `identical`, `1`, `0`. One scenario changes, and only as the fix means it to: `pipeline-excluded` runs `recon-to-vuln` with `--exclude sub.example.com`, the one host subfinder finds — before, httpx and nuclei then ran on the seed and reported a live host and an XSS; now they have nothing to scan and report 0 (`diff` shows exactly that). (If another difference is only an `elapsed <dur> (1m…s)` line, the machine was loaded enough for a stage to pass a minute — capture again into an empty directory.)

- [ ] **Step 6: Commit and push** — reread `CLAUDE_HANDOFF.local.md` first (Global Constraints), then:

```bash
git commit -m "A stage that reads another scans what it found, never the seed: nothing found, nothing run" -- cyberfw/pipeline/engine.py tests/unit/test_engine.py CHANGELOG.md
git log -1 --format=%B | grep -ci co-authored
git push origin HEAD:main
```

Expected: `0` from the `grep`; the push lands on `main`.

- [ ] **Step 7: Move the main checkout** — in the main checkout (`C:/Users/DaniilSirbu/Desktop/CS-TOOL_main`):

```bash
git fetch origin && git merge --ff-only origin/main && git status --short
```

Expected: a fast-forward to the new commit; `git status` lists the same staged and uncommitted files as before — the user's `.gitignore` and `upgrades.md`, and Codex's files.
