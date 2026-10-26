# Public API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put a small, stable Python API — `cyberfw.api` — on top of the core, for the user's own scripts and CI, and make the CLI's `pipeline`, `run`, `pipeline --plan`, `diff` and `export` its first users, without changing a line of what they print.

**Architecture:** `cyberfw/api.py` composes the core (Step 2) into seven calls — `run_pipeline`, `plan_pipeline`, `run_tool`, `load_run`, `compare_runs`, `export_sarif`, `export_csv` — that return data (`RunOutcome`, `Plan`, `SavedRun`) and raise typed errors (`PreflightError` is new). Progress reaches the caller through the core's `RunObserver`, which learns two things the CLI needs to go through the API: `on_plan` (the prepared stages, before anything runs — the CLI builds its live view from it) and the scan's `done` carrying its `PipelineResult` (the CLI prints the stage or record table from it). The CLI keeps every prompt and line it prints, in its observer and two small hooks; the transcript harness compares the output of 50 scenarios after every task with the code before the plan.

**Tech Stack:** Python 3.14 via `uv`, Typer + Rich, pytest, ruff, mypy `--strict`.

**Spec:** `docs/superpowers/specs/2026-10-18-core-api-cli-split-design.md` — this plan is **Step 3** of it (Step 1, the CLI package, and Step 2, the core, are done). It also lands the Step 2 review's API-shaping minors: `StepEvent.completed` instead of `done`, `Literal` types for `step` and `stream`, a scan that ends even when cleanup fails, an observer that never leaves a live display open, and the README structure naming the real core modules.

Departures from the spec's Step 3 text, each keeping a higher rule (output unchanged, a sound stable surface):

- **The observer gains `on_plan(plan)`, and the scan's `done` carries its `PipelineResult`.** The CLI draws its live view from the stages before the scan starts, and prints the `--no-parse` stage table (pipeline) or the record table (`run`) from the scan's result — through one `run_pipeline` / `run_tool` call.
- **`StepEvent.done` is renamed `completed`**, and `step` / `stream` become `Literal` types, before they become a public contract.
- **`Plan` details:** each blocking entry is a `Blocker(stage, tool, reason)` named tuple, a stage's own controls are `(name, value)` pairs; `Plan`, `PlanStage` and `Blocker` live in `core/scan.py` and are re-exported by the API.
- **`run_tool` with neither a target nor inputs runs with nothing to work on** (and finds nothing) instead of raising — what `cyberfw run --list <empty file>` does today.
- **A report that cannot be written is a `ReportError`** (what the writers already raise), so the CLI tells it apart from an engine failure; one test that simulated it with a bare `CyberfwError` now raises `ReportError`.
- **When the engine raises, `run_pipeline` closes the session's records store** (what streamed stays on disk), as the Step 2 review recommended.
- **The one ordering change:** `cyberfw run --list FILE` reads the host file before the tool is checked. It shows only when the file is missing *and* the tool or target is bad — both fail either way.

Every file, script and `Expected:` line below comes from running this plan end-to-end on a throwaway worktree of `main` at `e79428d`: the suite goes 1082 → 1087 → 1089 → 1110 → 1110 → 1112 passed; ruff and mypy `--strict` are clean after each task, and the transcripts of all 50 scenarios are identical to the baseline after each task.

## Global Constraints

- Run everything through `uv run --quiet …`. Suite: `uv run --quiet python -m pytest -q`; lint: `uv run --quiet ruff check .`; types: `uv run --quiet mypy cyberfw`. All clean at the end of every task.
- **Output stays as it is:** every command's console text, exit code and saved reports — checked after every task with the transcript harness (50 scenarios, including the error paths and `diff` / `export`).
- **The stable surface** (spec): the functions and types in `cyberfw.api.__all__`; `cyberfw.core.*` and `cyberfw.cli.*` stay internal. The API never prints, prompts or calls `sys.exit`.
- **The dependency rule** (spec): `core` and `api` import domain modules only — never `cyberfw.cli`, `typer`, Rich, the presentation modules or the shared `console`; `import cyberfw.api` leaves `cyberfw.cli` and `typer` unloaded. `tests/unit/test_core_layering.py` checks both from Task 3 on.
- Tests reach internals through `tests/unit/_cli.py`, which from Task 3 also covers `cyberfw.api`.
- Scratchpad: `SCRATCH=C:/Users/DANIIL~1/AppData/Local/Temp/claude/C--Users-DaniilSirbu-Desktop-CS-TOOL-main/6a8b772a-7993-414c-98b5-45500cbb762c/scratchpad`, `W="$SCRATCH/api-plan"`. The plan's scripts and transcripts live in `$W`, never in the repo.
- Commits: **no `Co-Authored-By` trailer** (the user's rule for this repo); stage only the task's files, never `CS-TOOL_presentation.pdf`. Push to `main` at the end (the user's standing instruction).

## Review Focus

1. Every CLI path that now goes through the API prints exactly what it printed — in particular the error paths: an engine that raises (exit 1, message last), a report that cannot be written (`report failed:`, exit 0), a missing dependency named before the stages that cannot run, the ffuf note before the `--no-parse` / `--topology` lines → the transcript harness after every task, and `TestPipelineErrors` (Task 4).
2. A script using the API prints nothing to stdout or stderr → `test_a_pipeline_run_returns_its_stages_records_and_reports` checks both streams (Task 3), on top of Step 2's subprocess test.
3. Not saving leaves no session behind, a `save` callable is asked after the comparison and before anything is written, an earlier session is never removed → `test_a_run_that_is_not_saved_leaves_no_session_behind` (Task 3) and Step 2's finishing tests.
4. A crash mid-scan releases the records store and leaves no live display open → `test_an_engine_failure_releases_the_records_store` (Task 3) and the terminal tests of Task 1.
5. The README's API example keeps working as the API evolves → `test_the_readme_example_runs` (Task 5).

---

### Before Task 1: the tools and a baseline

The same two helpers as Step 2's plan, in a fresh `$W`: `edit.py` (checked edits: each names how often its pattern must match) and the transcript harness, which now has 50 scenarios — Step 2's 36 plus an engine that raises, a report that cannot be written, a missing dependency (alone, with a blocked stage, and in a plan), the ffuf note with `--no-parse --topology`, and `diff` / `export` (two runs, JSON, SARIF, CSV, to a file, missing runs, no format).

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

- [ ] **Step 2: Save the transcript harness** — save as `$W/test_zz_capture.py` (copied into `tests/unit/` only for a capture, never committed):

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

- [ ] **Step 3: Capture the baseline** — on `main`, before any change:

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/0-base" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
uv run --quiet python -m pytest -q
git status --short
```

Expected: `50 passed`; `1082 passed, 5 skipped, 8 deselected`; `git status` shows only `?? CS-TOOL_presentation.pdf`.

---

### Task 1: Events fit for a public API, and a scan that always ends with its result

**Files:**
- Modify (by script): `cyberfw/core/events.py`, `cyberfw/core/steps.py`, `cyberfw/core/scan.py`, `cyberfw/core/tool_run.py`, `cyberfw/cli/scan.py`; tests `tests/unit/test_core_pipeline.py`, `tests/unit/test_core_tool.py`, `tests/unit/test_core_steps.py`, `tests/unit/test_cli.py`

**Interfaces:**
- Produces, in `cyberfw/core/events.py`: `StepName = Literal["scan", "tls", "mail", "takeover", "intel", "vt", "compare"]`, `Stream = Literal["stdout", "stderr"]`; `StepEvent.step: StepName`; `StepEvent.completed: int = 0` (was `done`); `RunObserver.on_output(line: str, stream: Stream)`; `StepSummary` now also covers `PipelineResult` (the scan's own result).
- Produces, in `cyberfw/core/scan.py`: `end_scan(manager, observer, result: PipelineResult | None)` — closes the manager, then sends `StepEvent("done", "scan", summary=result)` even if closing fails; `execute_pipeline` uses it. In `cyberfw/core/tool_run.py`: `ToolRun.result -> PipelineResult` (the run as a one-stage result); `run_tool_once` ends its scan with it.
- `_CliObserver` closes a still-open activity line before starting another, and stops the live view even when the view fails to finish.

- [ ] **Step 1: Write the failing tests**

Save as `$W/task1_tests.py`:

```python
"""Task 1, tests first: the scan ends with its result, whatever fails on the way out.

Usage: python task1_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

PIPELINE_TESTS = '''

class _Ends(RunObserver):
    """Keeps the done events."""

    def __init__(self) -> None:
        self.ends: list[StepEvent] = []

    def on_step(self, event: StepEvent) -> None:
        if event.kind == "done":
            self.ends.append(event)


def test_the_scan_ends_with_its_result(settings: Settings, manager: ToolManager) -> None:
    prepared = prepare_pipeline("recon-to-vuln", "example.com", settings=settings, manager=manager)
    session = open_session(settings.reports_dir, kind="pipeline", name="recon-to-vuln", session=None, stream=True)
    seen = _Ends()

    result = execute_pipeline(prepared, session=session, wordlist=None, observer=seen)

    assert [event.step for event in seen.ends] == ["scan"] and seen.ends[0].summary is result


def test_the_scan_still_ends_when_closing_the_manager_fails(settings: Settings, manager: ToolManager) -> None:
    def stuck() -> None:
        raise OSError("connection pool [stuck]")

    prepared = prepare_pipeline("recon-to-vuln", "example.com", settings=settings, manager=manager)
    session = open_session(settings.reports_dir, kind="pipeline", name="recon-to-vuln", session=None, stream=True)
    seen = _Ends()

    with pytest.MonkeyPatch.context() as patch:  # the fixture closes the real manager afterwards
        patch.setattr(manager, "close", stuck)
        with pytest.raises(OSError, match="stuck"):
            execute_pipeline(prepared, session=session, wordlist=None, observer=seen)

    assert [event.step for event in seen.ends] == ["scan"]
    assert isinstance(seen.ends[0].summary, PipelineResult) and seen.ends[0].summary.succeeded()
'''

TOOL_TEST = '''

def test_a_tool_run_ends_its_scan_with_a_one_stage_result(settings: Settings, manager: ToolManager) -> None:
    session = open_session(settings.reports_dir, kind="run", name="subfinder", session=None, stream=False)
    ends: list[StepEvent] = []

    class Ends(RunObserver):
        def on_step(self, event: StepEvent) -> None:
            if event.kind == "done":
                ends.append(event)

    ran = run_tool_once("subfinder", settings=settings, manager=manager, target="example.com",
                        session=session, observer=Ends())

    (end,) = ends
    assert isinstance(end.summary, PipelineResult)
    assert end.summary.nodes == [ran.node] and end.summary.records == ran.records
'''

TERMINAL_TESTS = r'''

    def test_a_live_view_that_fails_to_finish_is_still_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyberfw.core.events import StepEvent

        monkeypatch.setenv("TERM", "xterm-256color")
        terminal = Console(file=io.StringIO(), force_terminal=True, width=120, theme=THEME)
        patch_cli(monkeypatch, "console", terminal)

        class Broken:
            def __rich__(self) -> str:
                return "scan"

            def finish(self) -> None:
                raise RuntimeError("view [broke]")

        observer = cli._CliObserver(animate=True, view=Broken(), fps=4)
        observer.on_step(StepEvent("start", "scan"))
        with pytest.raises(RuntimeError, match="broke"):
            observer.on_step(StepEvent("done", "scan"))

        raw = terminal.file.getvalue()  # type: ignore[attr-defined]
        assert raw.count("\x1b[?25l") == raw.count("\x1b[?25h") > 0, "the live view was left open"

    def test_a_new_activity_line_closes_one_left_open(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyberfw.core.events import StepEvent

        monkeypatch.setenv("TERM", "xterm-256color")
        terminal = Console(file=io.StringIO(), force_terminal=True, width=120, theme=THEME)
        patch_cli(monkeypatch, "console", terminal)

        observer = cli._CliObserver(animate=True)
        observer.on_step(StepEvent("start", "mail", subject="example.com"))  # never ends
        observer.on_step(StepEvent("start", "takeover", total=1))
        observer.on_step(StepEvent("done", "takeover"))

        raw = terminal.file.getvalue()  # type: ignore[attr-defined]
        assert raw.count("\x1b[?25l") == raw.count("\x1b[?25h") > 0, "an activity line was left open"
'''

pipeline = Source(root, "tests/unit/test_core_pipeline.py")
pipeline.replace(
    "from cyberfw.pipeline.engine import PipelineEngine, StageEvent\n",
    "from cyberfw.pipeline.engine import PipelineEngine, PipelineResult, StageEvent\n",
)
pipeline.text = pipeline.text.rstrip("\n") + "\n" + PIPELINE_TESTS

tool = Source(root, "tests/unit/test_core_tool.py")
tool.replace("from cyberfw.pipeline.schemas import ToolRecord\n",
             "from cyberfw.pipeline.engine import PipelineResult\nfrom cyberfw.pipeline.schemas import ToolRecord\n")
tool.text = tool.text.rstrip("\n") + "\n" + TOOL_TEST

cli_tests = Source(root, "tests/unit/test_cli.py")
cli_tests.replace(
    '        assert "recon-to-vuln · example.com" in drawn and "Email check skipped" in drawn\n',
    '        assert "recon-to-vuln · example.com" in drawn and "Email check skipped" in drawn\n' + TERMINAL_TESTS,
)

for source in (pipeline, tool, cli_tests):
    source.save()
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python "$W/task1_tests.py" .
uv run --quiet python -m pytest tests/unit/test_core_pipeline.py tests/unit/test_core_tool.py "tests/unit/test_cli.py::TestLiveDisplaysOnATerminal" -q
```

Expected: three `edited` lines, then `5 failed, 18 passed`: `test_the_scan_ends_with_its_result`, `test_the_scan_still_ends_when_closing_the_manager_fails`, `test_a_tool_run_ends_its_scan_with_a_one_stage_result`, `test_a_live_view_that_fails_to_finish_is_still_closed` ("the live view was left open") and `test_a_new_activity_line_closes_one_left_open` ("an activity line was left open").

- [ ] **Step 3: Change the events and the scan's ending**

Save as `$W/task1_events.py`:

```python
"""Task 1: event shapes fit for a public API, and a scan that always ends with its result.

Usage: python task1_events.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

events = Source(root, "cyberfw/core/events.py")
events.replace(
    "from cyberfw.pipeline.engine import StageEvent\n",
    "from cyberfw.pipeline.engine import PipelineResult, StageEvent\n",
)
events.replace(
    "from cyberfw.threatintel import IntelSummary\n",
    "from cyberfw.threatintel import IntelSummary\n"
    "\n"
    "#: The scan itself, then each step after it, in the order they run.\n"
    'StepName: TypeAlias = Literal["scan", "tls", "mail", "takeover", "intel", "vt", "compare"]\n'
    "#: Which of a tool's streams a raw output line came from.\n"
    'Stream: TypeAlias = Literal["stdout", "stderr"]\n',
)
events.replace(
    "#: A step's result, sent with its ``done`` event: the comparison with an earlier\n"
    "#: run is a :class:`~cyberfw.report.diff.RunDiff`, threat intel a\n"
    "#: :class:`~cyberfw.threatintel.IntelSummary`.\n"
    "StepSummary: TypeAlias = TlsSummary | MailSummary | TakeoverSummary | IntelSummary | VtSummary | RunDiff\n",
    "#: A step's result, sent with its ``done`` event: the scan's own is its\n"
    "#: :class:`~cyberfw.pipeline.engine.PipelineResult`, the comparison with an earlier\n"
    "#: run a :class:`~cyberfw.report.diff.RunDiff`, threat intel a\n"
    "#: :class:`~cyberfw.threatintel.IntelSummary`.\n"
    "StepSummary: TypeAlias = (\n"
    "    PipelineResult | TlsSummary | MailSummary | TakeoverSummary | IntelSummary | VtSummary | RunDiff\n"
    ")\n",
)
events.replace("    step: str\n", "    step: StepName\n")
events.replace(
    "    #: Units finished so far, on ``advance``.\n    done: int = 0\n",
    "    #: Units finished so far, on ``advance``.\n    completed: int = 0\n",
)
events.replace(
    "    def on_output(self, line: str, stream: str) -> None:\n",
    "    def on_output(self, line: str, stream: Stream) -> None:\n",
)

steps = Source(root, "cyberfw/core/steps.py")
steps.replace(
    '    """A ``progress`` callback that reports ``done`` units of ``step`` to the observer."""\n'
    '    return lambda done: observer.on_step(StepEvent("advance", step, total=total, done=done))\n',
    '    """A ``progress`` callback that reports how many units of ``step`` are finished."""\n'
    '    return lambda completed: observer.on_step(StepEvent("advance", step, total=total, completed=completed))\n',
)
steps.replace(
    "def _advance(observer: RunObserver, step: str, total: int) -> Callable[[int], None]:\n",
    "def _advance(observer: RunObserver, step: StepName, total: int) -> Callable[[int], None]:\n",
)
steps.replace("    StepEvent,\n    StepSummary,\n", "    StepEvent,\n    StepName,\n    StepSummary,\n")

scan = Source(root, "cyberfw/core/scan.py")
scan.replace(
    "    observer.on_step(StepEvent(\"start\", \"scan\"))\n"
    "    try:\n"
    "        result = anyio.run(functools.partial(engine.run, extra_input=wordlist), prepared.nodes, prepared.target)\n"
    "    finally:\n"
    "        prepared.manager.close()\n"
    "        observer.on_step(StepEvent(\"done\", \"scan\"))\n",
    "    observer.on_step(StepEvent(\"start\", \"scan\"))\n"
    "    try:\n"
    "        result = anyio.run(functools.partial(engine.run, extra_input=wordlist), prepared.nodes, prepared.target)\n"
    "    except BaseException:\n"
    "        end_scan(prepared.manager, observer, None)\n"
    "        raise\n"
    "    end_scan(prepared.manager, observer, result)\n",
)
scan.replace(
    "    The scan is a step of its own: ``start`` before the engine runs and ``done``\n"
    "    after it — also when it raises — then a note for any hosts kept out of scope.\n",
    "    The scan is a step of its own: ``start`` before the engine runs and ``done``,\n"
    "    carrying the result, after it — also when it raises — then a note for any\n"
    "    hosts kept out of scope.\n",
)
scan.replace(
    "\n\ndef execute_pipeline(",
    '''

def end_scan(manager: ToolManager, observer: RunObserver, result: PipelineResult | None) -> None:
    """Close the tool manager, then end the ``scan`` step with its result (``None``
    when it raised) — the ``done`` goes out even if closing fails."""
    try:
        manager.close()
    finally:
        observer.on_step(StepEvent("done", "scan", summary=result))


def execute_pipeline(''',
)

tool_run = Source(root, "cyberfw/core/tool_run.py")
tool_run.replace("from cyberfw.core.scan import wire_observer\n", "from cyberfw.core.scan import end_scan, wire_observer\n")
tool_run.replace(
    "    session: Session\n\n\nasync def _run_single(",
    '''    session: Session

    @property
    def result(self) -> PipelineResult:
        """The run as a one-stage pipeline result."""
        return PipelineResult(
            nodes=[self.node], records=self.records, started_at=self.started_at, finished_at=self.finished_at
        )


async def _run_single(''',
)
tool_run.replace(
    "    observer.on_step(StepEvent(\"start\", \"scan\"))\n"
    "    try:\n"
    "        node, records = anyio.run(_run_single, engine, ctx, tool, parse)\n"
    "    finally:\n"
    "        manager.close()\n"
    "        observer.on_step(StepEvent(\"done\", \"scan\"))\n"
    "    finished_at = datetime.now(timezone.utc)\n"
    "    if session.context is not None:\n"
    "        session.context.close()\n"
    "    return ToolRun(\n"
    "        tool=tool, target=target, node=node, records=records, started_at=started_at, finished_at=finished_at,\n"
    "        session=session,\n"
    "    )\n",
    "    observer.on_step(StepEvent(\"start\", \"scan\"))\n"
    "    try:\n"
    "        node, records = anyio.run(_run_single, engine, ctx, tool, parse)\n"
    "    except BaseException:\n"
    "        end_scan(manager, observer, None)\n"
    "        raise\n"
    "    ran = ToolRun(\n"
    "        tool=tool, target=target, node=node, records=records, started_at=started_at,\n"
    "        finished_at=datetime.now(timezone.utc), session=session,\n"
    "    )\n"
    "    end_scan(manager, observer, ran.result)\n"
    "    if session.context is not None:\n"
    "        session.context.close()\n"
    "    return ran\n",
)
tool_run.replace(
    "    result = PipelineResult(nodes=[run.node], records=run.records, started_at=run.started_at, finished_at=run.finished_at)\n"
    "    info = run_info(manager, name=run.tool, seed=run.target, session_id=run.session.id, tools={run.tool})\n"
    "    return write_reports(result, session_id=run.session.id, settings=settings, run=info)\n",
    "    info = run_info(manager, name=run.tool, seed=run.target, session_id=run.session.id, tools={run.tool})\n"
    "    return write_reports(run.result, session_id=run.session.id, settings=settings, run=info)\n",
)

cli = Source(root, "cyberfw/cli/scan.py")
cli.replace(
    "            if event.step in _ACTIVITIES:\n"
    "                label, detail = _ACTIVITIES[event.step]\n",
    "            if event.step in _ACTIVITIES:\n"
    "                self._close_activity()  # one a step never ended must not stay on screen\n"
    "                label, detail = _ACTIVITIES[event.step]\n",
)
cli.replace("                self._activity.advance(event.done)\n", "                self._activity.advance(event.completed)\n")
cli.replace(
    "        else:\n"
    "            if self._activity is not None:\n"
    "                self._activity.__exit__(None, None, None)\n"
    "                self._activity = None\n"
    "            if event.summary is not None:\n",
    "        else:\n"
    "            self._close_activity()\n"
    "            if event.summary is not None:\n",
)
cli.replace(
    "    def _scan(self, event: StepEvent) -> None:\n",
    "    def _close_activity(self) -> None:\n"
    "        if self._activity is not None:\n"
    "            self._activity.__exit__(None, None, None)\n"
    "            self._activity = None\n"
    "\n"
    "    def _scan(self, event: StepEvent) -> None:\n",
)
cli.replace(
    "        elif event.kind == \"done\" and self._live is not None:\n"
    "            self.view.finish()\n"
    "            self._live.refresh()\n"
    "            self._live.stop()\n"
    "            self._live = None\n"
    "            _after_live()\n",
    "        elif event.kind == \"done\" and self._live is not None:\n"
    "            try:\n"
    "                self.view.finish()\n"
    "                self._live.refresh()\n"
    "            finally:  # a view that fails to finish must not leave the display live\n"
    "                self._live.stop()\n"
    "                self._live = None\n"
    "                _after_live()\n",
)

tests = Source(root, "tests/unit/test_core_steps.py")
tests.sub(r"event\.done\b", "event.completed", count=2)

for source in (events, steps, scan, tool_run, cli, tests):
    source.save()
```

```bash
uv run --quiet python "$W/task1_events.py" .
uv run --quiet ruff check --fix --select F401,I001 cyberfw tests
uv run --quiet python -m pytest tests/unit/test_core_pipeline.py tests/unit/test_core_tool.py tests/unit/test_core_steps.py "tests/unit/test_cli.py::TestLiveDisplaysOnATerminal" -q
```

Expected: six `edited` lines; `All checks passed!`; `36 passed`.

- [ ] **Step 4: Run everything**

Run: `uv run --quiet python -m pytest -q`, `uv run --quiet ruff check .`, `uv run --quiet mypy cyberfw`
Expected: `1087 passed, 5 skipped, 8 deselected`; ruff clean; mypy `Success: no issues found in 74 source files`.

- [ ] **Step 5: The output is unchanged**

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/1-events" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -r "$W/transcripts/0-base" "$W/transcripts/1-events" && echo identical
```

Expected: `50 passed`, then `identical`.

- [ ] **Step 6: Commit**

```bash
git add cyberfw/core cyberfw/cli/scan.py tests/unit/test_core_pipeline.py tests/unit/test_core_tool.py tests/unit/test_core_steps.py tests/unit/test_cli.py
git commit -m "Shape run events for a public API; the scan always ends with its result"
```

---

### Task 2: A pipeline's plan is built in the core

**Files:**
- Modify (by script): `cyberfw/core/scan.py`, `cyberfw/core/events.py`, `cyberfw/cli/views.py`, `cyberfw/cli/scan.py`; `tests/unit/test_core_pipeline.py`

**Interfaces:**
- Consumes: Task 1's events.
- Produces, in `cyberfw/core/scan.py`: `Blocker(stage, tool, reason)` (a `NamedTuple`; `PreparedPipeline.blocking` is now `list[Blocker]`), `PlanStage(index, tool, stage, consumes, state, options: tuple[tuple[str, str], ...])`, `Plan(name, target, stages, blocking, warnings)` with `.ready`, `plan_of(prepared) -> Plan`. In `cyberfw/core/events.py`: `RunObserver.on_plan(plan: Plan)` (a no-op by default).
- `_plan_view(plan: Plan)` draws a `Plan`; `pipeline --plan` prints `_plan_view(plan_of(prepared))`.

- [ ] **Step 1: Write the failing tests**

Save as `$W/task2_tests.py`:

```python
"""Task 2, tests first: a prepared pipeline as a plan — its stages, what they read, what blocks.

Usage: python task2_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

PLAN_TESTS = '''

def test_a_plan_lists_each_stage_with_what_it_reads_and_its_tool_state(
    settings: Settings, manager: ToolManager
) -> None:
    (settings.tools_dir / "nuclei").unlink()

    plan = plan_of(prepare_pipeline("recon-to-vuln", "example.com", settings=settings, manager=manager))

    assert [(s.index, s.tool, s.stage, s.consumes, s.state) for s in plan.stages] == [
        (1, "subfinder", "subdomains", "seed", "ready"),
        (2, "httpx", "live_http", "subdomains", "ready"),
        (3, "nuclei", "vulns", "live_http", "not installed"),
    ]
    assert plan.blocking == (Blocker("vulns", "nuclei", "not installed"),) and not plan.ready
    assert (plan.name, plan.target, plan.warnings) == ("recon-to-vuln", "example.com", ())


def test_a_planned_stage_shows_its_own_options_and_the_stage_it_reads(
    settings: Settings, manager: ToolManager
) -> None:
    nodes = [
        Node(tool="subfinder", stage="subs"),
        Node(tool="httpx", stage="live", rate_limit=50),
        Node(tool="nuclei", stage="vulns", input_from="subs", severity="high", tags="cve", max_records=10),
    ]
    prepared = PreparedPipeline(
        name="custom", target=None, nodes=nodes, blocking=[], warnings=["subfinder works best with x"],
        states={"subfinder": "ready", "httpx": "ready", "nuclei": "ready"}, settings=settings, manager=manager,
    )

    plan = plan_of(prepared)

    assert [stage.consumes for stage in plan.stages] == ["seed", "subs", "subs"]
    assert [stage.options for stage in plan.stages] == [
        (), (("rate", "50"),), (("severity", "high"), ("tags", "cve"), ("max", "10")),
    ]
    assert plan.ready and plan.warnings == ("subfinder works best with x",)
'''

pipeline = Source(root, "tests/unit/test_core_pipeline.py")
pipeline.replace(
    "from cyberfw.core.scan import choose_wordlist, execute_pipeline, prepare_pipeline\n",
    "from cyberfw.core.scan import (\n"
    "    Blocker,\n    PreparedPipeline,\n    choose_wordlist,\n    execute_pipeline,\n    plan_of,\n"
    "    prepare_pipeline,\n)\n",
)
pipeline.replace(
    "from cyberfw.pipeline.engine import PipelineEngine, PipelineResult, StageEvent\n",
    "from cyberfw.pipeline.engine import Node, PipelineEngine, PipelineResult, StageEvent\n",
)
pipeline.text = pipeline.text.rstrip("\n") + "\n" + PLAN_TESTS
pipeline.save()
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python "$W/task2_tests.py" .
uv run --quiet python -m pytest tests/unit/test_core_pipeline.py -q
```

Expected: `edited tests/unit/test_core_pipeline.py`, then a collection error — `ImportError: cannot import name 'Blocker' from 'cyberfw.core.scan'`.

- [ ] **Step 3: Build the plan in the core; the CLI only draws it**

Save as `$W/task2_plan.py`:

```python
"""Task 2: the plan of a pipeline is built in the core; the CLI only draws it.

Usage: python task2_plan.py <repo root>   (then: ruff check --fix --select F401,I001 cyberfw)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

PLAN_TYPES = '''class Blocker(NamedTuple):
    """A stage that cannot run as things stand, and why."""

    stage: str
    tool: str
    reason: str


@dataclass(frozen=True)
class PlanStage:
    """One stage of a planned pipeline."""

    #: Its place in the pipeline, counted from 1.
    index: int
    tool: str
    stage: str
    #: ``seed``, or the stage whose targets it reads.
    consumes: str
    #: ``ready`` / ``blocked`` / ``not installed``.
    state: str
    #: The stage's own scan controls, when set, as ``(name, value)`` pairs:
    #: ``severity``, ``tags``, ``rate``, ``max``.
    options: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Plan:
    """A pipeline as it would run: its stages, what blocks them, what only weakens them."""

    name: str
    target: str | None
    stages: tuple[PlanStage, ...]
    blocking: tuple[Blocker, ...]
    warnings: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return not self.blocking


'''

PLAN_OF = '''def plan_of(prepared: PreparedPipeline) -> Plan:
    """The plan a prepared pipeline would run: each stage, the stage it reads, its
    tool's state and its own scan controls, then what blocks and what weakens it."""
    stages: list[PlanStage] = []
    previous: str | None = None
    for index, node in enumerate(prepared.nodes, start=1):
        controls = (("severity", node.severity), ("tags", node.tags), ("rate", node.rate_limit), ("max", node.max_records))
        stages.append(PlanStage(
            index=index,
            tool=node.tool,
            stage=node.stage,
            consumes=node.input_from or ("seed" if previous is None else previous),
            state=prepared.states[node.tool],
            options=tuple((key, str(value)) for key, value in controls if value),
        ))
        previous = node.stage
    return Plan(
        name=prepared.name, target=prepared.target, stages=tuple(stages),
        blocking=tuple(prepared.blocking), warnings=tuple(prepared.warnings),
    )


'''

PLAN_VIEW = '''def _plan_view(plan: Plan) -> HudFrame:
    """A dry-run picture of a pipeline: each stage, what it consumes, the state
    of its tool and any per-stage options, then the pre-flight verdict."""
    table = hud_table()
    table.add_column("#", style="muted", justify="right", no_wrap=True)
    table.add_column("tool", style="tool", no_wrap=True)
    table.add_column("stage", no_wrap=True)
    table.add_column("consumes", style="muted", no_wrap=True)
    table.add_column("state", no_wrap=True)
    table.add_column("options", style="muted", overflow="fold", ratio=1)
    for stage in plan.stages:
        table.add_row(
            str(stage.index), stage.tool, stage.stage, stage.consumes, pip_word(stage.state, state_style(stage.state)),
            "  ".join(f"{key}={value}" for key, value in stage.options),
        )
    verdict = (
        Text(f"{len(plan.blocking)} stage(s) cannot run as-is — --force-start runs the rest", style="warn")
        if plan.blocking
        else Text("ready to run", style="ok")
    )
    footer = join([Text(f"plan · {plan.target or '<target>'}", style="muted"), verdict], "   ")
    panes = [Pane(table, title=f"Plan · {plan.name}", pad=0)]
    if plan.warnings:
        panes.append(Pane(Group(*(Text(w, style="warn") for w in plan.warnings)), title="Notes"))
    return HudFrame(panes, footer=footer)
'''

scan = Source(root, "cyberfw/core/scan.py")
scan.replace("from dataclasses import dataclass\nfrom pathlib import Path\n",
             "from dataclasses import dataclass\nfrom pathlib import Path\nfrom typing import NamedTuple\n")
scan.replace("@dataclass\nclass PreparedPipeline:\n", PLAN_TYPES + "@dataclass\nclass PreparedPipeline:\n")
scan.replace(
    "    #: ``(stage, tool, reason)`` for each stage that cannot run as things stand.\n"
    "    blocking: list[tuple[str, str, str]]\n",
    "    #: Each stage that cannot run as things stand, and why.\n"
    "    blocking: list[Blocker]\n",
)
scan.replace(
    ") -> tuple[list[tuple[str, str, str]], list[str], dict[str, str]]:\n",
    ") -> tuple[list[Blocker], list[str], dict[str, str]]:\n",
)
scan.replace("    blocking: list[tuple[str, str, str]] = []\n", "    blocking: list[Blocker] = []\n")
scan.replace("            blocking.append((node.stage, node.tool, state))\n",
             "            blocking.append(Blocker(node.stage, node.tool, state))\n")
scan.replace("            blocking.append((node.stage, node.tool, requirement))\n",
             "            blocking.append(Blocker(node.stage, node.tool, requirement))\n")
scan.replace("def choose_wordlist(", PLAN_OF + "def choose_wordlist(")

events = Source(root, "cyberfw/core/events.py")
events.replace("from typing import Literal, TypeAlias\n", "from typing import TYPE_CHECKING, Literal, TypeAlias\n")
events.replace(
    "from cyberfw.threatintel import IntelSummary\n",
    "from cyberfw.threatintel import IntelSummary\n\nif TYPE_CHECKING:\n    from cyberfw.core.scan import Plan\n",
)
events.replace(
    '    """Receives a run\'s events. Every method does nothing: override what you need."""\n\n',
    '    """Receives a run\'s events. Every method does nothing: override what you need."""\n\n'
    "    def on_plan(self, plan: Plan) -> None:\n"
    '        """The pipeline as prepared — its stages, their tools\' states, what blocks — before anything runs."""\n\n',
)

views = Source(root, "cyberfw/cli/views.py")
views.replace_span(
    "def _plan_view(prepared: PreparedPipeline) -> HudFrame:\n",
    "        panes.append(Pane(Group(*(Text(w, style=\"warn\") for w in prepared.warnings)), title=\"Notes\"))\n"
    "    return HudFrame(panes, footer=footer)\n",
    PLAN_VIEW,
)
views.replace("from cyberfw.core.scan import PreparedPipeline\n", "from cyberfw.core.scan import Plan\n")

cli = Source(root, "cyberfw/cli/scan.py")
cli.replace("        console.print(_plan_view(prepared))\n", "        console.print(_plan_view(plan_of(prepared)))\n")
cli.replace(
    "from cyberfw.core.scan import choose_wordlist, execute_pipeline, prepare_pipeline\n",
    "from cyberfw.core.scan import choose_wordlist, execute_pipeline, plan_of, prepare_pipeline\n",
)

for source in (scan, events, views, cli):
    source.save()
```

```bash
uv run --quiet python "$W/task2_plan.py" .
uv run --quiet ruff check --fix --select F401,I001 cyberfw tests
uv run --quiet python -m pytest tests/unit/test_core_pipeline.py -q
```

Expected: four `edited` lines; `All checks passed!`; `14 passed`.

- [ ] **Step 4: Run everything**

Run: `uv run --quiet python -m pytest -q`, `uv run --quiet ruff check .`, `uv run --quiet mypy cyberfw`
Expected: `1089 passed, 5 skipped, 8 deselected`; ruff clean; mypy `Success: no issues found in 74 source files`.

- [ ] **Step 5: The output is unchanged**

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/2-plan" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -r "$W/transcripts/0-base" "$W/transcripts/2-plan" && echo identical
```

Expected: `50 passed`, then `identical` — the three `--plan` scenarios included.

- [ ] **Step 6: Commit**

```bash
git add cyberfw/core/scan.py cyberfw/core/events.py cyberfw/cli/views.py cyberfw/cli/scan.py tests/unit/test_core_pipeline.py
git commit -m "Build a pipeline's plan in the core; the CLI only draws it"
```

---

### Task 3: The public API

**Files:**
- Create: `cyberfw/api.py`, `tests/unit/test_api.py`
- Modify (by script): `cyberfw/exceptions.py`, `cyberfw/cli/scan.py`, `tests/unit/test_core_layering.py`, `tests/unit/_cli.py`, `tests/unit/test_cli_seams.py`, `tests/unit/test_cli.py`

**Interfaces:**
- Consumes: Task 2's `Plan`, `Blocker`, `plan_of`, `on_plan`; Task 1's events; Step 2's core.
- Produces, in `cyberfw/api.py` (the stable surface, `__all__`): `run_pipeline(name, target, *, settings=None, ffuf=False, wordlist=None, gowitness=None, max_httpx=0, severity="", tags="", rate_limit=None, exclude=(), mail=True, takeover=True, intel=True, vt_key=None, vt_limit=20, baseline=None, compare=True, session=None, save: bool | Callable[[], bool] = True, force_start=False, observer=None) -> RunOutcome`; `plan_pipeline(name, target=None, *, settings=None, ffuf=False, gowitness=None, max_httpx=0) -> Plan`; `run_tool(tool, *, target=None, inputs=(), wordlist=None, settings=None, severity="", tags="", rate_limit=None, parse=True, session=None, save=False, observer=None) -> RunOutcome`; `load_run(ref, *, settings=None) -> SavedRun`; `compare_runs(old, new) -> RunDiff`; `export_sarif(run) -> dict`; `export_csv(run) -> str`; `RunOutcome(result, run, session_id, session_dir, reports, changes, notes)` with `.succeeded`, `.alert_hits(severity="low")`, `.exit_code(alert_severity=None)`; `SavedRun(path, payload)`; and the re-exported types. `_scan_control_overrides` moves here from the CLI.
- Produces, in `cyberfw/exceptions.py`: `PreflightError(CyberfwError)` with `.blocking: list[tuple[str, str, str]]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_api.py`:

```python
"""cyberfw.api: runs, plans and saved runs as data — offline, against the CLI tests' fake tools."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberfw import api
from cyberfw.exceptions import CyberfwError, RegistryError, ToolNotFoundError
from cyberfw.pipeline.context import SessionContext
from cyberfw.pipeline.engine import Node, NodeResult, PipelineEngine

from . import test_cli as base

pytestmark = pytest.mark.usefixtures("prints_nothing")

PIPELINE = ("recon-to-vuln", "example.com")


class Recorder(api.RunObserver):
    """Everything a run sends, as short labels, plus the notes."""

    def __init__(self) -> None:
        self.log: list[str] = []
        self.notes: list[api.Note] = []

    def on_plan(self, plan: api.Plan) -> None:
        self.log.append("plan")

    def on_stage(self, event: api.StageEvent) -> None:
        self.log.append("stage")

    def on_record(self, record: api.ToolRecord) -> None:
        self.log.append("record")

    def on_step(self, event: api.StepEvent) -> None:
        self.log.append(f"{event.step}:{event.kind}")

    def on_note(self, note: api.Note) -> None:
        self.log.append(f"note:{note.level}")
        self.notes.append(note)


@pytest.fixture(autouse=True)
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    base._write_fake_binaries(tmp_path / "tools_bin")
    base._write_registry(tmp_path)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _two_saved_runs(workspace: Path) -> tuple[api.RunOutcome, api.RunOutcome]:
    """A first run, then one where nuclei adds a new high finding."""
    first = api.run_pipeline(*PIPELINE, session="one", mail=False)
    base.TestBaselineComparison._tool_prints(
        workspace, "nuclei",
        {"template-id": "xss", "matched-at": "https://sub.example.com/", "info": {"name": "XSS", "severity": "medium"}},
        {"template-id": "sqli", "matched-at": "https://sub.example.com/login", "info": {"name": "SQLi", "severity": "high"}},
    )
    return first, api.run_pipeline(*PIPELINE, session="two", mail=False)


def test_a_pipeline_run_returns_its_stages_records_and_reports(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    seen = Recorder()

    outcome = api.run_pipeline(*PIPELINE, session="first", observer=seen)

    assert outcome.succeeded and outcome.exit_code() == 0
    assert [stage.node.tool for stage in outcome.result.nodes] == ["subfinder", "httpx", "nuclei"]
    assert len(outcome.result.records) >= 3
    assert outcome.reports == {
        "json": workspace / "reports" / "first" / "report.json",
        "html": workspace / "reports" / "first" / "report.html",
    }
    assert (outcome.session_id, outcome.session_dir) == ("first", workspace / "reports" / "first")
    assert seen.log[0] == "plan" and {"stage", "record", "scan:start", "scan:done", "mail:done"} <= set(seen.log)
    assert capsys.readouterr() == ("", "")


def test_the_notes_of_a_run_are_kept_in_its_outcome() -> None:
    seen = Recorder()

    outcome = api.run_pipeline(*PIPELINE, save=False, observer=seen)

    assert outcome.notes == seen.notes
    assert any(note.text.startswith("Email check skipped") for note in outcome.notes)  # live DNS is off in tests


def test_a_failed_stage_exits_1(workspace: Path) -> None:
    base._break_tool(workspace, "httpx")

    outcome = api.run_pipeline(*PIPELINE, save=False, mail=False)

    assert not outcome.succeeded and outcome.exit_code() == 1 and outcome.exit_code("low") == 1


def test_new_findings_exit_3_only_when_an_alert_severity_is_given(workspace: Path) -> None:
    _, second = _two_saved_runs(workspace)

    assert second.changes is not None and second.alert_hits("high") == 1
    assert (second.exit_code(), second.exit_code("high"), second.exit_code("critical")) == (0, 3, 0)


def test_a_failed_run_outranks_its_new_findings(workspace: Path) -> None:
    # Even with new findings to alert on, a broken scan is reported as broken.
    _two_saved_runs(workspace)
    changes = api.compare_runs(api.load_run("one"), api.load_run("two"))
    failed = api.PipelineResult(nodes=[NodeResult(node=Node(tool="httpx", stage="live_http"), ok=False)])

    outcome = api.RunOutcome(
        result=failed, run=api.RunInfo(), session_id="x", session_dir=workspace, reports={}, changes=changes
    )

    assert outcome.alert_hits("high") == 1 and outcome.exit_code("high") == 1


def test_an_unknown_alert_severity_is_a_value_error() -> None:
    outcome = api.run_pipeline(*PIPELINE, save=False, mail=False)

    with pytest.raises(ValueError, match="severity must be one of"):
        outcome.exit_code("urgent")


def test_a_run_that_is_not_saved_leaves_no_session_behind(workspace: Path) -> None:
    asked: list[bool] = []

    api.run_pipeline(*PIPELINE, session="dropped", save=False, mail=False)
    api.run_pipeline(*PIPELINE, session="declined", save=lambda: asked.append(True) or False, mail=False)

    assert asked == [True]
    assert not (workspace / "reports" / "dropped").exists() and not (workspace / "reports" / "declined").exists()


def test_stages_that_cannot_run_stop_the_run_before_it_starts(workspace: Path) -> None:
    (workspace / "tools_bin" / "nuclei").unlink()
    seen = Recorder()

    with pytest.raises(api.PreflightError) as caught:
        api.run_pipeline(*PIPELINE, observer=seen)

    assert caught.value.blocking == [("vulns", "nuclei", "not installed")]
    assert seen.log == ["plan"]
    assert list((workspace / "reports").iterdir()) == []


def test_force_start_runs_the_stages_that_can(workspace: Path) -> None:
    (workspace / "tools_bin" / "nuclei").unlink()

    outcome = api.run_pipeline(*PIPELINE, force_start=True, save=False, mail=False)

    assert [stage.ok for stage in outcome.result.nodes] == [True, True, False] and outcome.exit_code() == 1


def test_a_session_that_is_not_a_plain_name_is_a_value_error() -> None:
    with pytest.raises(ValueError, match="plain directory name"):
        api.run_pipeline(*PIPELINE, session="../outside")


def test_an_unknown_pipeline_is_a_registry_error() -> None:
    with pytest.raises(RegistryError):
        api.run_pipeline("no-such-pipeline", "example.com")


def test_an_engine_failure_releases_the_records_store(monkeypatch: pytest.MonkeyPatch) -> None:
    async def broken(self: PipelineEngine, *_a: object, **_k: object) -> object:
        raise CyberfwError("the engine broke")

    real_close = SessionContext.close
    closed: list[bool] = []

    def counting_close(self: SessionContext) -> None:
        closed.append(True)
        real_close(self)

    monkeypatch.setattr(PipelineEngine, "run", broken)
    monkeypatch.setattr(SessionContext, "close", counting_close)

    with pytest.raises(CyberfwError, match="the engine broke"):
        api.run_pipeline(*PIPELINE)

    assert closed == [True]


def test_a_plan_lists_the_stages_what_blocks_and_whether_it_is_ready(workspace: Path) -> None:
    plan = api.plan_pipeline(*PIPELINE)

    assert plan.ready and [stage.tool for stage in plan.stages] == ["subfinder", "httpx", "nuclei"]

    (workspace / "tools_bin" / "nuclei").unlink()
    blocked = api.plan_pipeline("recon-to-vuln")

    assert not blocked.ready and blocked.target is None
    assert blocked.blocking == (api.Blocker("vulns", "nuclei", "not installed"),)


def test_a_tool_run_returns_its_records_and_writes_nothing_unless_saved() -> None:
    outcome = api.run_tool("subfinder", target="example.com")

    assert [record.target for record in outcome.result.records] == ["sub.example.com"]
    assert outcome.succeeded and outcome.reports == {} and not outcome.session_dir.exists()


def test_a_saved_tool_run_writes_its_reports(workspace: Path) -> None:
    outcome = api.run_tool("subfinder", target="example.com", session="once", save=True)

    assert sorted(outcome.reports) == ["html", "json"]
    assert outcome.reports["json"] == workspace / "reports" / "once" / "report.json"


def test_a_tool_run_asks_to_save_only_when_it_found_something(workspace: Path) -> None:
    base._silence_tool(workspace, "subfinder")
    asked: list[bool] = []

    outcome = api.run_tool("subfinder", target="example.com", save=lambda: asked.append(True) or True)

    assert asked == [] and outcome.reports == {}


def test_a_tool_run_with_nothing_to_work_on_finds_nothing() -> None:
    outcome = api.run_tool("subfinder")

    assert outcome.succeeded and outcome.result.records == []


def test_a_target_the_tool_cannot_take_is_a_value_error() -> None:
    with pytest.raises(ValueError, match="local repository directory"):
        api.run_tool("gitleaks", target="https://utm.md/")


def test_a_tool_that_is_not_installed_is_not_found(workspace: Path) -> None:
    (workspace / "tools_bin" / "subfinder").unlink()

    with pytest.raises(ToolNotFoundError):
        api.run_tool("subfinder", target="example.com")


def test_saved_runs_load_compare_and_export(workspace: Path) -> None:
    first, _ = _two_saved_runs(workspace)

    one, two = api.load_run("one"), api.load_run(workspace / "reports" / "two")
    changes = api.compare_runs(one, two)
    sarif = api.export_sarif(two)

    assert one.path == first.reports["json"]
    assert changes.new_findings_at_least("high") == 1
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    assert "nuclei,vuln,high,https://sub.example.com/login,SQLi,false" in api.export_csv(two).splitlines()


def test_a_run_that_was_never_saved_is_not_found() -> None:
    with pytest.raises(FileNotFoundError):
        api.load_run("never-saved")


def test_scan_controls_override_only_what_the_caller_set() -> None:
    overrides = api._scan_control_overrides

    assert overrides(severity="", tags="", rate_limit=None, exclude=[]) == {}
    assert overrides(severity="high", tags="", rate_limit=None, exclude=[]) == {"severity": "high"}
    assert overrides(severity="high", tags="cve", rate_limit=20, exclude=["*.dev"]) == {
        "severity": "high", "tags": "cve", "rate_limit": 20, "exclude": ["*.dev"],
    }
```

- [ ] **Step 2: Run them to see them fail**

Run: `uv run --quiet python -m pytest tests/unit/test_api.py -q`
Expected: collection error — `ImportError: cannot import name 'api' from 'cyberfw'`.

- [ ] **Step 3: Create the API**

Create `cyberfw/api.py`:

```python
"""cyberfw's Python API: run a pipeline or one tool, plan a pipeline, read and compare saved runs.

Stable within a major version: the functions and types in ``__all__``.
``cyberfw.core`` and ``cyberfw.cli`` are internal. Nothing here prints, prompts
or calls ``sys.exit``: results come back as data, progress goes to an optional
:class:`RunObserver`, and logging is the caller's to set up. The calls are
synchronous and run their own event loop — call them from plain code, not from
inside a running asyncio loop.

Example::

    from cyberfw import api

    outcome = api.run_pipeline("recon-to-vuln", "example.com", save=False)
    print(outcome.succeeded, len(outcome.result.records), outcome.exit_code())
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cyberfw.config import Settings, load_settings
from cyberfw.core.events import (
    MailSummary,
    Note,
    RunObserver,
    StepEvent,
    StepName,
    StepSummary,
    Stream,
    TakeoverSummary,
    TlsSummary,
    VtSummary,
)
from cyberfw.core.finish import finalize, run_info
from cyberfw.core.scan import (
    Blocker,
    Plan,
    PlanStage,
    choose_wordlist,
    execute_pipeline,
    plan_of,
    prepare_pipeline,
)
from cyberfw.core.sessions import checked_session, open_session
from cyberfw.core.steps import post_scan
from cyberfw.core.tool_run import check_tool, keep_tool_run, run_tool_once
from cyberfw.core.workspace import open_manager
from cyberfw.exceptions import PreflightError
from cyberfw.pipeline.engine import PipelineResult, StageEvent
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.report import diff as rundiff
from cyberfw.report.csv_report import to_csv
from cyberfw.report.diff import RunDiff
from cyberfw.report.run_info import RunInfo
from cyberfw.report.sarif import to_sarif
from cyberfw.threatintel import IntelSummary

__all__ = [
    "Blocker",
    "IntelSummary",
    "MailSummary",
    "Note",
    "PipelineResult",
    "Plan",
    "PlanStage",
    "PreflightError",
    "RunDiff",
    "RunInfo",
    "RunObserver",
    "RunOutcome",
    "SavedRun",
    "StageEvent",
    "StepEvent",
    "StepName",
    "StepSummary",
    "Stream",
    "TakeoverSummary",
    "TlsSummary",
    "ToolRecord",
    "VtSummary",
    "compare_runs",
    "export_csv",
    "export_sarif",
    "load_run",
    "plan_pipeline",
    "run_pipeline",
    "run_tool",
]


@dataclass
class RunOutcome:
    """What a run produced: its result, its facts, where it was kept, what changed."""

    #: The stages, their records and timing; hosts kept out of scope in ``excluded``.
    result: PipelineResult
    run: RunInfo
    session_id: str
    session_dir: Path
    #: The reports written, by format (``json``, ``html``); empty when the run was not saved.
    reports: dict[str, Path]
    #: What changed since the earlier run it was compared with, if it was.
    changes: RunDiff | None
    #: Every note the run sent, in order.
    notes: list[Note] = field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        """Every stage ran and finished cleanly."""
        return self.result.succeeded()

    def alert_hits(self, severity: str = "low") -> int:
        """New findings at ``severity`` or worse since the earlier run; 0 without a comparison."""
        _check_severity(severity)
        return self.changes.new_findings_at_least(severity) if self.changes is not None else 0

    def exit_code(self, alert_severity: str | None = None) -> int:
        """The CLI's exit code for this run: 1 when it failed — a broken scan is
        reported as broken, never as "nothing new" — 3 when ``alert_severity`` is
        given and there are new findings at it or worse, else 0."""
        if not self.succeeded:
            return 1
        if alert_severity is not None and self.alert_hits(alert_severity):
            return 3
        return 0


@dataclass(frozen=True)
class SavedRun:
    """A saved run: its ``report.json`` and what it holds."""

    path: Path
    payload: dict[str, Any]


def _check_severity(severity: str) -> None:
    if severity not in rundiff.REAL:
        raise ValueError(f"severity must be one of {', '.join(rundiff.REAL)}, got {severity!r}")


def _scan_control_overrides(
    *, severity: str, tags: str, rate_limit: int | None, exclude: list[str]
) -> dict[str, object]:
    """The ``Settings`` fields to override for this run — only the controls the
    caller actually set, so an unset flag leaves the env/YAML/default in place."""
    overrides: dict[str, object] = {}
    if severity:
        overrides["severity"] = severity
    if tags:
        overrides["tags"] = tags
    if rate_limit is not None:
        overrides["rate_limit"] = rate_limit
    if exclude:
        overrides["exclude"] = exclude
    return overrides


def _settings(
    settings: Settings | None,
    *,
    severity: str = "",
    tags: str = "",
    rate_limit: int | None = None,
    exclude: Sequence[str] = (),
) -> Settings:
    """The settings for one call: as given, else loaded the way the CLI loads them;
    the scan controls the caller set override them for this call only."""
    settings = settings if settings is not None else load_settings()
    settings.ensure_dirs()
    overrides = _scan_control_overrides(severity=severity, tags=tags, rate_limit=rate_limit, exclude=list(exclude))
    return settings.model_copy(update=overrides) if overrides else settings


class _Relay(RunObserver):
    """Passes every event on to the caller's observer and keeps the notes for the outcome."""

    def __init__(self, observer: RunObserver | None) -> None:
        self._observer = observer if observer is not None else RunObserver()
        self.notes: list[Note] = []

    def on_plan(self, plan: Plan) -> None:
        self._observer.on_plan(plan)

    def on_stage(self, event: StageEvent) -> None:
        self._observer.on_stage(event)

    def on_record(self, record: ToolRecord) -> None:
        self._observer.on_record(record)

    def on_output(self, line: str, stream: Stream) -> None:
        self._observer.on_output(line, stream)

    def on_step(self, event: StepEvent) -> None:
        self._observer.on_step(event)

    def on_note(self, note: Note) -> None:
        self.notes.append(note)
        self._observer.on_note(note)


def run_pipeline(
    name: str,
    target: str,
    *,
    settings: Settings | None = None,
    ffuf: bool = False,
    wordlist: str | None = None,
    gowitness: bool | None = None,
    max_httpx: int = 0,
    severity: str = "",
    tags: str = "",
    rate_limit: int | None = None,
    exclude: Sequence[str] = (),
    mail: bool = True,
    takeover: bool = True,
    intel: bool = True,
    vt_key: str | None = None,
    vt_limit: int = 20,
    baseline: str | None = None,
    compare: bool = True,
    session: str | None = None,
    save: bool | Callable[[], bool] = True,
    force_start: bool = False,
    observer: RunObserver | None = None,
) -> RunOutcome:
    """Run a pipeline against ``target`` and finish it: the checks after the scan,
    triage, the comparison with an earlier run, and the reports.

    ``settings`` default to the CLI's (env, ``config.local.yaml``); ``severity``,
    ``tags``, ``rate_limit`` and ``exclude`` override them for this call only.
    VirusTotal runs only with ``vt_key`` — the API never looks for a key or asks.
    ``baseline`` names the earlier run to compare with (else the newest of the same
    pipeline and seed); ``compare=False`` skips the comparison. ``save`` keeps the
    reports; a callable is asked after the comparison, before anything is written.
    A session this call made is removed when the run is not saved.

    Raises :class:`ValueError` (no target; a session that is not a plain name),
    :class:`RegistryError` (an unknown pipeline, or a tool it names),
    :class:`PreflightError` (stages cannot run and ``force_start`` is not set),
    :class:`ReportError` (the reports cannot be written) and
    :class:`CyberfwError` (the engine itself failed).
    """
    if not target:
        raise ValueError("a pipeline needs a target")
    if session:
        checked_session(session)
    settings = _settings(settings, severity=severity, tags=tags, rate_limit=rate_limit, exclude=exclude)
    relay = _Relay(observer)
    manager = open_manager(settings)
    try:
        prepared = prepare_pipeline(
            name, target, settings=settings, manager=manager, ffuf=ffuf, gowitness=gowitness, max_httpx=max_httpx
        )
        relay.on_plan(plan_of(prepared))
        for warning in prepared.warnings:
            relay.on_note(Note("warn", warning))
        if prepared.blocking and not force_start:
            raise PreflightError(prepared.blocking)
        chosen = choose_wordlist(settings, wordlist, ffuf=ffuf, observer=relay)
        run_session = open_session(settings.reports_dir, kind="pipeline", name=name, session=session, stream=True)
    except BaseException:
        manager.close()
        raise
    try:
        result = execute_pipeline(prepared, session=run_session, wordlist=chosen, observer=relay)
        post_scan(
            result, seed=target, settings=settings, mail=mail, takeover=takeover, intel=intel,
            vt_key=vt_key, vt_limit=vt_limit, observer=relay,
        )
        finished = finalize(
            result, manager=manager, settings=settings, name=name, seed=target,
            tools={node.tool for node in prepared.nodes}, session=run_session, compare=compare,
            baseline=baseline, save=save, observer=relay,
        )
    except BaseException:
        # The run never finished: release the records store (what streamed stays on disk).
        if run_session.context is not None:
            run_session.context.close()
        raise
    return RunOutcome(
        result=result, run=finished.run, session_id=run_session.id, session_dir=run_session.dir,
        reports=finished.reports, changes=finished.changes, notes=relay.notes,
    )


def plan_pipeline(
    name: str,
    target: str | None = None,
    *,
    settings: Settings | None = None,
    ffuf: bool = False,
    gowitness: bool | None = None,
    max_httpx: int = 0,
) -> Plan:
    """What :func:`run_pipeline` would run, without running it: each stage, the
    stage it reads, its tool's state, what blocks and what only weakens the run.
    Raises :class:`RegistryError` for an unknown pipeline or a tool it names."""
    settings = _settings(settings)
    manager = open_manager(settings)
    try:
        return plan_of(prepare_pipeline(
            name, target, settings=settings, manager=manager, ffuf=ffuf, gowitness=gowitness, max_httpx=max_httpx
        ))
    finally:
        manager.close()


def run_tool(
    tool: str,
    *,
    target: str | None = None,
    inputs: Sequence[str] = (),
    wordlist: str | None = None,
    settings: Settings | None = None,
    severity: str = "",
    tags: str = "",
    rate_limit: int | None = None,
    parse: bool = True,
    session: str | None = None,
    save: bool | Callable[[], bool] = False,
    observer: RunObserver | None = None,
) -> RunOutcome:
    """Run one registered tool on its own against ``target`` and/or ``inputs``.

    With neither, the tool has nothing to work on and finds nothing. Without
    ``parse`` every stdout line is a raw record. ``save=True`` streams the records
    into ``reports/<session>/`` as they arrive and writes both reports; a callable
    is asked after the run — only when it produced records — before anything is
    written; ``False`` writes nothing.

    Raises :class:`ValueError` (a target the tool cannot take; a session that is
    not a plain name), :class:`RegistryError` (an unknown tool) and
    :class:`ToolNotFoundError` (a tool that is not installed).
    """
    if session:
        checked_session(session)
    settings = _settings(settings, severity=severity, tags=tags, rate_limit=rate_limit)
    relay = _Relay(observer)
    manager = open_manager(settings)
    try:
        check_tool(manager, tool, target)
    except BaseException:
        manager.close()
        raise
    run_session = open_session(settings.reports_dir, kind="run", name=tool, session=session, stream=save is True)
    ran = run_tool_once(
        tool, settings=settings, manager=manager, target=target, inputs=inputs, wordlist=wordlist,
        parse=parse, session=run_session, observer=relay,
    )
    keep = save if isinstance(save, bool) else bool(ran.records) and save()
    reports = keep_tool_run(ran, settings=settings, manager=manager) if keep else {}
    return RunOutcome(
        result=ran.result,
        run=run_info(manager, name=tool, seed=target, session_id=run_session.id, tools={tool}),
        session_id=run_session.id, session_dir=run_session.dir, reports=reports, changes=None, notes=relay.notes,
    )


def load_run(ref: str | Path, *, settings: Settings | None = None) -> SavedRun:
    """A saved run, by session id, its directory or its ``report.json`` (looked up
    under ``reports/``). Raises :class:`FileNotFoundError` when there is none and
    :class:`ValueError` when the file is not a cyberfw report."""
    settings = settings if settings is not None else load_settings()
    path = rundiff.resolve_report(str(ref), settings.reports_dir)
    return SavedRun(path=path, payload=rundiff.load_report(path))


def compare_runs(old: SavedRun, new: SavedRun) -> RunDiff:
    """What changed from ``old`` to ``new``: findings, ports, subdomains, certificates, exploitation."""
    return rundiff.compare(old.payload, new.payload)


def export_sarif(run: SavedRun) -> dict[str, Any]:
    """The run's findings as a SARIF 2.1.0 document (for CI / code scanning)."""
    return to_sarif(run.payload)


def export_csv(run: SavedRun) -> str:
    """Every record of the run as CSV (for triage in a spreadsheet)."""
    return to_csv(run.payload)
```

Run: `uv run --quiet python -m pytest tests/unit/test_api.py -q`
Expected: still a collection error — `ImportError: cannot import name 'PreflightError' from 'cyberfw.exceptions'`: the next step adds it.

- [ ] **Step 4: `PreflightError`; the core rule and the test helpers cover the API; the CLI's scan controls come from it**

Save as `$W/task3_wiring.py`:

```python
"""Task 3: PreflightError, the core rule extended to the API, test helpers that reach it.

Usage: python task3_wiring.py <repo root>   (then: ruff check --fix --select F401,I001 cyberfw tests)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

PREFLIGHT_ERROR = '''

class PreflightError(CyberfwError):
    """Stages of a pipeline cannot run as things stand, and ``force_start`` was not given."""

    def __init__(self, blocking: Sequence[tuple[str, str, str]]) -> None:
        #: ``(stage, tool, reason)`` for each stage that cannot run.
        self.blocking = list(blocking)
        super().__init__("; ".join(f"{tool} ({stage}): {reason}" for stage, tool, reason in self.blocking))
'''

exceptions = Source(root, "cyberfw/exceptions.py")
exceptions.replace('    "ReportError",\n]\n', '    "ReportError",\n    "PreflightError",\n]\n')
exceptions.text = exceptions.text.rstrip("\n") + "\n" + PREFLIGHT_ERROR

layering = Source(root, "tests/unit/test_core_layering.py")
layering.replace(
    '"""cyberfw.core never reaches for the UI: no CLI, typer, Rich, presentation modules or console."""\n',
    '"""cyberfw.core and cyberfw.api never reach for the UI: no CLI, typer, Rich, presentation modules or console."""\n',
)
layering.replace(
    'CORE = Path(cyberfw.__file__).resolve().parent / "core"\n',
    'PACKAGE = Path(cyberfw.__file__).resolve().parent\n'
    'CORE = PACKAGE / "core"\n'
    '#: The core\'s modules, and the public API on top of them.\n'
    'CHECKED = [*sorted(CORE.glob("*.py")), PACKAGE / "api.py"]\n',
)
layering.replace("        for path in sorted(CORE.glob(\"*.py\"))\n", "        for path in CHECKED\n")
layering.replace(
    '    modules = [f"cyberfw.core.{path.stem}" for path in sorted(CORE.glob("*.py")) if path.stem != "__init__"]\n',
    '    modules = [f"cyberfw.core.{path.stem}" for path in sorted(CORE.glob("*.py")) if path.stem != "__init__"]\n'
    '    modules.append("cyberfw.api")\n',
)

helper = Source(root, "tests/unit/_cli.py")
helper.replace(
    "#: The packages whose modules tests reach into.\n"
    '_PACKAGES = ("cyberfw.cli", "cyberfw.core")\n',
    "#: The packages whose modules tests reach into, and the API module on top of them.\n"
    '_PACKAGES = ("cyberfw.cli", "cyberfw.core")\n'
    '_MODULES = ("cyberfw.api",)\n',
)
helper.replace(
    "                modules.append(importlib.import_module(f\"{package_name}.{info.name}\"))\n"
    "    return modules\n",
    "                modules.append(importlib.import_module(f\"{package_name}.{info.name}\"))\n"
    "    return modules + [importlib.import_module(name) for name in _MODULES]\n",
)
helper.replace(
    '    """Every module of the CLI and the core — found on disk, so a new one is never missed.\n',
    '    """Every module of the CLI and the core — found on disk, so a new one is never missed — and the API.\n',
)

seams = Source(root, "tests/unit/test_cli_seams.py")
seams.replace(
    "def test_the_helper_covers_every_cli_and_core_module() -> None:\n",
    "def test_the_helper_covers_every_cli_and_core_module_and_the_api() -> None:\n",
)
seams.replace(
    "        if path.stem not in {\"__init__\", \"__main__\"}\n    }\n",
    "        if path.stem not in {\"__init__\", \"__main__\"}\n    } | {\"cyberfw.api\"}\n",
)

cli = Source(root, "cyberfw/cli/scan.py")
cli.drop_defs("_scan_control_overrides")
cli.replace("from cyberfw.cli.app import app\n", "from cyberfw.api import _scan_control_overrides\nfrom cyberfw.cli.app import app\n")

cli_tests = Source(root, "tests/unit/test_cli.py")
cli_tests.replace(
    "    def test_overrides_picks_only_the_flags_that_were_set(self) -> None:\n"
    "        _scan_control_overrides = cli._scan_control_overrides\n"
    "\n"
    "        assert _scan_control_overrides(severity=\"\", tags=\"\", rate_limit=None, exclude=[]) == {}\n"
    "        assert _scan_control_overrides(severity=\"high\", tags=\"\", rate_limit=None, exclude=[]) == {\"severity\": \"high\"}\n"
    "        assert _scan_control_overrides(severity=\"high\", tags=\"cve\", rate_limit=20, exclude=[\"*.dev\"]) == {\n"
    "            \"severity\": \"high\", \"tags\": \"cve\", \"rate_limit\": 20, \"exclude\": [\"*.dev\"],\n"
    "        }\n"
    "\n",
    "",
)

for source in (exceptions, layering, helper, seams, cli, cli_tests):
    source.save()
```

```bash
uv run --quiet python "$W/task3_wiring.py" .
uv run --quiet ruff check --fix --select F401,I001 cyberfw tests
uv run --quiet python -m pytest tests/unit/test_api.py tests/unit/test_core_layering.py tests/unit/test_cli_seams.py -q
```

Expected: six `edited` lines; `All checks passed!`; `30 passed`.

- [ ] **Step 5: Run everything**

Run: `uv run --quiet python -m pytest -q`, `uv run --quiet ruff check .`, `uv run --quiet mypy cyberfw`
Expected: `1110 passed, 5 skipped, 8 deselected`; ruff clean; mypy `Success: no issues found in 75 source files`.

- [ ] **Step 6: The output is unchanged**

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/3-api" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -r "$W/transcripts/0-base" "$W/transcripts/3-api" && echo identical
```

Expected: `50 passed`, then `identical`.

- [ ] **Step 7: Commit**

```bash
git add cyberfw/api.py cyberfw/exceptions.py cyberfw/cli/scan.py tests/unit/test_api.py tests/unit/test_core_layering.py tests/unit/_cli.py tests/unit/test_cli_seams.py tests/unit/test_cli.py
git commit -m "Add cyberfw.api: runs, plans and saved runs as data"
```

---

### Task 4: `cyberfw pipeline` goes through the API

**Files:**
- Modify (by script): `cyberfw/cli/common.py`, `cyberfw/cli/scan.py` (`task4_cli.py`); `tests/unit/test_cli.py` (`task4_tests.py`)

**Interfaces:**
- Consumes: Task 3's `run_pipeline`, `plan_pipeline`, `Plan`, `PreflightError`, `RunOutcome`; Task 1's scan result on `done`.
- Produces, in `cyberfw/cli/common.py`: `_setup(*, verbose=False) -> Settings` (settings, directories, logging — no manager); `_bootstrap` is `_setup` plus `open_manager`.
- `_CliObserver(…, make_view=Callable[[Plan], view | None], before_scan=Callable[[], None])`, `.scan_result`. `_pipeline_exit_code` is gone: `RunOutcome.exit_code` and its tests in `test_api.py` replace it.

- [ ] **Step 1: Guard the error paths before rewiring them**

Save as `$W/task4_tests.py`:

```python
"""Task 4, guards first: the pipeline's error paths keep their messages and exit codes.

Usage: python task4_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

GUARDS = '''

class TestPipelineErrors:
    """What `pipeline` prints and returns when it cannot start, cannot finish, or cannot save."""

    def test_missing_dependencies_are_named_before_the_stages_that_cannot_run(self, tmp_path: Path) -> None:
        registry = (tmp_path / "registry.yaml").read_text(encoding="utf-8")
        (tmp_path / "registry.yaml").write_text(
            registry.replace("  binary: subfinder\\n", "  binary: subfinder\\n  check_deps: [cyberfw-test-missing-dep]\\n"),
            encoding="utf-8",
        )
        (tmp_path / "tools_bin" / "nuclei").unlink()

        res = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report", "--no-mail"])

        assert res.exit_code == 2
        assert res.stdout.index("works best with `cyberfw-test-missing-dep`") < res.stdout.index(
            "nuclei (vulns): not installed"
        ) < res.stdout.index("--force-start")

    def test_an_engine_failure_exits_1_with_its_message(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cyberfw.exceptions import CyberfwError
        from cyberfw.pipeline.engine import PipelineEngine

        async def broken(self: object, *_a: object, **_k: object) -> object:
            raise CyberfwError("the engine [broke]")

        monkeypatch.setattr(PipelineEngine, "run", broken)

        res = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--no-report", "--no-mail"])

        assert res.exit_code == 1 and res.stdout.rstrip().endswith("the engine [broke]")

    def test_reports_that_cannot_be_written_are_reported_and_the_run_ends(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cyberfw.exceptions import ReportError

        def refuse(*_a: object, **_k: object) -> object:
            raise ReportError("cannot write report.json: [denied]")

        patch_cli(monkeypatch, "generate_json_report", refuse)

        res = runner.invoke(app, ["pipeline", "recon-to-vuln", "-t", "example.com", "--session", "w", "--no-mail"])

        assert res.exit_code == 0
        assert res.stdout.rstrip().endswith("report failed: cannot write report.json: [denied]")
'''

tests = Source(root, "tests/unit/test_cli.py")
# A report that cannot be written is a ReportError — what the JSON and HTML writers
# raise, and what the API tells apart from an engine failure.
tests.replace(
    "    def test_a_report_error(self, monkeypatch: pytest.MonkeyPatch) -> None:\n"
    "        from cyberfw.exceptions import CyberfwError\n"
    "\n"
    "        def broken(*_args: object, **_kwargs: object) -> None:\n"
    "            raise CyberfwError(\"cannot write [x]\")\n",
    "    def test_a_report_error(self, monkeypatch: pytest.MonkeyPatch) -> None:\n"
    "        from cyberfw.exceptions import ReportError\n"
    "\n"
    "        def broken(*_args: object, **_kwargs: object) -> None:\n"
    "            raise ReportError(\"cannot write [x]\")\n",
)
tests.replace_span(
    "class TestAlertExitCode:\n",
    "        assert _pipeline_exit_code(succeeded=True, alert_hits=0) == 0\n\n\n",
    "",
)
tests.text = tests.text.rstrip("\n") + "\n" + GUARDS
tests.save()
```

```bash
uv run --quiet python "$W/task4_tests.py" .
uv run --quiet python -m pytest tests/unit/test_cli.py -q -k "TestPipelineErrors or report_error or TestAlertExitCode"
```

Expected: `edited tests/unit/test_cli.py`, then `4 passed, 271 deselected` — the three new guards and the report-error test pass on today's code (they must stay green); `TestAlertExitCode` is gone.

- [ ] **Step 2: Rewire `pipeline` and `pipeline --plan` onto the API**

Save as `$W/task4_cli.py`:

```python
"""Task 4: `cyberfw pipeline` and `pipeline --plan` go through cyberfw.api.

Usage: python task4_cli.py <repo root>   (then: ruff check --fix --select F401,I001 cyberfw)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

SETUP = '''def _setup(*, verbose: bool = False) -> Settings:
    """Load the settings, make sure their directories exist, wire logging.

    ``verbose`` forces this process's log level to DEBUG regardless of the
    configured ``log_level``, so ``-v`` surfaces the install/download trace
    without a permanent config change.
    """
    settings = load_settings()
    if verbose and settings.log_level != "DEBUG":
        settings = settings.model_copy(update={"log_level": "DEBUG"})
    settings.ensure_dirs()
    setup_logging(level=settings.log_level, log_dir=settings.logs_dir, log_to_file=settings.log_to_file)
    return settings


def _bootstrap(*, verbose: bool = False) -> tuple[Settings, ToolManager]:
    """:func:`_setup`, and a tool manager over the registry in use."""
    settings = _setup(verbose=verbose)
    return settings, open_manager(settings)
'''

SCAN_HOOK = '''    def on_plan(self, plan: Plan) -> None:
        if self.make_view is not None:
            self.view = self.make_view(plan)

    def _scan(self, event: StepEvent) -> None:
        """As the scan starts its lead-in lines, then the live view; as it ends the
        view's final frame — and the scan's result, for whoever prints it later."""
        if event.kind == "start":
            if self.before_scan is not None:
                self.before_scan()
            if self.view is not None:
                self._live = Live(self.view, console=console, refresh_per_second=self.fps, transient=False)
                self._live.start(refresh=True)
        elif event.kind == "done":
            if isinstance(event.summary, PipelineResult):
                self.scan_result = event.summary
            if self.view is not None and self._live is not None:
                try:
                    self.view.finish()
                    self._live.refresh()
                finally:  # a view that fails to finish must not leave the display live
                    self._live.stop()
                    self._live = None
                    _after_live()
'''

PIPELINE_BODY = '''    settings = _setup(verbose=verbose)
    # Resolve the VirusTotal key up front (and prompt if needed) before the live
    # view takes over the terminal — a prompt and a Live render cannot coexist.
    # A --plan dry run scans nothing, so it never prompts for a key.
    vt_key = None if plan else _resolve_vt_key(settings, vt_enrich)
    if plan:
        try:
            dry_run = plan_pipeline(name, target, settings=settings, ffuf=ffuf, gowitness=gowitness, max_httpx=max_httpx)
        except RegistryError as exc:
            console.print(f"[err]{escape(str(exc))}[/err]")
            raise typer.Exit(2) from exc
        console.print(_plan_view(dry_run))
        return
    assert target is not None  # a non-plan run required --target above; narrows for the scan path

    # Verbose view when parsing is disabled (config parse=false or --no-parse):
    # stream each stage's raw stdout/stderr live instead of the quiet spinner.
    # Stages are still parsed internally so results thread from one to the next.
    verbose = no_parse or not settings.parse
    # The flag overrides the `view` setting for this run; unset falls back to it.
    use_topology = topology if topology is not None else settings.view == "topology"

    def _make_view(prepared: Plan) -> PipelineLiveView | TopologyView | None:
        if verbose:
            return None
        nodes = [Node(tool=stage.tool, stage=stage.stage) for stage in prepared.stages]
        if use_topology:
            return TopologyView(nodes, seed=target, title=f"{name} · {target}", animate=settings.animations)
        return PipelineLiveView(nodes, title=f"pipeline {name} · {target}", animate=settings.animations)

    def _before_scan() -> None:
        if topology is True and verbose:
            # Only when the user explicitly asked: the config default silently yields
            # to the raw stream under --no-parse rather than nagging every run.
            why = "--no-parse" if no_parse else "config parse=false"
            console.print(f"[warn]--topology needs the parsed view; ignored under {why}.[/warn]")
        if verbose:
            why = "--no-parse" if no_parse else "config parse=false"
            console.print(f"[muted]{why}: streaming raw stdout/stderr from every stage[/muted]")

    observer = _CliObserver(
        animate=settings.animations, make_view=_make_view, before_scan=_before_scan,
        echo_output=verbose, fps=_live_fps(settings),
    )

    def _decide() -> bool:
        # Asked once the comparison is on screen; the raw stream's stage table comes first.
        if verbose and observer.scan_result is not None:
            console.print(_node_table(observer.scan_result))
        return _wants_to_save(report, default=True, what=name)

    try:
        outcome = run_pipeline(
            name, target, settings=settings, ffuf=ffuf, wordlist=wordlist, gowitness=gowitness,
            max_httpx=max_httpx, severity=severity, tags=tags, rate_limit=rate_limit, exclude=exclude or [],
            mail=mail, takeover=takeover, intel=intel, vt_key=vt_key, vt_limit=vt_limit, baseline=baseline,
            compare=not no_baseline, session=session, save=_decide, force_start=force_start, observer=observer,
        )
    except RegistryError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(2) from exc
    except PreflightError as exc:
        # Whether the run can happen at all is knowable before it starts, and a
        # scan takes minutes: say what is unavailable instead of spending the time.
        for stage, tool, reason in exc.blocking:
            console.print(f"[err]{tool}[/err] ({stage}): [err]{reason}[/err]")
        console.print(
            "[warn]Fix the above (`cyberfw init`, `cyberfw status`), "
            "or pass --force-start to run the stages that can.[/warn]"
        )
        raise typer.Exit(2) from exc
    except ReportError as exc:
        console.print(f"[err]report failed:[/err] {escape(str(exc))}")
        return
    except CyberfwError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(1) from exc

    # A blank line: Live's last frame ends without one, so the panel would
    # otherwise start on the same line as the table's bottom edge.
    console.print()
    motion.play(
        console,
        lambda progress: _run_summary(
            outcome.result, name=name, session_id=outcome.session_id, reports=list(outcome.reports.items()),
            progress=progress,
        ),
        duration=0.7,
        animate=settings.animations,
    )

    alert_hits = outcome.alert_hits(alert_severity) if alert else 0
    if alert_hits:
        base = outcome.changes.baseline.get("session_id") if outcome.changes else None
        since = f" since {base}" if base else ""
        console.print(
            f"[err]ALERT: {alert_hits} new finding(s) >= {alert_severity}{since}[/err]"
        )

    code = outcome.exit_code(alert_severity if alert else None)
    if code:
        raise typer.Exit(code)
'''

common = Source(root, "cyberfw/cli/common.py")
common.replace_span(
    "def _bootstrap(*, verbose: bool = False) -> tuple[Settings, ToolManager]:\n",
    "    return settings, open_manager(settings)\n",
    SETUP,
)

scan = Source(root, "cyberfw/cli/scan.py")
scan.drop_defs("_pipeline_exit_code")
scan.replace(
    "        raw_records: bool = False,\n        fps: int = 4,\n    ) -> None:\n",
    "        raw_records: bool = False,\n        fps: int = 4,\n"
    "        make_view: Callable[[Plan], PipelineLiveView | TopologyView | None] | None = None,\n"
    "        before_scan: Callable[[], None] | None = None,\n"
    "    ) -> None:\n",
)
scan.replace(
    "        self.fps = fps\n",
    "        self.fps = fps\n"
    "        #: Builds the live view from the plan the run sends first (``pipeline``).\n"
    "        self.make_view = make_view\n"
    "        #: Prints what comes right before the scan: the mode lines, a tool's header.\n"
    "        self.before_scan = before_scan\n"
    "        #: The scan's own result, once it has ended.\n"
    "        self.scan_result: PipelineResult | None = None\n",
)
scan.replace_span(
    "    def _scan(self, event: StepEvent) -> None:\n",
    "                self._live = None\n                _after_live()\n",
    SCAN_HOOK,
)
scan.replace_span(
    "    settings, manager = _bootstrap(verbose=verbose)\n    overrides = _scan_control_overrides(\n",
    "    code = _pipeline_exit_code(succeeded=result.succeeded(), alert_hits=alert_hits)\n"
    "    if code:\n        raise typer.Exit(code)\n",
    PIPELINE_BODY,
)
scan.replace(
    "from cyberfw.api import _scan_control_overrides\n",
    "from cyberfw.api import Plan, _scan_control_overrides, plan_pipeline, run_pipeline\n",
)
scan.replace(
    "from cyberfw.cli.common import (\n    VerboseOption,\n",
    "from cyberfw.cli.common import (\n    VerboseOption,\n    _setup,\n",
)
scan.replace("from pathlib import Path\n", "from collections.abc import Callable\nfrom pathlib import Path\n")
scan.replace(
    "from cyberfw.exceptions import (\n",
    "from cyberfw.exceptions import (\n    PreflightError,\n    ReportError,\n",
)
scan.replace("from cyberfw.pipeline.engine import (\n", "from cyberfw.pipeline.engine import (\n    PipelineResult,\n")

for source in (common, scan):
    source.save()
```

```bash
uv run --quiet python "$W/task4_cli.py" .
uv run --quiet ruff check --fix --select F401,I001 cyberfw
uv run --quiet python -m pytest tests/unit/test_cli.py -q -k "TestPipelineErrors or report_error"
```

Expected: `edited cyberfw/cli/common.py`, `edited cyberfw/cli/scan.py`; `Found 7 errors (7 fixed, 0 remaining).`; `4 passed, 271 deselected`.

- [ ] **Step 3: Run everything**

Run: `uv run --quiet python -m pytest -q`, `uv run --quiet ruff check .`, `uv run --quiet mypy cyberfw`
Expected: `1110 passed, 5 skipped, 8 deselected`; ruff clean; mypy `Success: no issues found in 75 source files`.

- [ ] **Step 4: The output is unchanged**

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/4-pipeline" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -r "$W/transcripts/0-base" "$W/transcripts/4-pipeline" && echo identical
```

Expected: `50 passed`, then `identical` — every `pipeline` scenario, the error paths included.

- [ ] **Step 5: Commit**

```bash
git add cyberfw/cli/common.py cyberfw/cli/scan.py tests/unit/test_cli.py
git commit -m "Run cyberfw pipeline and pipeline --plan through cyberfw.api"
```

---

### Task 5: `run`, `diff` and `export` go through the API; the docs

**Files:**
- Create: `tests/unit/test_api_readme.py`
- Modify (by script): `tests/unit/test_cli_package.py` (`task5_tests.py`); `cyberfw/cli/scan.py`, `cyberfw/cli/reports.py` (`task5_cli.py`); `README.md`, `CHANGELOG.md` (`task5_docs.py`)

**Interfaces:**
- Consumes: Task 3's `run_tool`, `load_run`, `compare_runs`, `export_sarif`, `export_csv`; Task 4's `_setup` and observer hooks.
- `_CliObserver(…, after_scan=Callable[[PipelineResult], None])` prints a tool's records once its scan ended. After this task `cli/scan.py` and `cli/reports.py` import none of the core's orchestration (`test_the_run_commands_go_through_the_public_api`).

- [ ] **Step 1: The run commands go through the API — failing test first**

Save as `$W/task5_tests.py`:

```python
"""Task 5, test first: the run commands are the public API's first users.

Usage: python task5_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

GUARD = '''

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
'''

tests = Source(root, "tests/unit/test_cli_package.py")
tests.text = tests.text.rstrip("\n") + "\n" + GUARD
tests.save()
```

```bash
uv run --quiet python "$W/task5_tests.py" .
uv run --quiet python -m pytest tests/unit/test_cli_package.py -q
```

Expected: `edited tests/unit/test_cli_package.py`, then `1 failed, 4 passed` — `assert {'cyberfw.cor...ore.tool_run'} == set()`: `cli/scan.py` still imports `core.sessions` and `core.tool_run`.

- [ ] **Step 2: The README's example must run — failing test first**

Create `tests/unit/test_api_readme.py`:

```python
"""The Python API example in README.md runs as written — against the CLI tests' fake tools."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from .test_cli import _workspace  # noqa: F401 - the fake-tools workspace, autouse

README = Path(__file__).resolve().parents[2] / "README.md"
FENCE = "`" * 3


def test_the_readme_example_runs(capsys: pytest.CaptureFixture[str]) -> None:
    text = README.read_text(encoding="utf-8")
    section = text[text.index("## Python API") : text.index("## Разработка")]
    example = re.search(FENCE + r"python\n(.*?)\n" + FENCE, section, re.S)
    assert example is not None, "the Python API section shows an example"

    with pytest.raises(SystemExit) as stopped:
        exec(compile(example[1], "README.md", "exec"), {})  # noqa: S102 - the example is the test

    lines = capsys.readouterr().out.splitlines()
    assert "done: scan" in lines and lines[-1].startswith("True ")
    assert stopped.value.code == 0
```

Run: `uv run --quiet python -m pytest tests/unit/test_api_readme.py -q`
Expected: `1 failed` — `ValueError: substring not found` (there is no "Python API" section yet).

- [ ] **Step 3: Rewire `run`, `diff` and `export`**

Save as `$W/task5_cli.py`:

```python
"""Task 5: `cyberfw run`, `diff` and `export` go through cyberfw.api.

Usage: python task5_cli.py <repo root>   (then: ruff check --fix --select F401,I001 cyberfw)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

RUN_BODY = '''    settings = _setup(verbose=verbose)
    hosts = _read_hosts(list_file) if list_file is not None else []
    target_label = target or f"{len(hosts)} host(s) from {list_file}"
    # Parsing is on by default; disable it via the config `parse:` setting
    # (CYBERFW_PARSE=false) or override per-run with --no-parse.
    do_parse = settings.parse and not no_parse

    def _header() -> None:
        console.print(f"[info]tool:[/info] [tool]{tool}[/tool]  [info]target:[/info] {target_label}")
        if not do_parse:
            why = "--no-parse" if no_parse else "config parse=false"
            console.print(f"[muted]{why}: streaming raw stdout/stderr exactly as the tool prints it[/muted]")

    def _records(result: PipelineResult) -> None:
        if not do_parse:
            console.print(f"[info]{len(result.records)} line(s) captured[/info]")
        elif result.records:
            console.print(_record_table(result.records, tool=tool, target=target_label))
        else:
            console.print("[muted]No records found.[/muted]")

    view = (
        PipelineLiveView([Node(tool=tool, stage=tool)], title=f"{tool} · {target_label}", animate=settings.animations)
        if do_parse
        else None
    )
    observer = _CliObserver(
        animate=settings.animations, view=view, raw_records=not do_parse, fps=_live_fps(settings),
        before_scan=_header, after_scan=_records,
    )
    # --save streams into reports/<session>/ as records arrive (crash-safe). An
    # undecided run asks once the results are on screen, and only when there is
    # something to keep, so an ad-hoc `run` never litters the filesystem.
    decide = save if save is not None else (lambda: _wants_to_save(None, default=False, what=tool))
    try:
        # The adapter knows what kind of target it takes; that is checked before
        # the binary is looked for, so a wrong target is a usage error (exit 2).
        outcome = run_tool(
            tool, target=target, inputs=hosts, wordlist=wordlist, settings=settings, severity=severity,
            tags=tags, rate_limit=rate_limit, parse=do_parse, session=session, save=decide, observer=observer,
        )
    except ValueError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(2) from exc
    except ToolNotFoundError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        console.print("[warn]Run `cyberfw init` first (or export CYBERFW_GITHUB_TOKEN).[/warn]")
        raise typer.Exit(1) from exc
    except CyberfwError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(1) from exc

    if outcome.reports:
        console.print(f"[ok]saved:[/ok] {outcome.session_dir}")
        for label, path in outcome.reports.items():
            console.print(f"[ok]{label}:[/ok] {path}")

    (stage,) = outcome.result.nodes
    if not stage.ok:
        console.print(f"[err]{escape(stage.error or 'stage failed')}[/err]")
        raise typer.Exit(1)
'''

scan = Source(root, "cyberfw/cli/scan.py")
scan.replace_span(
    "    settings, manager = _bootstrap(verbose=verbose)\n"
    "    overrides = _scan_control_overrides(severity=severity, tags=tags, rate_limit=rate_limit, exclude=[])\n",
    "    if not ran.node.ok:\n"
    "        console.print(f\"[err]{escape(ran.node.error or 'stage failed')}[/err]\")\n"
    "        raise typer.Exit(1)\n",
    RUN_BODY,
)
scan.replace(
    "        before_scan: Callable[[], None] | None = None,\n    ) -> None:\n",
    "        before_scan: Callable[[], None] | None = None,\n"
    "        after_scan: Callable[[PipelineResult], None] | None = None,\n"
    "    ) -> None:\n",
)
scan.replace(
    "        self.before_scan = before_scan\n",
    "        self.before_scan = before_scan\n"
    "        #: Prints what the scan's result shows right after it: a tool's records.\n"
    "        self.after_scan = after_scan\n",
)
scan.replace(
    "                finally:  # a view that fails to finish must not leave the display live\n"
    "                    self._live.stop()\n"
    "                    self._live = None\n"
    "                    _after_live()\n",
    "                finally:  # a view that fails to finish must not leave the display live\n"
    "                    self._live.stop()\n"
    "                    self._live = None\n"
    "                    _after_live()\n"
    "            if self.after_scan is not None and self.scan_result is not None:\n"
    "                self.after_scan(self.scan_result)\n",
)
scan.replace(
    "from cyberfw.api import Plan, _scan_control_overrides, plan_pipeline, run_pipeline\n",
    "from cyberfw.api import Plan, plan_pipeline, run_pipeline, run_tool\n",
)
scan.replace(
    '"""`run` and `pipeline`: their flags, questions and rendering — the runs themselves are cyberfw.core\'s."""\n',
    '"""`run` and `pipeline`: their flags, questions and rendering — the runs themselves go through cyberfw.api."""\n',
)

reports = Source(root, "cyberfw/cli/reports.py")
reports.replace(
    "        before = rundiff.load_report(rundiff.resolve_report(old, settings.reports_dir))\n"
    "        after = rundiff.load_report(rundiff.resolve_report(new, settings.reports_dir))\n",
    "        before, after = load_run(old, settings=settings), load_run(new, settings=settings)\n",
)
reports.replace("    changes = rundiff.compare(before, after)\n", "    changes = compare_runs(before, after)\n")
reports.replace(
    "        payload = rundiff.load_report(rundiff.resolve_report(run, settings.reports_dir))\n",
    "        saved = load_run(run, settings=settings)\n",
)
reports.replace(
    "    document = json.dumps(to_sarif(payload), ensure_ascii=False, indent=2) if sarif else to_csv(payload)\n",
    "    document = json.dumps(export_sarif(saved), ensure_ascii=False, indent=2) if sarif else export_csv(saved)\n",
)
reports.replace("from cyberfw.cli.app import app\n", "from cyberfw.api import compare_runs, export_csv, export_sarif, load_run\nfrom cyberfw.cli.app import app\n")

for source in (scan, reports):
    source.save()
```

```bash
uv run --quiet python "$W/task5_cli.py" .
uv run --quiet ruff check --fix --select F401,I001 cyberfw
uv run --quiet python -m pytest tests/unit/test_cli_package.py -q
```

Expected: `edited cyberfw/cli/scan.py`, `edited cyberfw/cli/reports.py`; `Found 8 errors (8 fixed, 0 remaining).`; `5 passed`.

- [ ] **Step 4: The docs**

Save as `$W/task5_docs.py`:

```python
"""Task 5: the Python API in README and CHANGELOG; the structure section names the real modules.

Usage: python task5_docs.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])
FENCE = "`" * 3

API_SECTION = f"""## Python API

Всё, что CLI делает с прогонами, доступно из Python — для своих скриптов и CI.
`cyberfw.api` стабилен в пределах мажорной версии; `cyberfw.core` и
`cyberfw.cli` — внутренние. API ничего не печатает, не спрашивает и не вызывает
`sys.exit`: результат возвращается данными, ход прогона — через необязательный
наблюдатель, логирование настраивает вызывающий.

{FENCE}python
from cyberfw import api


class Progress(api.RunObserver):
    def on_step(self, event: api.StepEvent) -> None:
        if event.kind == "done":
            print("done:", event.step)


outcome = api.run_pipeline("recon-to-vuln", "example.com", save=False, observer=Progress())
print(outcome.succeeded, len(outcome.result.records))
raise SystemExit(outcome.exit_code(alert_severity="high"))  # 0 / 1 / 3, как у CLI
{FENCE}

- `run_pipeline(name, target, ...)` → `RunOutcome`: `result` (этапы, записи,
  время), `run`, `session_id`, `session_dir`, `reports`, `changes`, `notes`;
  `succeeded`, `alert_hits(severity)`, `exit_code(alert_severity)`. `save` —
  `True`/`False` или функция, которую спросят после сравнения, до записи отчётов.
- `plan_pipeline(name, target=None, ...)` → `Plan`: этапы, что каждый читает,
  состояние инструментов, что блокирует запуск (`ready`).
- `run_tool(tool, target=..., inputs=..., save=...)` → `RunOutcome`.
- `load_run(ref)` → `SavedRun`; `compare_runs(old, new)`, `export_sarif(run)`,
  `export_csv(run)`.
- Ошибки: `RegistryError` (неизвестный pipeline или инструмент), `ValueError`
  (цель не того вида, сессия не простым именем, неизвестная severity),
  `PreflightError` с `.blocking` (этапы не могут запуститься без `force_start`),
  `ToolNotFoundError`, `ReportError`, `FileNotFoundError` из `load_run`.
- Вызовы синхронные и запускают свой event loop — вызывайте их из обычного кода,
  не изнутри работающего asyncio-цикла.

"""

readme = Source(root, "README.md")
readme.replace(
    "  core/                  прогон без интерфейса: реестр и lock (workspace), сессии, события\n"
    "                         (events), подготовка, запуск и завершение скана (runs)\n",
    "  core/                  прогон без интерфейса: реестр и lock (workspace), события (events),\n"
    "                         сессии (sessions), запуск пайплайна (scan), проверки после скана\n"
    "                         (steps), завершение и отчёты (finish), одиночный run (tool_run)\n"
    "  api.py                 публичный Python API (стабилен в пределах мажорной версии)\n",
)
readme.replace("## Разработка\n", API_SECTION + "## Разработка\n")

changelog = Source(root, "CHANGELOG.md")
changelog.replace(
    "### Added\n",
    "### Added\n"
    "- Публичный Python API `cyberfw.api`: `run_pipeline`, `plan_pipeline`, `run_tool`,\n"
    "  `load_run`, `compare_runs`, `export_sarif`, `export_csv` и их типы результатов\n"
    "  (`RunOutcome`, `Plan`, `SavedRun`), ошибка `PreflightError`. Ничего не печатает\n"
    "  и не спрашивает: результат — данными, ход прогона — через наблюдатель\n"
    "  `RunObserver`. Команды `pipeline`, `run`, `pipeline --plan`, `diff` и `export`\n"
    "  теперь работают через него. Описание — в README, раздел «Python API».\n",
    count=1,
)

readme.save()
changelog.save()
```

```bash
uv run --quiet python "$W/task5_docs.py" .
uv run --quiet python -m pytest tests/unit/test_api_readme.py -q
```

Expected: `edited README.md`, `edited CHANGELOG.md`; `1 passed`.

- [ ] **Step 5: Run everything**

Run: `uv run --quiet python -m pytest -q`, `uv run --quiet ruff check .`, `uv run --quiet mypy cyberfw`
Expected: `1112 passed, 5 skipped, 8 deselected`; ruff clean; mypy `Success: no issues found in 75 source files`.

- [ ] **Step 6: The output is unchanged**

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/5-run" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -r "$W/transcripts/0-base" "$W/transcripts/5-run" && echo identical
```

Expected: `50 passed`, then `identical` — the `run`, `diff` and `export` scenarios included.

- [ ] **Step 7: Commit and push**

```bash
git add cyberfw/cli/scan.py cyberfw/cli/reports.py tests/unit/test_cli_package.py tests/unit/test_api_readme.py README.md CHANGELOG.md
git commit -m "Run cyberfw run, diff and export through cyberfw.api; document the API"
git push origin main
```
