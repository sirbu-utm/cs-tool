# Remaining Upgrades Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix what is left of the user's review (`upgrades.md`): stopping a tool stops everything it started (item 3), VirusTotal keeps `--exclude` like the takeover check (the rest of item 1), a stage's name can never put its files outside the session (item 8), a baseline is a run that scanned the same thing (item 10), the registry and lock in use are the workspace's the settings name (item 5), and an update never destroys the installed version before the new one is whole (item 6).

**Architecture:** Six independent fixes, one task each, in six areas: `cyberfw/pipeline/processes.py` (new: a `ProcessGroup` — a new session on POSIX, a Job Object on Windows) wired into `cyberfw/pipeline/executor.py`; `cyberfw/core/steps.py` (`enrich_vt` takes the exclusions); `cyberfw/pipeline/context.py` (one rule for stage names and their file names) used by `engine.py` and `pipelines/loader.py`; `cyberfw/report/diff.py` (`find_baseline` keys a seed by what the pipeline's root tool scans) and `core/finish.py`; `cyberfw/core/workspace.py` (the workspace's registry first); `cyberfw/manager/installer.py` (unpack beside, then swap) and `manager/__init__.py` (the install record written atomically). Each task adds its line to the CHANGELOG's «Fixed».

**Tech Stack:** Python 3.14 via `uv`, asyncio subprocesses, `ctypes` (kernel32/ntdll Job Objects on Windows), `os.killpg` on POSIX, pydantic v2, pytest (`asyncio_mode = auto`), ruff, mypy `--strict`.

**Spec:** `upgrades.md` — the user's review, staged by the user in the main checkout (`C:/Users/DaniilSirbu/Desktop/CS-TOOL_main/upgrades.md`), not part of `main` — items 1 (its proposal covers every "additional network check"; Codex fixed the takeover check, VirusTotal is left), 3, 5, 6, 8 and 10, each with its proposal and its check.

Scope, as agreed with the user and Codex (`CLAUDE_HANDOFF.local.md`): items 4, 7, 9, 11, 12 and the takeover half of item 1 are Codex's, committed on `main` (`049651d`…`695b50b`); item 2 is done (`56c7bb8`). Departures from the spec's text, each keeping its intent:

- **Item 3 also stops what a tool left running after it exited**: a Job Object ends its processes when its last handle closes (also if cyberfw itself dies), and POSIX does the same for consistency — a scanner's leftover child is still the scan.
- **Item 3 changes Codex's lifecycle fixture**: its fake child is no process, so it gets a stand-in group (`_NoGroup`) and a `pid`.
- **Item 5's lock stays next to the registry in use** — the existing, tested design (a clone's lock in the clone, a wheel's in site-packages); what changes is which registry: the workspace's the settings name, never the current directory's when they name another. The wheel fallback is spelled out in the docstrings.
- **Item 8 rejects only what can leave the session or collide** — `/`, `\`, `:`, `.`, `..`, control characters, and two names that map to one file; dots and spaces inside a name stay allowed (user pipelines use them). `cyberfw run <tool> --list` names its stage after the tool unchecked, so `_materialize` always reduces the name to one segment too.
- **Item 10 keys a seed by the pipeline's root tool**: subfinder, naabu and rustscan scan a host; nmap a host and port; any other tool — including a plugin or an unknown one — the whole URL (scheme, host, port, path, query; host case, a default port and a trailing `/` not counting). The root tool comes from the run's first node.

Every file, script and `Expected:` line below comes from running this plan on a throwaway worktree of `main` at `695b50b`: the suite goes 1299 → 1305 → 1308 → 1322 → 1327 → 1330 → 1340 passed; ruff and mypy `--strict` are clean after each task; the transcripts of all 50 scenarios are identical to the baseline after Task 1 and after Task 6 (see Task 1, Step 5, for the one race). On Linux (WSL, `--noconftest`) the process-tree, lifecycle, cancellation and installer tests pass; `test_timeout_still_applies_after_both_pipes_close` fails there before and after this plan alike (without conftest a record does not validate).

## Global Constraints

- Run everything through `uv run --quiet …`. Suite: `uv run --quiet python -m pytest -q`; lint: `uv run --quiet ruff check .`; types: `uv run --quiet mypy cyberfw`. All clean at the end of every task.
- **Everything else behaves as before** — every command's console text, exit code and saved reports, checked with the transcript harness (50 scenarios) after Tasks 1 and 6.
- **Work in a clean worktree of `main`, never in the main checkout**: the main checkout holds the user's staged `.gitignore` and `upgrades.md`, Codex's unstaged `.gitignore` lines and its uncommitted `tests/unit/test_upgrade_flows.py`. Push with `git push origin HEAD:main` at the end; the main checkout then moves only by `git merge --ff-only`, which leaves those files as they are.
- Commits: one per task, by path only (`git commit -m "…" -- <paths>`); **no `Co-Authored-By` trailer** (the user's rule for this repo); never `CS-TOOL_presentation.pdf` or `CLAUDE_HANDOFF.local.md`.
- Before each commit and before the push, reread `CLAUDE_HANDOFF.local.md`: if Codex has reserved a file of the task meanwhile, stop and ask the user.
- Scratchpad: `SCRATCH=C:/Users/DANIIL~1/AppData/Local/Temp/claude/C--Users-DaniilSirbu-Desktop-CS-TOOL-main/6a8b772a-7993-414c-98b5-45500cbb762c/scratchpad`, `W="$SCRATCH/p2-exec"`. The plan's scripts and transcripts live in `$W`, never in the repo.

## Review Focus

1. Ctrl+C in a POSIX terminal: a tool in a session of its own no longer gets the terminal's SIGINT, so cyberfw's cancellation must stop it — SIGTERM to its whole group, SIGKILL after the grace period → `test_cancelling_stops_the_tool_s_children_too` (Task 1) and the existing `TestCancellation` (graceful on POSIX).
2. A Windows machine where no Job Object can hold the tool (cyberfw itself inside a restrictive job, a CI runner) still runs it — resumed, never left suspended → `test_a_tool_runs_even_where_no_job_object_can_hold_it` and `test_a_tool_whose_process_cannot_be_taken_in_is_killed_not_run` (Task 1).
3. Updating a tool while a scan runs it on Windows still lands, and the old copy never shadows the new one → `test_an_update_while_the_old_version_runs_still_lands` (Task 6).
4. A domain pipeline seeded with a URL (`recon-to-vuln` on `https://Example.com/`) still finds the run seeded `example.com` → `test_find_baseline_picks_the_newest_earlier_run_of_the_same_scan` (Task 4, updated) and `test_a_host_scanning_pipeline_still_matches_one_host_however_it_is_written`.
5. A user pipeline whose stage names hold dots or spaces keeps working → `test_dots_and_spaces_inside_a_name_are_fine` (Task 3).

---

### Before Task 1: the worktree, the tools and a baseline

- [ ] **Step 1: A clean worktree of `main`** — from the main checkout:

```bash
mkdir -p "$W"
git fetch origin && git worktree add --detach "$W/repo" origin/main
cd "$W/repo" && uv sync --quiet --extra dev && git log --oneline -1
```

Expected: `695b50b One deadline covers a tool's whole life, and a usable buffered report survives a failed or timed-out run` (a later commit of `main` is fine if `git log 695b50b..origin/main` touches no file of this plan). Every later command runs in `$W/repo`.

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

Expected: `50 passed`; `1299 passed, 5 skipped, 8 deselected`; `git status` shows nothing.

---

### Task 1: Stopping a tool stops everything it started (item 3)

**Files:**
- Create: `cyberfw/pipeline/processes.py`, `tests/unit/test_process_tree.py`
- Modify (by script): `cyberfw/pipeline/executor.py` (spawn in a group, adopt, `_stop(proc, group)`, close in `finally`), `tests/unit/test_executor_lifecycle.py` (a stand-in group for the fake child), `CHANGELOG.md`

**Interfaces:**
- Produces, in `cyberfw/pipeline/processes.py`: `ProcessGroup()` with `spawn_options() -> dict[str, Any]` (static: `{"start_new_session": True}` on POSIX, `{"creationflags": CREATE_SUSPENDED}` on Windows), `adopt(pid: int) -> None` (raises `OSError` when the process cannot be opened), `terminate()`, `kill()`, `close()`; on Windows the module-level `_new_job() -> int` (tests replace it).
- Produces: `run_stage` raises `ExecutionError("<tool> could not start: its process could not be given a group of its own (…)")` when `adopt` fails, after killing the process.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_process_tree.py`:

```python
"""Stopping a tool stops every process it started, not only the one cyberfw launched.

A tool is often a wrapper — a shell script, an entry point, a binary that forks
workers (gowitness and its Chrome). Whatever it left behind would go on scanning:
after a timeout, a cancellation or a failing callback, and after the tool itself
has exited, none of it may remain.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

import pytest

from cyberfw.exceptions import ExecutionError
from cyberfw.pipeline.executor import run_stage
from cyberfw.pipeline.schemas import ToolRecord


def _bare_python() -> str:
    """The interpreter itself. On Windows a venv's python.exe is a launcher that runs
    it as a child in a job of its own, and ends that child along with itself — which
    would stop the tool's tree for us and hide what this file checks."""
    return getattr(sys, "_base_executable", sys.executable)


def _wrapper(tmp_path: Path, then: str, *, delay: float = 2.0) -> tuple[list[str], Path, Path]:
    """A tool that starts a child, waits until the child runs, then does ``then``.

    The child marks ``started`` at once — with the time it would mark ``late`` —
    and ``late`` ``delay`` seconds later: longer than the tool runs, so only a
    child that outlived the tool's stop gets to."""
    started, late = tmp_path / "child_started", tmp_path / "child_late"
    child = tmp_path / "child.py"
    child.write_text(
        "import pathlib, time\n"
        f"pathlib.Path({str(started)!r}).write_text(str(time.time() + {delay}))\n"
        f"time.sleep({delay})\n"
        f"pathlib.Path({str(late)!r}).write_text('late')\n",
        encoding="utf-8",
    )
    tool = tmp_path / "tool.py"
    tool.write_text(
        "import pathlib, subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, {str(child)!r}], stdin=subprocess.DEVNULL,\n"
        "                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        f"while not pathlib.Path({str(started)!r}).exists():\n"
        "    time.sleep(0.02)\n" + then,
        encoding="utf-8",
    )
    return [_bare_python(), str(tool)], started, late


async def _assert_the_child_was_stopped(started: Path, late: Path) -> None:
    assert started.exists(), "the tool's child never ran"
    due = float(started.read_text())  # when a surviving child would mark ``late``
    await asyncio.sleep(max(0.0, due + 1.0 - time.time()))
    assert not late.exists(), "the tool's child outlived the tool"


async def test_a_timeout_stops_the_tool_s_children_too(tmp_path: Path) -> None:
    cmd, started, late = _wrapper(tmp_path, "print('ready', flush=True)\ntime.sleep(30)\n", delay=6.0)

    with pytest.raises(ExecutionError, match="timed out"):
        await run_stage(cmd, tool="x", stage="s", context=None, timeout=4)

    await _assert_the_child_was_stopped(started, late)


async def test_cancelling_stops_the_tool_s_children_too(tmp_path: Path) -> None:
    cmd, started, late = _wrapper(tmp_path, "print('ready', flush=True)\ntime.sleep(30)\n")
    ready = asyncio.Event()

    async def on_stdout_raw(line: str) -> None:
        if line == "ready":
            ready.set()

    task = asyncio.create_task(run_stage(cmd, tool="x", stage="s", context=None, on_stdout_raw=on_stdout_raw))
    await asyncio.wait_for(ready.wait(), 20)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    await _assert_the_child_was_stopped(started, late)


async def test_a_failing_callback_stops_the_tool_s_children_too(tmp_path: Path) -> None:
    cmd, started, late = _wrapper(tmp_path, "print('x.example.com', flush=True)\ntime.sleep(30)\n")

    async def boom(record: ToolRecord) -> None:
        raise RuntimeError("callback failed")

    with pytest.raises(RuntimeError, match="callback failed"):
        await run_stage(cmd, tool="x", stage="s", context=None, on_record=boom, parse=False)

    await _assert_the_child_was_stopped(started, late)


async def test_what_a_finished_tool_left_running_is_stopped(tmp_path: Path) -> None:
    cmd, started, late = _wrapper(tmp_path, "")

    assert await run_stage(cmd, tool="x", stage="s", context=None) == []

    await _assert_the_child_was_stopped(started, late)


async def test_a_tool_whose_process_cannot_be_taken_in_is_killed_not_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cyberfw.pipeline import processes

    def refuse(self: processes.ProcessGroup, pid: int) -> None:
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(processes.ProcessGroup, "adopt", refuse)
    marker = tmp_path / "ran"
    tool = tmp_path / "tool.py"
    tool.write_text(f"import pathlib, time\ntime.sleep(0.5)\npathlib.Path({str(marker)!r}).write_text('ran')\n")

    with pytest.raises(ExecutionError, match="x could not start: .*Access is denied"):
        await run_stage([sys.executable, str(tool)], tool="x", stage="s", context=None)

    await asyncio.sleep(1.5)
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="Job Objects are Windows'")
async def test_a_tool_runs_even_where_no_job_object_can_hold_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cyberfw.pipeline import processes

    def no_job() -> int:
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(processes, "_new_job", no_job)
    tool = tmp_path / "tool.py"
    tool.write_text("print('x.example.com')\n")

    records = await asyncio.wait_for(
        run_stage([sys.executable, str(tool)], tool="x", stage="s", context=None, parse=False), 30
    )

    assert [record.target for record in records] == ["x.example.com"]
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python -m pytest tests/unit/test_process_tree.py -q -p no:cacheprovider
```

Expected: `6 failed` — four `AssertionError: the tool's child outlived the tool` (timeout, cancellation, a failing callback, a finished tool's leftover) and two `ImportError: cannot import name 'processes' from 'cyberfw.pipeline'`. (On Linux the Windows-only test is skipped: `5 failed, 1 skipped`.)

- [ ] **Step 3: The process group, and the executor using it**

Create `cyberfw/pipeline/processes.py`:

```python
"""A tool's process tree: whatever a tool starts stops with it.

A scanner is often a wrapper — a shell script, an entry point, a binary that forks
workers — and stopping only the process cyberfw launched leaves the rest running,
still scanning. So each tool runs in a group of its own — a new session (its own
process group) on POSIX, a Job Object on Windows — and stopping the tool stops
the group.
"""

from __future__ import annotations

import os
import signal
import sys
from typing import Any

from cyberfw.logging import get_logger

LOG = get_logger("executor")

#: CreateProcess flag: the process starts with its main thread suspended, so it is in
#: its job before it runs a single instruction — let alone starts a child.
_CREATE_SUSPENDED = 0x00000004


class ProcessGroup:
    """The processes one tool runs as. Spawn the tool with :meth:`spawn_options`,
    hand its pid to :meth:`adopt`, and :meth:`close` the group once it is done."""

    def __init__(self) -> None:
        self._pgid: int | None = None
        self._job: int | None = None

    @staticmethod
    def spawn_options() -> dict[str, Any]:
        """Keyword arguments for ``create_subprocess_exec`` that start the tool in a
        group of its own (on Windows: suspended, until :meth:`adopt` lets it run)."""
        if sys.platform == "win32":
            return {"creationflags": _CREATE_SUSPENDED}
        return {"start_new_session": True}

    def adopt(self, pid: int) -> None:
        """Take the tool's process, just spawned with :meth:`spawn_options`, into the
        group — and on Windows let it run. Raises :class:`OSError` if the process
        cannot even be opened: it is then still suspended, for the caller to kill.
        Where no Job Object can hold it, the tool runs all the same, and stopping it
        stops its own process only."""
        if sys.platform == "win32":
            self._job = _adopt_into_job(pid)
        else:
            self._pgid = pid  # start_new_session made it the leader of a group of its own

    def terminate(self) -> None:
        """Ask every process in the group to exit: SIGTERM on POSIX. Windows has no
        such request, so there the whole job is ended at once."""
        if sys.platform == "win32":
            self.kill()
        elif self._pgid is not None:
            _signal_group(self._pgid, signal.SIGTERM)

    def kill(self) -> None:
        """End every process still in the group, at once."""
        if sys.platform == "win32":
            if self._job is not None:
                _kernel32.TerminateJobObject(self._job, 1)
        elif self._pgid is not None:
            _signal_group(self._pgid, signal.SIGKILL)

    def close(self) -> None:
        """End whatever the tool left running and let go of the group."""
        self.kill()
        if sys.platform == "win32" and self._job is not None:
            _kernel32.CloseHandle(self._job)
        self._job = self._pgid = None


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")

    _PROCESS_TERMINATE = 0x0001
    _PROCESS_SET_QUOTA = 0x0100
    _PROCESS_SUSPEND_RESUME = 0x0800
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    #: The job's last handle closing — cyberfw's, at :meth:`ProcessGroup.close` or
    #: when cyberfw itself dies — ends every process still in it.
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000

    class _BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_uint64)
            for name in ("Reads", "Writes", "Others", "ReadBytes", "WriteBytes", "OtherBytes")
        ]

    class _ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimits),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    _kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    _kernel32.TerminateJobObject.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _ntdll.NtResumeProcess.argtypes = (wintypes.HANDLE,)
    _ntdll.NtResumeProcess.restype = ctypes.c_long

    def _new_job() -> int:
        """A Job Object that ends its processes when its last handle closes."""
        job = _kernel32.CreateJobObjectW(None, None)
        if not job:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not _kernel32.SetInformationJobObject(
            job, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            error = ctypes.WinError(ctypes.get_last_error())
            _kernel32.CloseHandle(job)
            raise error
        return int(job)

    def _adopt_into_job(pid: int) -> int | None:
        """Put the suspended process ``pid`` in a new job, then resume it: the job's
        handle, or None where no job can hold it (it runs all the same)."""
        process = _kernel32.OpenProcess(
            _PROCESS_TERMINATE | _PROCESS_SET_QUOTA | _PROCESS_SUSPEND_RESUME, False, pid
        )
        if not process:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            job: int | None = None
            try:
                job = _new_job()
                if not _kernel32.AssignProcessToJobObject(job, process):
                    raise ctypes.WinError(ctypes.get_last_error())
            except OSError as exc:
                if job is not None:
                    _kernel32.CloseHandle(job)
                job = None
                LOG.debug("pid %d runs outside a job object (%s): stopping it stops its own process only", pid, exc)
            status = _ntdll.NtResumeProcess(process)
            if status < 0:
                if job is not None:
                    _kernel32.CloseHandle(job)  # ends the process, still suspended in it
                raise OSError(f"could not resume the process (NTSTATUS {status & 0xFFFFFFFF:#010x})")
            return job
        finally:
            _kernel32.CloseHandle(process)

else:

    def _signal_group(pgid: int, signum: signal.Signals) -> None:
        """Send ``signum`` to every process in the group ``pgid`` (none left: a no-op)."""
        try:
            os.killpg(pgid, signum)
        except (ProcessLookupError, PermissionError):
            pass
```

Save as `$W/task1_tree.py`:

```python
"""Task 1: each tool runs in a process group of its own, and stopping it stops the group.

Usage: python task1_tree.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

executor = Source(root, "cyberfw/pipeline/executor.py")
executor.replace(
    "and its stderr separately (kept as a bounded tail for diagnostics), and on\n"
    "cancellation (Ctrl+C / SIGTERM) asks the child to exit (SIGTERM), waits a short\n"
    "grace period and only then SIGKILLs it, so a long scan never orphans a process\n"
    "yet a tool that flushes on SIGTERM gets to. A non-zero exit (including SIGSEGV /\n",
    "and its stderr separately (kept as a bounded tail for diagnostics), and on\n"
    "cancellation (Ctrl+C / SIGTERM) asks the tool to exit (SIGTERM), waits a short\n"
    "grace period and only then SIGKILLs it — the tool and every process it started\n"
    "(:mod:`cyberfw.pipeline.processes`) — so a long scan never orphans a process\n"
    "yet a tool that flushes on SIGTERM gets to. A non-zero exit (including SIGSEGV /\n",
)
executor.replace(
    "from cyberfw.pipeline.context import SessionContext\n",
    "from cyberfw.pipeline.context import SessionContext\nfrom cyberfw.pipeline.processes import ProcessGroup\n",
)
executor.replace(
    "    cmd = _prepare_cmd(cmd)\n"
    "    try:\n"
    "        proc = await asyncio.create_subprocess_exec(\n",
    "    cmd = _prepare_cmd(cmd)\n"
    "    group = ProcessGroup()\n"
    "    try:\n"
    "        proc = await asyncio.create_subprocess_exec(\n",
)
executor.replace(
    "            env=dict(env) if env is not None else tool_environment(),\n"
    "        )\n"
    "    except OSError as exc:\n"
    "        raise ExecutionError(\n"
    '            f"{tool} could not start: {exc}. The installed binary may target another OS or architecture.",\n'
    "            stderr_tail=[str(exc)],\n"
    "        ) from exc\n",
    "            env=dict(env) if env is not None else tool_environment(),\n"
    "            **group.spawn_options(),\n"
    "        )\n"
    "    except OSError as exc:\n"
    "        raise ExecutionError(\n"
    '            f"{tool} could not start: {exc}. The installed binary may target another OS or architecture.",\n'
    "            stderr_tail=[str(exc)],\n"
    "        ) from exc\n"
    "    try:\n"
    "        group.adopt(proc.pid)\n"
    "    except OSError as exc:\n"
    "        # Never a tool cyberfw could not stop as a whole — nor one left suspended.\n"
    "        _kill_if_running(proc)\n"
    "        await proc.wait()\n"
    "        _close_transport(proc)\n"
    "        raise ExecutionError(\n"
    '            f"{tool} could not start: its process could not be given a group of its own ({exc})",\n'
    "            stderr_tail=[str(exc)],\n"
    "        ) from exc\n",
)
executor.replace("            await _stop(proc)\n", "            await _stop(proc, group)\n", count=2)
executor.replace(
    "        # Leaving this block with a live child — a callback or Context Store\n"
    "        # error mid-stream, or a second cancellation during the grace period —\n"
    "        # must never orphan a scanner. (transport.close() below also kills,\n"
    "        # but via a private attribute.)\n"
    "        _kill_if_running(proc)\n",
    "        # Leaving this block with a live child — a callback or Context Store\n"
    "        # error mid-stream, or a second cancellation during the grace period —\n"
    "        # must never orphan a scanner, nor anything it started: the group goes\n"
    "        # too, with whatever a finished tool left running. (transport.close()\n"
    "        # below also kills, but via a private attribute.)\n"
    "        _kill_if_running(proc)\n"
    "        group.close()\n",
)
executor.replace_span(
    "async def _stop(proc: asyncio.subprocess.Process, grace: float = _TERM_GRACE) -> None:\n",
    "        await proc.wait()\n\n\n#: NTSTATUS codes",
    "async def _stop(proc: asyncio.subprocess.Process, group: ProcessGroup, grace: float = _TERM_GRACE) -> None:\n"
    '    """Ask the tool to exit, wait up to ``grace`` seconds, then hard-kill it — the\n'
    "    tool and every process in its ``group``.\n"
    "\n"
    "    ``terminate()`` is SIGTERM to the tool's whole process group on POSIX (which\n"
    "    well-behaved scanners handle by flushing and exiting) and the end of its Job\n"
    "    Object on Windows (immediate, so the wait returns at once). Whatever is still\n"
    "    in the group once the tool's own process has exited is killed. Awaiting here —\n"
    "    instead of scheduling the kill on a detached task — means nothing outlives\n"
    "    ``run_stage``.\n"
    '    """\n'
    "    if proc.returncode is None:\n"
    "        group.terminate()\n"
    "        try:\n"
    "            proc.terminate()\n"
    "        except ProcessLookupError:  # pragma: no cover - already gone\n"
    "            pass\n"
    "        try:\n"
    "            await asyncio.wait_for(proc.wait(), grace)\n"
    "        except asyncio.TimeoutError:\n"
    "            _kill_if_running(proc)\n"
    "            await proc.wait()\n"
    "    group.kill()\n\n\n#: NTSTATUS codes",
)
executor.save()

# The lifecycle tests hand run_stage a fake child — no process, so no process tree:
# it gets a stand-in group, and a pid to hand it.
lifecycle = Source(root, "tests/unit/test_executor_lifecycle.py")
lifecycle.replace(
    "        self.exit_delay: float | None = None\n",
    "        self.exit_delay: float | None = None\n"
    "        self.pid = 0  # no process: its group is a _NoGroup\n",
)
lifecycle.replace(
    "@pytest.fixture\nasync def child(",
    "class _NoGroup:\n"
    '    """The process group of a fake child: there is no process tree to stop."""\n'
    "\n"
    "    @staticmethod\n"
    "    def spawn_options() -> dict[str, Any]:\n"
    "        return {}\n"
    "\n"
    "    def adopt(self, pid: int) -> None:\n"
    "        pass\n"
    "\n"
    "    def terminate(self) -> None:\n"
    "        pass\n"
    "\n"
    "    def kill(self) -> None:\n"
    "        pass\n"
    "\n"
    "    def close(self) -> None:\n"
    "        pass\n"
    "\n"
    "\n"
    "@pytest.fixture\nasync def child(",
)
lifecycle.replace(
    '    monkeypatch.setattr("cyberfw.pipeline.executor.asyncio.create_subprocess_exec", spawn)\n'
    "    yield process\n",
    '    monkeypatch.setattr("cyberfw.pipeline.executor.asyncio.create_subprocess_exec", spawn)\n'
    '    monkeypatch.setattr("cyberfw.pipeline.executor.ProcessGroup", _NoGroup)\n'
    "    yield process\n",
)
lifecycle.save()

changelog = Source(root, "CHANGELOG.md")
changelog.replace(
    "### Fixed\n",
    "### Fixed\n"
    "- Таймаут, отмена или ошибка обработчика останавливали только процесс,\n"
    "  запущенный cyberfw, а то, что он сам запустил (обёртка и её сканер,\n"
    "  gowitness и Chrome, воркеры), продолжало работать. Теперь каждый инструмент\n"
    "  идёт в своей группе процессов — отдельная сессия на POSIX, Job Object на\n"
    "  Windows — и останавливается вся группа: на POSIX сначала SIGTERM всем, после\n"
    "  паузы SIGKILL. То, что инструмент оставил работать после своего выхода, тоже\n"
    "  завершается.\n",
)
changelog.save()
```

```bash
uv run --quiet python "$W/task1_tree.py" .
```

Expected: `edited cyberfw/pipeline/executor.py`, `edited tests/unit/test_executor_lifecycle.py`, `edited CHANGELOG.md`.

- [ ] **Step 4: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_process_tree.py tests/unit/test_executor.py tests/unit/test_executor_lifecycle.py tests/unit/test_executor_buffered_failure.py -q -p no:cacheprovider
```

Expected: `65 passed, 2 skipped`.

- [ ] **Step 5: The whole suite, lint, types, and the output**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1305 passed, 5 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 80 source files`.

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/1-tree" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -rb "$W/transcripts/0-base" "$W/transcripts/1-tree" && echo identical
```

Expected: `50 passed`, then `identical`. Two differences are not findings: an `elapsed <dur> (1m…s)` line (a loaded machine — capture again into an empty directory), and, in `pipeline-ffuf-verbose-topology`, nuclei's and ffuf's raw lines in the other order — two stages running at once print in whichever order they happen to, and starting each tool in its own group shifts that race (the dry run saw it once in four captures). Anything else is.

- [ ] **Step 6: Commit** — reread `CLAUDE_HANDOFF.local.md` in the main checkout first (Global Constraints): if Codex has reserved a file of this task meanwhile, stop and ask the user. Then:

```bash
git add -- cyberfw/pipeline/processes.py tests/unit/test_process_tree.py
git commit -m "Stopping a tool stops everything it started: each tool runs in a process group of its own" -- cyberfw/pipeline/processes.py cyberfw/pipeline/executor.py tests/unit/test_process_tree.py tests/unit/test_executor_lifecycle.py CHANGELOG.md
git log -1 --format=%B | grep -ci co-authored
```

Expected: `0` from the `grep`.

---

### Task 2: VirusTotal is never sent an excluded host (item 1, the rest)

**Files:**
- Modify (by script): `cyberfw/core/steps.py` (`enrich_vt(..., exclude)`, `post_scan` passes `settings.exclude`), `CHANGELOG.md`; tests `tests/unit/test_core_steps.py`

**Interfaces:**
- Produces: `enrich_vt(result, api_key, limit, observer, exclude: Sequence[str] = ())` — the targets go through `in_scope(target, exclude)` before any lookup; `post_scan` passes `settings.exclude` positionally (as it does for `check_takeover`).

- [ ] **Step 1: Write the failing tests**

Save as `$W/task2_tests.py`:

```python
"""Task 2, test first: VirusTotal is never sent a host --exclude keeps out of scope.

Usage: python task2_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

TESTS = '''

def test_virustotal_is_never_sent_an_excluded_host(seen: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    # --exclude keeps a host out of scope for the checks after the scan too: it
    # stays among the discovery results, but is not sent to a third party.
    looked_up: list[list[str]] = []

    async def fake_enrich(targets: list[str], api_key: str, limit: int = 20, **_kw: object) -> list[vt.Reputation]:
        looked_up.append(list(targets))
        return []

    monkeypatch.setattr(vt, "enrich", fake_enrich)
    private = _record("subfinder", {"host": "private.example.com", "source": "stub"})
    probed = _record("httpx", {"url": "https://private.example.com/login", "status_code": 200})
    result = PipelineResult(records=[private, _host(), probed])

    steps.enrich_vt(result, "key", 20, seen, ["*.private.example.com", "private.example.com"])

    assert looked_up == [["sub.example.com"]]
    assert [record.target for record in result.records] == [
        "private.example.com", "sub.example.com", "https://private.example.com/login",
    ]


def test_with_every_host_excluded_virustotal_is_not_called(seen: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    async def never(*_a: object, **_kw: object) -> list[vt.Reputation]:
        raise AssertionError("VirusTotal was called")

    monkeypatch.setattr(vt, "enrich", never)

    steps.enrich_vt(PipelineResult(records=[_host()]), "key", 20, seen, ["*.example.com"])

    assert seen.steps == []


def test_post_scan_hands_the_exclusions_to_virustotal(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    passed: list[list[str]] = []
    monkeypatch.setattr(steps, "check_tls", lambda *_a: None)
    monkeypatch.setattr(steps, "enrich_vt", lambda _r, _k, _l, _o, exclude=(): passed.append(list(exclude)))
    settings = Settings(root_dir=tmp_path, exclude=["*.internal.example.com"])

    steps.post_scan(
        PipelineResult(), seed="example.com", settings=settings, mail=False, takeover=False, intel=False,
        vt_key="key", vt_limit=20, observer=RunObserver(),
    )

    assert passed == [["*.internal.example.com"]]
'''

tests = Source(root, "tests/unit/test_core_steps.py")
tests.text = tests.text.rstrip("\n") + "\n" + TESTS
tests.save()
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python "$W/task2_tests.py" .
uv run --quiet python -m pytest tests/unit/test_core_steps.py -q -p no:cacheprovider
```

Expected: `edited tests/unit/test_core_steps.py`; then `3 failed, 13 passed` — two `TypeError: enrich_vt() takes 4 positional arguments but 5 were given` and `AssertionError: assert [[]] == [['*.internal.example.com']]` (post_scan hands VirusTotal no exclusions).

- [ ] **Step 3: Hand VirusTotal the exclusions**

Save as `$W/task2_scope.py`:

```python
"""Task 2: VirusTotal enrichment takes the run's exclusions, like the takeover check.

Usage: python task2_scope.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

steps = Source(root, "cyberfw/core/steps.py")
steps.replace(
    "def enrich_vt(result: PipelineResult, api_key: str, limit: int, observer: RunObserver) -> None:\n"
    '    """Append VirusTotal reputation records for the run\'s discovered targets."""\n'
    "    targets = vt.enrichment_targets(result.records)\n",
    "def enrich_vt(\n"
    "    result: PipelineResult, api_key: str, limit: int, observer: RunObserver, exclude: Sequence[str] = ()\n"
    ") -> None:\n"
    '    """Append VirusTotal reputation records for the run\'s in-scope discovered targets:\n'
    "    a host ``exclude`` keeps out of scope is never sent to VirusTotal.\"\"\"\n"
    "    targets = [target for target in vt.enrichment_targets(result.records) if in_scope(target, exclude)]\n",
)
steps.replace(
    '    """The checks after the scan, in order: TLS always, the others when asked for\n'
    '    (VirusTotal only with a key). Each adds its records to ``result``."""\n',
    '    """The checks after the scan, in order: TLS always, the others when asked for\n'
    "    (VirusTotal only with a key). Each adds its records to ``result``; those that\n"
    "    reach out to a host or a third party keep ``settings.exclude`` out of scope.\"\"\"\n",
)
steps.replace(
    "        enrich_vt(result, vt_key, vt_limit, observer)\n",
    "        enrich_vt(result, vt_key, vt_limit, observer, settings.exclude)\n",
)
steps.save()

changelog = Source(root, "CHANGELOG.md")
changelog.replace(
    "### Fixed\n",
    "### Fixed\n"
    "- `--exclude` не действовал на обогащение VirusTotal: исключённые хосты всё\n"
    "  равно отправлялись в VirusTotal. Теперь туда уходят только хосты в области\n"
    "  сканирования, как и в takeover-проверку; записи обнаружения остаются в отчёте.\n",
)
changelog.save()
```

```bash
uv run --quiet python "$W/task2_scope.py" .
```

Expected: `edited cyberfw/core/steps.py`, `edited CHANGELOG.md`.

- [ ] **Step 4: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_core_steps.py tests/unit/test_takeover_scope.py -q -p no:cacheprovider
```

Expected: `24 passed`.

- [ ] **Step 5: The whole suite, lint, types**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1308 passed, 5 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 80 source files`.

- [ ] **Step 6: Commit** — reread `CLAUDE_HANDOFF.local.md` in the main checkout first (Global Constraints): if Codex has reserved a file of this task meanwhile, stop and ask the user. Then:

```bash
git commit -m "VirusTotal is never sent a host --exclude keeps out of scope" -- cyberfw/core/steps.py tests/unit/test_core_steps.py CHANGELOG.md
git log -1 --format=%B | grep -ci co-authored
```

Expected: `0` from the `grep`.

---

### Task 3: A stage's name never puts its files outside the session (item 8)

**Files:**
- Modify (by script): `cyberfw/pipeline/context.py` (`stage_file_name`, `check_stage_name`, `check_stage_files`), `cyberfw/pipeline/engine.py` (`_validate_wiring`, `_materialize`), `cyberfw/pipelines/loader.py`, `CHANGELOG.md`; tests `tests/unit/test_pipeline_files.py`, `tests/unit/test_engine.py`

**Interfaces:**
- Produces, in `cyberfw/pipeline/context.py`: `stage_file_name(stage) -> str` (the one segment the store and the engine name a stage's files by), `check_stage_name(stage) -> None` and `check_stage_files(stages) -> None` (both raise `ValueError`).
- Produces: `PipelineEngine.run` refuses such a pipeline before anything runs (`ValueError`); `load_pipeline_file` refuses it with the file named (`RegistryError`).

- [ ] **Step 1: Write the failing tests**

Save as `$W/task3_tests.py`:

```python
"""Task 3, test first: a stage's name names its files, so it must stay one plain name.

Usage: python task3_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

LOADER_TESTS = '''

class TestStageNamesStayInTheSession:
    """A stage's name names its files in the session (``<stage>.jsonl``, ``<stage>.input``):
    one that is no plain name, or one that two stages would share as a file name, is
    rejected when the file is read — before anything is written."""

    @pytest.mark.parametrize(
        "stage", ["../outside", "/etc/outside", "C:\\\\outside", "C:outside", "a\\\\b", "a/b", ".", ".."]
    )
    def test_a_stage_name_that_is_no_plain_name_is_rejected(self, tmp_path: Path, stage: str) -> None:
        text = f"nodes:\\n  - tool: subfinder\\n    stage: {json.dumps(stage)}\\n"

        with pytest.raises(RegistryError, match=r"broken\\.yaml: stage .* is not a plain name"):
            load_pipeline_file(_write(tmp_path, "broken", text))

    def test_two_stages_that_would_share_one_file_are_rejected(self, tmp_path: Path) -> None:
        text = "nodes:\\n  - tool: subfinder\\n    stage: live http\\n  - tool: httpx\\n    stage: live_http\\n"

        with pytest.raises(RegistryError, match="'live http' and 'live_http' would share one file"):
            load_pipeline_file(_write(tmp_path, "twins", text))

    def test_dots_and_spaces_inside_a_name_are_fine(self, tmp_path: Path) -> None:
        text = "nodes:\\n  - tool: subfinder\\n    stage: sub domains.v2\\n"

        assert [node.stage for node in load_pipeline_file(_write(tmp_path, "dotted", text))] == ["sub domains.v2"]
'''

ENGINE_TESTS = '''

class TestStageFilesStayInTheSession:
    """Nothing a stage writes lands outside the session, whatever the stage is called."""

    @staticmethod
    def _engine(tmp_path: Path, *, session: bool = True) -> PipelineEngine:
        registry_path = tmp_path / "registry.yaml"
        registry_path.write_text("subfinder:\\n  repo: org/subfinder\\n  asset_patterns: []\\n", encoding="utf-8")
        engine = _make_engine(tmp_path, registry_path)
        if not session:
            engine.context = None
        return engine

    async def test_a_stage_name_that_is_no_plain_name_is_refused_before_anything_runs(self, tmp_path: Path) -> None:
        engine = self._engine(tmp_path)

        with pytest.raises(ValueError, match="'../outside' is not a plain name"):
            await engine.run([Node(tool="subfinder", stage="../outside")], seed="example.com")

        assert not list(tmp_path.rglob("*outside*"))

    async def test_two_stages_that_would_share_one_file_are_refused(self, tmp_path: Path) -> None:
        engine = self._engine(tmp_path)
        nodes = [Node(tool="subfinder", stage="live http"), Node(tool="subfinder", stage="live_http")]

        with pytest.raises(ValueError, match="would share one file"):
            await engine.run(nodes, seed="example.com")

    @pytest.mark.parametrize("session", [True, False], ids=["session", "no-session"])
    def test_a_list_input_lands_in_its_directory_whatever_the_stage_is_called(
        self, tmp_path: Path, session: bool
    ) -> None:
        # ``cyberfw run <tool> --list`` names its one stage after the tool, unchecked.
        engine = self._engine(tmp_path, session=session)

        path = engine._materialize("../../outside", ["a.example.com"])
        try:
            expected = engine.context.session_dir if engine.context is not None else Path(tempfile.gettempdir())
            assert path.parent == expected
            assert ".." not in path.name and path.read_text(encoding="utf-8") == "a.example.com\\n"
        finally:
            path.unlink(missing_ok=True)
'''

loader = Source(root, "tests/unit/test_pipeline_files.py")
loader.replace("from __future__ import annotations\n\nfrom pathlib import Path\n",
               "from __future__ import annotations\n\nimport json\nfrom pathlib import Path\n")
loader.text = loader.text.rstrip("\n") + "\n" + LOADER_TESTS
loader.save()

engine = Source(root, "tests/unit/test_engine.py")
engine.replace("\nimport sys\nfrom pathlib import Path\n", "\nimport sys\nimport tempfile\nfrom pathlib import Path\n")
engine.text = engine.text.rstrip("\n") + "\n" + ENGINE_TESTS
engine.save()
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python "$W/task3_tests.py" .
uv run --quiet python -m pytest tests/unit/test_pipeline_files.py tests/unit/test_engine.py -q -p no:cacheprovider -k "StageNames or StageFiles"
```

Expected: `edited tests/unit/test_pipeline_files.py`, `edited tests/unit/test_engine.py`; then `13 failed, 1 passed` — nine `DID NOT RAISE RegistryError`, two `DID NOT RAISE ValueError`, and two `AssertionError`s showing the `.input` file outside its directory (`…/sess/../..`, `…/Temp/cyberfw-<pid>-../..`). The test that passes (`…dots_and_spaces_inside_a_name_are_fine`) guards that the fix keeps such names.

- [ ] **Step 3: One rule for stage names, one file name per stage**

Save as `$W/task3_names.py`:

```python
"""Task 3: one rule for what a stage may be called, and one file name per stage.

Usage: python task3_names.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

context = Source(root, "cyberfw/pipeline/context.py")
context.replace(
    '__all__ = ["SessionContext"]\n',
    '__all__ = ["SessionContext", "check_stage_files", "check_stage_name", "stage_file_name"]\n',
)
context.replace(
    "\n\nclass SessionContext:\n",
    "\n\n"
    "def stage_file_name(stage: str) -> str:\n"
    '    """The one path segment a stage\'s files in the session are named by: letters,\n'
    "    digits, ``-`` and ``_`` as they are, anything else as ``_``.\"\"\"\n"
    '    return "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in stage) or "stage"\n'
    "\n"
    "\n"
    "def check_stage_name(stage: str) -> None:\n"
    '    """Raise :class:`ValueError` unless ``stage`` is one plain name: not empty, ``.``\n'
    "    or ``..``, and with no path separator, drive colon or control character — it\n"
    "    names the stage's files in the session.\"\"\"\n"
    '    if stage.strip() in {"", ".", ".."} or any(ch in "/\\\\:" or not ch.isprintable() for ch in stage):\n'
    "        raise ValueError(\n"
    "            f\"stage {stage!r} is not a plain name: it names the stage's files in the session, \"\n"
    "            \"so it may hold no '/', '\\\\' or ':' and may not be '.' or '..'\"\n"
    "        )\n"
    "\n"
    "\n"
    "def check_stage_files(stages: list[str]) -> None:\n"
    '    """Raise :class:`ValueError` when two of ``stages`` would share one file name."""\n'
    "    named: dict[str, str] = {}\n"
    "    for stage in stages:\n"
    "        other = named.setdefault(stage_file_name(stage), stage)\n"
    "        if other != stage:\n"
    "            raise ValueError(f\"stages {other!r} and {stage!r} would share one file in the session: rename one\")\n"
    "\n"
    "\n"
    "class SessionContext:\n",
)
context.replace(
    "        # sanitise arbitrary stage names to a single path segment\n"
    '        safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in stage) or "stage"\n'
    '        path = self.session_dir / f"{safe}.jsonl"\n'
    "        return path\n",
    '        return self.session_dir / f"{stage_file_name(stage)}.jsonl"\n',
)
context.save()

engine = Source(root, "cyberfw/pipeline/engine.py")
engine.replace(
    "from cyberfw.pipeline.context import SessionContext\n",
    "from cyberfw.pipeline.context import (\n"
    "    SessionContext,\n"
    "    check_stage_files,\n"
    "    check_stage_name,\n"
    "    stage_file_name,\n"
    ")\n",
)
engine.replace(
    "    @staticmethod\n"
    "    def _validate_wiring(nodes: list[Node]) -> None:\n"
    '        """Fail fast on a pipeline whose ``input_from`` names a missing/later stage."""\n'
    "        seen: set[str] = set()\n"
    "        for node in nodes:\n",
    "    @staticmethod\n"
    "    def _validate_wiring(nodes: list[Node]) -> None:\n"
    '        """Fail fast — before anything is written — on a pipeline with a stage name\n'
    "        that is no plain name, two stages that would share one file, or an\n"
    '        ``input_from`` that names a missing/later stage."""\n'
    "        for node in nodes:\n"
    "            check_stage_name(node.stage)\n"
    "        check_stage_files([node.stage for node in nodes])\n"
    "        seen: set[str] = set()\n"
    "        for node in nodes:\n",
)
engine.replace(
    "        if self.context is not None:\n"
    '            path = self.context.session_dir / f"{stage_id}.input"\n'
    "        else:\n"
    '            path = Path(tempfile.gettempdir()) / f"cyberfw-{os.getpid()}-{stage_id}.input"\n',
    "        name = stage_file_name(stage_id)  # one segment, whatever the stage is called\n"
    "        if self.context is not None:\n"
    '            path = self.context.session_dir / f"{name}.input"\n'
    "        else:\n"
    '            path = Path(tempfile.gettempdir()) / f"cyberfw-{os.getpid()}-{name}.input"\n',
)
engine.save()

loader = Source(root, "cyberfw/pipelines/loader.py")
loader.replace(
    "keys, an ``input_from`` that does not name an earlier stage and duplicate stage\n"
    "names are rejected up front with the file named, as :class:`RegistryError`.\n",
    "keys, an ``input_from`` that does not name an earlier stage, duplicate stage\n"
    "names, a stage name that is no plain name (it names the stage's files in the\n"
    "session: no ``/``, ``\\\\`` or ``:``, not ``.`` or ``..``) and two stages whose\n"
    "file names would collide are rejected up front with the file named, as\n"
    ":class:`RegistryError`.\n",
)
loader.replace(
    "from cyberfw.pipeline.engine import Node\n",
    "from cyberfw.pipeline.context import check_stage_files, check_stage_name\nfrom cyberfw.pipeline.engine import Node\n",
)
loader.replace(
    "    seen: set[str] = set()\n"
    "    for node in spec.nodes:\n"
    "        if node.stage in seen:\n",
    "    try:\n"
    "        for node in spec.nodes:\n"
    "            check_stage_name(node.stage)\n"
    "        check_stage_files(list(dict.fromkeys(node.stage for node in spec.nodes)))\n"
    "    except ValueError as exc:\n"
    '        raise RegistryError(f"pipeline {path.name}: {exc}") from exc\n'
    "\n"
    "    seen: set[str] = set()\n"
    "    for node in spec.nodes:\n"
    "        if node.stage in seen:\n",
)
loader.save()

changelog = Source(root, "CHANGELOG.md")
changelog.replace(
    "### Fixed\n",
    "### Fixed\n"
    "- Имя этапа в YAML-пайплайне становилось частью пути: этап `../outside`\n"
    "  записывал свой `.input` вне каталога сессии, а имена, различающиеся только\n"
    "  `/`, пробелом или `_`, писали в один и тот же файл. Теперь имя этапа должно\n"
    "  быть простым — без `/`, `\\` и `:`, не `.` и не `..`; пайплайн с таким\n"
    "  именем или с двумя этапами, чьи файлы совпали бы, отклоняется до запуска, а\n"
    "  файлы этапа всегда лежат в каталоге сессии.\n",
)
changelog.save()
```

```bash
uv run --quiet python "$W/task3_names.py" .
```

Expected: `edited cyberfw/pipeline/context.py`, `edited cyberfw/pipeline/engine.py`, `edited cyberfw/pipelines/loader.py`, `edited CHANGELOG.md`.

- [ ] **Step 4: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_pipeline_files.py tests/unit/test_engine.py tests/unit/test_context.py -q -p no:cacheprovider
```

Expected: `93 passed`.

- [ ] **Step 5: The whole suite, lint, types**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1322 passed, 5 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 80 source files`.

- [ ] **Step 6: Commit** — reread `CLAUDE_HANDOFF.local.md` in the main checkout first (Global Constraints): if Codex has reserved a file of this task meanwhile, stop and ask the user. Then:

```bash
git commit -m "A stage's name stays one plain name: its files never land outside the session, nor two stages in one file" -- cyberfw/pipeline/context.py cyberfw/pipeline/engine.py cyberfw/pipelines/loader.py tests/unit/test_pipeline_files.py tests/unit/test_engine.py CHANGELOG.md
git log -1 --format=%B | grep -ci co-authored
```

Expected: `0` from the `grep`.

---

### Task 4: A baseline is a run that scanned the same thing (item 10)

**Files:**
- Modify (by script): `cyberfw/report/diff.py` (`_scan_scope` replaces `_seed_key`; `find_baseline(..., root_tool=None)`), `cyberfw/core/finish.py` (passes the first node's tool), `CHANGELOG.md`; tests `tests/unit/test_diff.py`, `tests/unit/test_core_finish.py`

**Interfaces:**
- Produces: `find_baseline(reports_dir, *, seed, pipeline, before, root_tool: str | None = None)` — `root_tool` is the pipeline's first stage's tool; unknown (`None`) compares whole targets.

- [ ] **Step 1: Write the failing tests**

Save as `$W/task4_tests.py`:

```python
"""Task 4, test first: an earlier run is a baseline only if it scanned what this run scans.

Usage: python task4_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

DIFF_TESTS = '''

def test_a_url_pipeline_never_takes_a_run_of_another_port_or_path_as_its_baseline(tmp_path: Path) -> None:
    # A pipeline that starts with nuclei scans the URL it is given, port and path and all.
    admin = _save(tmp_path, "admin", _doc(started="2026-10-01T10:00:00+00:00", seed="https://example.com:8443/admin",
                                          pipeline="web"), 1_000)
    _save(tmp_path, "other", _doc(started="2026-10-02T10:00:00+00:00", seed="http://example.com:8080/other",
                                  pipeline="web"), 2_000)
    now = diff._parse_time("2026-10-09T10:00:00+00:00")

    def baseline(seed: str) -> Path | None:
        return diff.find_baseline(tmp_path, seed=seed, pipeline="web", before=now, root_tool="nuclei")

    assert baseline("https://EXAMPLE.com:8443/admin/") == admin
    assert baseline("https://example.com:9443/admin") is None
    assert baseline("https://example.com:8443/other") is None
    assert baseline("http://example.com:8443/admin") is None


def test_a_url_s_default_port_is_the_same_scan(tmp_path: Path) -> None:
    plain = _save(tmp_path, "plain", _doc(started="2026-10-01T10:00:00+00:00", seed="https://example.com",
                                          pipeline="web"), 1_000)
    now = diff._parse_time("2026-10-09T10:00:00+00:00")

    assert diff.find_baseline(tmp_path, seed="https://example.com:443/", pipeline="web", before=now,
                              root_tool="httpx") == plain


def test_a_pipeline_of_an_unknown_root_tool_compares_whole_targets(tmp_path: Path) -> None:
    _save(tmp_path, "admin", _doc(started="2026-10-01T10:00:00+00:00", seed="https://example.com/admin",
                                  pipeline="custom"), 1_000)
    now = diff._parse_time("2026-10-09T10:00:00+00:00")

    for root_tool in (None, "my-plugin-scanner"):
        assert diff.find_baseline(tmp_path, seed="https://example.com/login", pipeline="custom", before=now,
                                  root_tool=root_tool) is None


def test_a_host_scanning_pipeline_still_matches_one_host_however_it_is_written(tmp_path: Path) -> None:
    ports = _save(tmp_path, "ports", _doc(started="2026-10-01T10:00:00+00:00", seed="https://Example.com:8443/x",
                                          pipeline="ports-to-vuln"), 1_000)
    now = diff._parse_time("2026-10-09T10:00:00+00:00")

    assert diff.find_baseline(tmp_path, seed="example.com.", pipeline="ports-to-vuln", before=now,
                              root_tool="naabu") == ports
'''

FINISH_TESTS = '''

def test_a_url_scan_is_compared_only_with_a_run_of_the_same_url(settings: Settings, manager: ToolManager) -> None:
    """report.json records the seed; a run of another port or path of the same host
    is another scan, and is never its baseline."""

    def finish(seed: str, minutes_ago: int, seen: RunObserver) -> Finished:
        run_session = open_session(settings.reports_dir, kind="pipeline", name="web", session=None, stream=True)
        return finalize(
            _scan(minutes_ago, ("xss", "medium")), manager=manager, settings=settings, name="web", seed=seed,
            tools={"nuclei"}, session=run_session, compare=True, baseline=None, save=True, observer=seen,
        )

    finish("https://example.com:8443/admin", 10, Recorder())
    other, same = Recorder(), Recorder()

    assert finish("https://example.com:8080/other", 5, other).changes is None
    assert finish("https://example.com:8443/admin/", 1, same).changes is not None
    assert other.events == [] and same.events == ["compare:start", "compare:done"]
'''

tests = Source(root, "tests/unit/test_diff.py")
tests.replace(
    '    assert diff.find_baseline(tmp_path, seed="example.com", pipeline="recon-to-vuln", before=now) == wanted\n'
    '    assert diff.find_baseline(tmp_path, seed="nobody.com", pipeline="recon-to-vuln", before=now) is None\n'
    '    assert diff.find_baseline(tmp_path / "missing", seed="example.com", pipeline="recon-to-vuln", before=now) is None\n',
    '    def baseline(reports: Path, seed: str) -> Path | None:\n'
    '        # recon-to-vuln starts with subfinder, which scans the domain alone.\n'
    '        return diff.find_baseline(reports, seed=seed, pipeline="recon-to-vuln", before=now, root_tool="subfinder")\n'
    "\n"
    '    assert baseline(tmp_path, "example.com") == wanted\n'
    '    assert baseline(tmp_path, "nobody.com") is None\n'
    '    assert baseline(tmp_path / "missing", "example.com") is None\n',
)
tests.replace(
    '    assert diff.find_baseline(tmp_path, seed="example.com", pipeline="recon-to-vuln", before=later) == path\n',
    '    assert diff.find_baseline(tmp_path, seed="example.com", pipeline="recon-to-vuln", before=later,\n'
    '                              root_tool="subfinder") == path\n',
)
tests.text = tests.text.rstrip("\n") + "\n" + DIFF_TESTS
tests.save()

finish = Source(root, "tests/unit/test_core_finish.py")
finish.text = finish.text.rstrip("\n") + "\n" + FINISH_TESTS
finish.save()
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python "$W/task4_tests.py" .
uv run --quiet python -m pytest tests/unit/test_diff.py tests/unit/test_core_finish.py -q -p no:cacheprovider
```

Expected: `edited tests/unit/test_diff.py`, `edited tests/unit/test_core_finish.py`; then `7 failed, 34 passed` — six `TypeError: find_baseline() got an unexpected keyword argument 'root_tool'`, and the bug itself: `test_a_url_scan_is_compared_only_with_a_run_of_the_same_url` gets a `RunDiff` whose baseline is the `https://example.com:8443/admin` run for a scan of `https://example.com:8080/other`.

- [ ] **Step 3: Key a seed by what the root tool scans**

Save as `$W/task4_scope.py`:

```python
"""Task 4: a baseline is a run that scanned the same thing — keyed by what the root tool scans.

Usage: python task4_scope.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

diff = Source(root, "cyberfw/report/diff.py")
diff.replace(
    "def _seed_key(seed: str) -> str:\n"
    "    return hostname_of(seed.strip()).lower().rstrip(\".\")\n",
    "#: Built-in tools that scan only the host (or domain) of their target: for a pipeline\n"
    "#: that starts with one, seeds naming one host are one scan.\n"
    '_HOST_SCOPED = frozenset({"subfinder", "naabu", "rustscan"})\n'
    "#: Ports a URL leaves unsaid.\n"
    '_DEFAULT_PORTS = {"http": 80, "https": 443}\n'
    "\n"
    "\n"
    "def _scan_scope(seed: str, root_tool: str | None) -> str:\n"
    '    """What ``seed`` makes a pipeline that starts with ``root_tool`` scan, as a key:\n'
    "    two seeds with one key are one scan.\n"
    "\n"
    "    A host-scanning root tool (subfinder, naabu, rustscan) scans the host; nmap the\n"
    "    host and a port the seed names; any other — a URL scanner, a plugin, a tool not\n"
    "    known here — its target whole: scheme, host, port, path and query, with the\n"
    "    host's case, a default port and a trailing slash not counting.\n"
    '    """\n'
    "    text = seed.strip()\n"
    "    try:\n"
    '        parts = urlsplit(text if "://" in text else f"//{text}")\n'
    "        port = parts.port\n"
    "    except ValueError:  # not a URL or a host[:port] — compare it as written\n"
    "        return text.lower()\n"
    '    host = (parts.hostname or "").rstrip(".")\n'
    "    if root_tool in _HOST_SCOPED:\n"
    "        return host\n"
    '    if root_tool == "nmap":\n'
    '        return f"{host}:{port}" if port else host\n'
    "    scheme = parts.scheme.lower()\n"
    '    netloc = host if port in (None, _DEFAULT_PORTS.get(scheme)) else f"{host}:{port}"\n'
    '    query = f"?{parts.query}" if parts.query else ""\n'
    '    target = f"{netloc}{parts.path.rstrip(\'/\')}{query}"\n'
    '    return f"{scheme}://{target}" if scheme else target\n',
)
diff.replace(
    "def find_baseline(\n"
    "    reports_dir: Path, *, seed: str | None, pipeline: str | None, before: datetime | None\n"
    ") -> Path | None:\n"
    '    """The newest earlier ``report.json`` of the same pipeline and seed target, or ``None``."""\n'
    "    if not seed or not pipeline or not reports_dir.is_dir():\n"
    "        return None\n"
    "    want = _seed_key(seed)\n",
    "def find_baseline(\n"
    "    reports_dir: Path,\n"
    "    *,\n"
    "    seed: str | None,\n"
    "    pipeline: str | None,\n"
    "    before: datetime | None,\n"
    "    root_tool: str | None = None,\n"
    ") -> Path | None:\n"
    '    """The newest earlier ``report.json`` of the same pipeline that scanned what\n'
    "    ``seed`` makes it scan, or ``None``. ``root_tool`` is the pipeline's first\n"
    "    stage's tool: it says which parts of the seed count (:func:`_scan_scope`) — the\n"
    "    host alone for a pipeline that starts with subfinder, the whole URL for one\n"
    "    that starts with nuclei. Not known, the whole target counts.\n"
    '    """\n'
    "    if not seed or not pipeline or not reports_dir.is_dir():\n"
    "        return None\n"
    "    want = _scan_scope(seed, root_tool)\n",
)
diff.replace(
    '        if run is None or run.get("pipeline") != pipeline or _seed_key(str(run.get("seed") or "")) != want:\n',
    "        if (\n"
    "            run is None\n"
    '            or run.get("pipeline") != pipeline\n'
    '            or _scan_scope(str(run.get("seed") or ""), root_tool) != want\n'
    "        ):\n",
)
diff.save()

finish = Source(root, "cyberfw/core/finish.py")
finish.replace(
    "            path = rundiff.find_baseline(reports_dir, seed=run.seed, pipeline=run.pipeline, before=result.started_at)\n",
    "            path = rundiff.find_baseline(\n"
    "                reports_dir,\n"
    "                seed=run.seed,\n"
    "                pipeline=run.pipeline,\n"
    "                before=result.started_at,\n"
    "                root_tool=result.nodes[0].node.tool if result.nodes else None,\n"
    "            )\n",
)
finish.replace(
    '    """Compare this run with an earlier one — the one named, else the newest\n'
    "    earlier run of the same pipeline and seed. A first scan has nothing to compare\n",
    '    """Compare this run with an earlier one — the one named, else the newest\n'
    "    earlier run of the same pipeline that scanned the same target (its first\n"
    "    stage's tool says which parts of the seed count). A first scan has nothing to compare\n",
)
finish.save()

changelog = Source(root, "CHANGELOG.md")
changelog.replace(
    "### Fixed\n",
    "### Fixed\n"
    "- Сравнение с прошлым прогоном выбирало baseline по одному имени хоста: для\n"
    "  пайплайна, начинающегося с nuclei или httpx, прогон\n"
    "  `https://example.com:8443/admin` сравнивался с прогоном\n"
    "  `http://example.com:8080/other` — и находки непроверенного сервиса\n"
    "  числились исправленными. Теперь значит то, что сканирует первый этап:\n"
    "  у subfinder, naabu и rustscan — хост, у nmap — хост и порт, у остальных —\n"
    "  весь URL (схема, хост, порт, путь); регистр хоста, порт по умолчанию и\n"
    "  завершающий `/` не различаются.\n",
)
changelog.save()
```

```bash
uv run --quiet python "$W/task4_scope.py" .
```

Expected: `edited cyberfw/report/diff.py`, `edited cyberfw/core/finish.py`, `edited CHANGELOG.md`.

- [ ] **Step 4: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_diff.py tests/unit/test_core_finish.py tests/unit/test_diff_coverage.py -q -p no:cacheprovider
```

Expected: `55 passed`.

- [ ] **Step 5: The whole suite, lint, types**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1327 passed, 5 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 80 source files`.

- [ ] **Step 6: Commit** — reread `CLAUDE_HANDOFF.local.md` in the main checkout first (Global Constraints): if Codex has reserved a file of this task meanwhile, stop and ask the user. Then:

```bash
git commit -m "A baseline is a run that scanned the same thing: the root tool decides which parts of the seed count" -- cyberfw/report/diff.py cyberfw/core/finish.py tests/unit/test_diff.py tests/unit/test_core_finish.py CHANGELOG.md
git log -1 --format=%B | grep -ci co-authored
```

Expected: `0` from the `grep`.

---

### Task 5: The registry and lock in use are the workspace's the settings name (item 5)

**Files:**
- Modify (by script): `cyberfw/core/workspace.py` (`registry_candidates(root_dir=None)`, `registry_path(root_dir=None)`, `open_manager` passes `settings.root_dir`), `tests/unit/test_cli.py` (four stand-ins take the new argument), `CHANGELOG.md`; tests `tests/unit/test_core_workspace.py`

**Interfaces:**
- Produces: `registry_candidates(root_dir: Path | None = None)` and `registry_path(root_dir: Path | None = None)` — `None` means the current directory, as before.

- [ ] **Step 1: Write the failing tests**

Save as `$W/task5_tests.py`:

```python
"""Task 5, test first: the workspace the settings name is the one whose registry and lock are used.

Usage: python task5_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

TESTS = '''

class TestTheWorkspaceTheSettingsName:
    """``Settings(root_dir=...)`` and ``CYBERFW_ROOT_DIR`` name a workspace: its registry
    and its lock are the ones in use, whichever directory cyberfw is started from."""

    @staticmethod
    def _workspace(path: Path, tool: str | None) -> Path:
        path.mkdir()
        if tool is not None:
            (path / "registry.yaml").write_text(f"{tool}:\\n  repo: org/{tool}\\n  asset_patterns: []\\n", encoding="utf-8")
        return path

    @staticmethod
    def _opened(settings: Settings) -> tuple[list[str], Path]:
        manager = open_manager(settings)
        try:
            return manager.registry.names(), manager.lock_path
        finally:
            manager.close()

    def test_settings_naming_another_workspace_use_its_registry_and_lock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        here = self._workspace(tmp_path / "a", "only-in-a")
        there = self._workspace(tmp_path / "b", "only-in-b")
        monkeypatch.chdir(here)

        assert self._opened(Settings(root_dir=there)) == (["only-in-b"], there / "tools.lock")

    def test_the_environment_naming_another_workspace_does_the_same(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        here = self._workspace(tmp_path / "a", "only-in-a")
        there = self._workspace(tmp_path / "b", "only-in-b")
        monkeypatch.chdir(here)
        monkeypatch.setenv("CYBERFW_ROOT_DIR", str(there))

        assert self._opened(load_settings()) == (["only-in-b"], there / "tools.lock")

    def test_a_workspace_with_no_registry_never_borrows_the_current_directory_s(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # It runs on the registry cyberfw ships (the checkout's here, the wheel's
        # when installed), with the lock that belongs to that one.
        here = self._workspace(tmp_path / "a", "only-in-a")
        there = self._workspace(tmp_path / "b", None)
        monkeypatch.chdir(here)

        names, lock = self._opened(Settings(root_dir=there))

        assert "only-in-a" not in names and "subfinder" in names
        assert lock.parent not in (here, there)
'''

tests = Source(root, "tests/unit/test_core_workspace.py")
tests.replace("from cyberfw.config import Settings\n", "from cyberfw.config import Settings, load_settings\n")
tests.text = tests.text.rstrip("\n") + "\n" + TESTS
tests.save()
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python "$W/task5_tests.py" .
uv run --quiet python -m pytest tests/unit/test_core_workspace.py -q -p no:cacheprovider
```

Expected: `edited tests/unit/test_core_workspace.py`; then `3 failed, 3 passed` — with workspace B named, the registry of the current directory A was used: `AssertionError: assert (['only-in-a']…` (twice) and `assert ('only-in-a' not in ['only-in-a'])`.

- [ ] **Step 3: The workspace's registry first**

Save as `$W/task5_workspace.py`:

```python
"""Task 5: the registry in use is the workspace's the settings name, then the shipped one.

Usage: python task5_workspace.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

workspace = Source(root, "cyberfw/core/workspace.py")
workspace.replace(
    "def registry_candidates() -> list[Path]:\n"
    '    """Where ``registry.yaml`` may live, most specific first.\n'
    "\n"
    "    The current directory (a workspace the user may have edited), then the\n"
    "    checkout root next to the package (running from a clone elsewhere), then\n"
    "    the copy the wheel ships as ``cyberfw/data/registry.yaml``.\n"
    '    """\n'
    '    candidates = [Path.cwd() / "registry.yaml", Path(__file__).resolve().parents[2] / "registry.yaml"]\n',
    "def registry_candidates(root_dir: Path | None = None) -> list[Path]:\n"
    '    """Where ``registry.yaml`` may live, most specific first.\n'
    "\n"
    "    The workspace in use — ``root_dir``, the one the settings name\n"
    "    (``Settings.root_dir``: ``CYBERFW_ROOT_DIR``, ``load_settings(root_dir=...)``, the\n"
    "    current directory when it is a workspace), else the current directory — then\n"
    "    the checkout root next to the package (running from a clone elsewhere), then the\n"
    "    copy the wheel ships as ``cyberfw/data/registry.yaml``. A workspace with no\n"
    "    registry of its own thus runs on the one cyberfw ships, never on the current\n"
    "    directory's when the settings name another.\n"
    '    """\n'
    "    workspace = root_dir if root_dir is not None else Path.cwd()\n"
    '    candidates = [workspace / "registry.yaml", Path(__file__).resolve().parents[2] / "registry.yaml"]\n',
)
workspace.replace(
    "def registry_path() -> Path:\n"
    '    """Locate ``registry.yaml`` or raise a :class:`RegistryError` naming the places tried."""\n'
    "    candidates = registry_candidates()\n",
    "def registry_path(root_dir: Path | None = None) -> Path:\n"
    '    """Locate the ``registry.yaml`` of the workspace ``root_dir`` (see\n'
    "    :func:`registry_candidates`) or raise a :class:`RegistryError` naming the places tried.\"\"\"\n"
    "    candidates = registry_candidates(root_dir)\n",
)
workspace.replace(
    '    """A :class:`ToolManager` over the registry in use — with the plugin tools in use,\n'
    '    their recipes under its entries of the same name — and ``tools.lock`` next to it."""\n'
    "    path = registry_path()\n",
    '    """A :class:`ToolManager` over the registry of the workspace ``settings`` name —\n'
    "    with the plugin tools in use, their recipes under its entries of the same name —\n"
    "    and ``tools.lock`` next to it. With no registry of the workspace's own, that is\n"
    "    the one cyberfw ships, and the lock beside it (in site-packages, for a wheel).\"\"\"\n"
    "    path = registry_path(settings.root_dir)\n",
)
workspace.save()

cli_tests = Source(root, "tests/unit/test_cli.py")
cli_tests.replace(
    '        patch_cli(monkeypatch, "registry_candidates", lambda: [tmp_path / "missing.yaml", packaged])\n',
    '        patch_cli(monkeypatch, "registry_candidates", lambda *_: [tmp_path / "missing.yaml", packaged])\n',
)
cli_tests.replace(
    '        patch_cli(monkeypatch, "registry_candidates", lambda: [tmp_path / "missing.yaml"])\n',
    '        patch_cli(monkeypatch, "registry_candidates", lambda *_: [tmp_path / "missing.yaml"])\n',
)
cli_tests.replace(
    '        patch_cli(monkeypatch, "registry_path", lambda: checkout / "registry.yaml")\n',
    '        patch_cli(monkeypatch, "registry_path", lambda *_: checkout / "registry.yaml")\n',
)
cli_tests.replace(
    '        patch_cli(monkeypatch, "registry_path", lambda: site / "registry.yaml")\n',
    '        patch_cli(monkeypatch, "registry_path", lambda *_: site / "registry.yaml")\n',
)
cli_tests.save()

changelog = Source(root, "CHANGELOG.md")
changelog.replace(
    "### Fixed\n",
    "### Fixed\n"
    "- `CYBERFW_ROOT_DIR` и `Settings(root_dir=...)` меняли каталоги отчётов и\n"
    "  инструментов, но `registry.yaml` и `tools.lock` по-прежнему брались из\n"
    "  текущего каталога — то есть из другого workspace. Теперь первым ищется\n"
    "  registry того workspace, который называют настройки, и lock лежит рядом с ним;\n"
    "  у workspace без своего registry — поставляемый с cyberfw (в клоне — из\n"
    "  репозитория, при установке из wheel — из пакета) и lock рядом с ним.\n",
)
changelog.save()
```

```bash
uv run --quiet python "$W/task5_workspace.py" .
```

Expected: `edited cyberfw/core/workspace.py`, `edited tests/unit/test_cli.py`, `edited CHANGELOG.md`.

- [ ] **Step 4: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_core_workspace.py -q -p no:cacheprovider
```

Expected: `6 passed`.

- [ ] **Step 5: The whole suite, lint, types**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1330 passed, 5 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 80 source files`.

- [ ] **Step 6: Commit** — reread `CLAUDE_HANDOFF.local.md` in the main checkout first (Global Constraints): if Codex has reserved a file of this task meanwhile, stop and ask the user. Then:

```bash
git commit -m "The registry and lock in use are the workspace's the settings name, not the current directory's" -- cyberfw/core/workspace.py tests/unit/test_core_workspace.py tests/unit/test_cli.py CHANGELOG.md
git log -1 --format=%B | grep -ci co-authored
```

Expected: `0` from the `grep`.

---

### Task 6: An update never destroys the installed version (item 6)

**Files:**
- Modify (by script): `cyberfw/manager/installer.py` (unpack into `.<tool>.staging-*`, `_swap_in`, `_clear_leftovers`, `_remove_tree`; `_remove_existing_binary(spec, keep=...)`), `cyberfw/manager/__init__.py` (no early unlink of the record; `_write_state` via a temp file and `os.replace`), `CHANGELOG.md`; tests `tests/unit/test_installer.py`, `tests/unit/test_manager.py`

**Interfaces:**
- Produces: `ToolInstaller.install_locked` unchanged in signature; it raises `DownloadError("could not put the new <tool> in place: …")` after putting the installed version back when the swap fails.

- [ ] **Step 1: Write the failing tests**

Save as `$W/task6_tests.py`:

```python
"""Task 6, test first: an update that fails leaves the installed version and its record as they were.

Usage: python task6_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

INSTALLER_TESTS = '''

class _Offline(_FakeClient):
    """The connection drops halfway through the download."""

    def download(self, url: str, destination: Path, *, expected_size: int | None = None) -> None:
        destination.write_bytes(b"partial")
        raise DownloadError("connection reset")


class TestAFailedUpdateKeepsTheInstalledVersion:
    """The new version is unpacked and checked beside the installed one, and takes its
    place only once it holds the tool's executable: a failed download, a wrong hash, a
    damaged or oversized archive, one without the executable, or a failed swap leave
    the installed version — every file of it — as it was, and nothing behind."""

    _OLD = b"#!/bin/sh\\necho old\\n"

    def _installed(self, installer: ToolInstaller) -> Path:
        tool_dir = installer.tools_dir / "subfinder"
        tool_dir.mkdir(parents=True)
        (tool_dir / "subfinder").write_bytes(self._OLD)
        (tool_dir / "README.md").write_text("old docs", encoding="utf-8")
        return tool_dir

    def _assert_untouched(self, installer: ToolInstaller, tool_dir: Path) -> None:
        assert (tool_dir / "subfinder").read_bytes() == self._OLD
        assert (tool_dir / "README.md").read_text(encoding="utf-8") == "old docs"
        assert sorted(path.name for path in installer.tools_dir.iterdir()) == ["subfinder"]

    @pytest.mark.parametrize("failure", ["download", "hash", "corrupt", "no executable", "too big"])
    def test_a_failed_update_leaves_the_installed_version(self, tmp_path: Path, failure: str) -> None:
        archive = {
            "corrupt": b"PK\\x03\\x04 definitely not a zip",
            "no executable": _zip_bytes({"README.md": b"new docs"}),
            "too big": _zip_bytes({"subfinder": b"#!/bin/sh\\n" + b"x" * 4096}),
        }.get(failure, _zip_bytes({"subfinder": b"#!/bin/sh\\necho new\\n"}))
        client = _Offline(archive) if failure == "download" else _FakeClient(archive)
        installer = _installer(tmp_path, client, max_archive_size=1024)
        tool_dir = self._installed(installer)
        locked = _locked(_SUBFINDER_ZIP, archive, sha256="0" * 64 if failure == "hash" else None)

        with pytest.raises((DownloadError, ChecksumError, ToolNotFoundError)):
            installer.install_locked(_spec(), "2.0.0", locked)

        self._assert_untouched(installer, tool_dir)

    def test_a_failed_swap_puts_the_installed_version_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        archive = _zip_bytes({"subfinder": b"#!/bin/sh\\necho new\\n"})
        installer = _installer(tmp_path, _FakeClient(archive))
        tool_dir = self._installed(installer)
        real_rename = Path.rename

        def refuse_the_new_version(self: Path, target: str | Path) -> Path:
            if self.name.startswith(".subfinder.staging-"):
                raise PermissionError(13, "Permission denied")
            return real_rename(self, target)

        monkeypatch.setattr(Path, "rename", refuse_the_new_version)

        with pytest.raises(DownloadError, match="could not put the new subfinder in place"):
            _install(installer, _spec(), archive, _SUBFINDER_ZIP)

        self._assert_untouched(installer, tool_dir)

    def test_an_update_while_the_old_version_runs_still_lands(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Windows will not delete a running exe, but renames it — and the directory
        around it: the old copy is parked, and it never shadows the new one."""
        archive = _zip_bytes({"naabu.exe": b"#!/bin/sh\\necho new\\n"})
        installer = _installer(tmp_path, _FakeClient(archive), Mapping("windows", "amd64"))
        running = installer.tools_dir / "naabu" / "naabu.exe"
        running.parent.mkdir(parents=True)
        running.write_bytes(b"running")
        real_unlink = Path.unlink

        def in_use(self: Path, missing_ok: bool = False) -> None:
            if self.is_file() and self.read_bytes() == b"running":
                raise PermissionError(32, "The process cannot access the file because it is being used")
            real_unlink(self, missing_ok=missing_ok)

        monkeypatch.setattr(Path, "unlink", in_use)
        spec = _spec(name="naabu", binary="naabu", asset_patterns=["*windows*amd64*"])

        result = _install(installer, spec, archive, "naabu_2.0.0_windows_amd64.zip")

        assert result.binary == running.resolve()
        assert result.binary.read_bytes() == b"#!/bin/sh\\necho new\\n"
        assert ensure_binary(installer.tools_dir, "naabu", "naabu") == running
'''

MANAGER_TESTS = '''

class TestAFailedReinstallKeepsTheRecord:
    """A re-install that fails leaves the installed version and the record of it as
    they were: the tool is still installed, at the version it had."""

    @pytest.mark.parametrize("failure", ["network", "tampered"])
    def test_the_record_survives_a_failed_reinstall(self, tmp_path: Path, failure: str) -> None:
        manager, client = _manager_with(tmp_path)
        manager.install("subfinder")
        before = manager.install_state("subfinder")
        if failure == "network":

            def offline(url: str, destination: Path, *, expected_size: int | None = None) -> None:
                raise DownloadError("connection reset")

            client.download = offline  # type: ignore[method-assign]
        else:
            client.archive_bytes = _zip_bytes({"subfinder": b"#!/bin/sh\\necho tampered\\n"})

        with pytest.raises((DownloadError, ChecksumError)):
            manager.install("subfinder", force=True)

        assert manager.install_state("subfinder") == before
        assert manager.is_installed("subfinder")

    def test_a_record_that_cannot_be_written_leaves_the_one_before(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        manager, _ = _manager_with(tmp_path)
        manager.install("subfinder")
        before = manager.install_state("subfinder")
        real_write = Path.write_text

        def disk_full(self: Path, *args: object, **kwargs: object) -> int:
            if self.name.startswith(".subfinder.install.json"):
                raise OSError(28, "No space left on device")
            return real_write(self, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(Path, "write_text", disk_full)
        with pytest.raises(OSError, match="No space left"):
            manager.install("subfinder", force=True)
        monkeypatch.undo()

        assert manager.install_state("subfinder") == before
        records = sorted(path.name for path in manager.settings.tools_dir.glob(".subfinder.*"))
        assert records == [".subfinder.install.json"]
'''

installer = Source(root, "tests/unit/test_installer.py")
installer.replace(
    "from cyberfw.manager.verify import checksum_for\n",
    "from cyberfw.manager.verify import checksum_for, ensure_binary\n",
)
installer.text = installer.text.rstrip("\n") + "\n" + INSTALLER_TESTS
installer.save()

manager = Source(root, "tests/unit/test_manager.py")
manager.text = manager.text.rstrip("\n") + "\n" + MANAGER_TESTS
manager.save()
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python "$W/task6_tests.py" .
uv run --quiet python -m pytest tests/unit/test_installer.py tests/unit/test_manager.py -q -p no:cacheprovider -k "FailedUpdate or FailedReinstall"
```

Expected: `edited tests/unit/test_installer.py`, `edited tests/unit/test_manager.py`; then `7 failed, 3 passed` — the installed binary gone after a corrupt, executable-less or oversized archive (`FileNotFoundError: …tools_bin\subfinder\subfinder`, three times), `DID NOT RAISE DownloadError` for the swap (there is none yet), and the install record lost (`assert None == {'binary': …`, three times). The three that pass — a failed download, a wrong hash, an update over a running version — guard what already worked.

- [ ] **Step 3: Unpack beside, then swap; write the record whole**

Save as `$W/task6_install.py`:

```python
"""Task 6: a new version is unpacked and checked beside the installed one before it replaces it.

Usage: python task6_install.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

installer = Source(root, "cyberfw/manager/installer.py")
installer.replace(
    "Layout: each tool is unpacked into its own ``tools_bin/<tool>/`` directory, which\n"
    "is wiped on re-install; the downloaded archive is deleted once extracted. The\n"
    "top level of ``tools_bin/`` therefore only holds those directories plus the\n"
    "``.<tool>.install.json`` state files written by :class:`ToolManager`.\n",
    "Layout: each tool lives in its own ``tools_bin/<tool>/`` directory. A re-install\n"
    "unpacks the new version into ``.<tool>.staging-*`` beside it and, once that holds\n"
    "the tool's executable, swaps the two (the old one passing through\n"
    "``.<tool>.previous-*`` on its way out), so a failed update leaves the installed\n"
    "version as it was; the downloaded archive is deleted once extracted. The top level\n"
    "of ``tools_bin/`` therefore only holds those directories plus the\n"
    "``.<tool>.install.json`` state files written by :class:`ToolManager`.\n",
)
installer.replace(
    '        """Install one platform\'s entry of a locked release, verified against the lock.\n'
    "\n"
    "        The archive's SHA-256 must equal the lock's *before* anything of the\n"
    "        previous install is touched, so a replaced or corrupted download leaves\n"
    "        the working tool in place. The downloaded archive is always removed.\n"
    '        """\n'
    "        tool_dir = self.tools_dir / spec.name\n"
    "        archive_path = self.tools_dir / asset.name\n"
    "        try:\n"
    "            self.client.download(asset.url, archive_path)\n"
    "            actual = sha256_hex(archive_path)\n"
    "            if actual != asset.sha256:\n"
    "                raise ChecksumError(\n"
    '                    f"SHA-256 mismatch for {asset.name}: tools.lock has {asset.sha256}, got {actual}"\n'
    "                )\n"
    "            self._remove_existing_binary(spec)\n"
    "            self._remove_stale_downloads(spec, keep=archive_path)\n"
    "            self._reset_tool_dir(tool_dir)\n"
    "            binary = self._extract(spec, archive_path, tool_dir)\n"
    "        finally:\n"
    "            archive_path.unlink(missing_ok=True)\n"
    "        self._make_executable(binary)\n",
    '        """Install one platform\'s entry of a locked release, verified against the lock.\n'
    "\n"
    "        The archive's SHA-256 must equal the lock's, and the archive must unpack —\n"
    "        beside the installed version — to the tool's executable, before anything of\n"
    "        the installed version is touched: a failed download, a wrong hash, a damaged\n"
    "        or oversized archive, one without the executable, or a swap that fails all\n"
    "        leave the working tool in place. The downloaded archive is always removed.\n"
    '        """\n'
    "        tool_dir = self.tools_dir / spec.name\n"
    "        archive_path = self.tools_dir / asset.name\n"
    '        staging = self.tools_dir / f".{spec.name}.staging-{uuid.uuid4().hex[:8]}"\n'
    "        try:\n"
    "            self.client.download(asset.url, archive_path)\n"
    "            actual = sha256_hex(archive_path)\n"
    "            if actual != asset.sha256:\n"
    "                raise ChecksumError(\n"
    '                    f"SHA-256 mismatch for {asset.name}: tools.lock has {asset.sha256}, got {actual}"\n'
    "                )\n"
    "            self._clear_leftovers(spec)\n"
    "            staging.mkdir()\n"
    "            unpacked = self._extract(spec, archive_path, staging)\n"
    "            self._make_executable(unpacked)\n"
    "            self._swap_in(staging, tool_dir)\n"
    "        finally:\n"
    "            archive_path.unlink(missing_ok=True)\n"
    "            self._remove_tree(staging)  # a failed install's unpacked copy; a swapped-in one is gone\n"
    "        binary = tool_dir / unpacked.relative_to(staging)\n"
    "        self._remove_existing_binary(spec, keep=tool_dir)\n"
    "        self._remove_stale_downloads(spec, keep=archive_path)\n",
)
installer.replace(
    "    def _reset_tool_dir(self, tool_dir: Path) -> None:\n"
    '        """Empty ``tool_dir`` so nothing from the previous version survives the re-install.\n'
    "\n"
    "        A file Windows still holds open is parked under a ``.stale-*`` name (see\n"
    "        :meth:`_unlink_or_park`); ``rmtree`` then leaves it in place and the fresh\n"
    "        extraction happens around it.\n"
    '        """\n'
    "        if tool_dir.is_dir():\n"
    "            for path in list(tool_dir.rglob(\"*\")):\n"
    "                if path.is_file():\n"
    "                    self._unlink_or_park(path)\n"
    "            shutil.rmtree(tool_dir, ignore_errors=True)\n"
    "        tool_dir.mkdir(parents=True, exist_ok=True)\n",
    "    def _swap_in(self, staging: Path, tool_dir: Path) -> None:\n"
    '        """Put the unpacked new version in ``tool_dir``\'s place: the installed one moves\n'
    "        aside first and is removed after, and a swap that fails puts it back. (Windows\n"
    "        renames a directory even while a tool inside it runs.)\"\"\"\n"
    "        previous: Path | None = None\n"
    "        if tool_dir.exists():\n"
    '            previous = tool_dir.with_name(f".{tool_dir.name}.previous-{uuid.uuid4().hex[:8]}")\n'
    "            try:\n"
    "                tool_dir.rename(previous)\n"
    "            except OSError as exc:\n"
    "                raise DownloadError(\n"
    '                    f"could not move the installed {tool_dir.name} aside: {exc}"\n'
    "                ) from exc\n"
    "        try:\n"
    "            staging.rename(tool_dir)\n"
    "        except OSError as exc:\n"
    "            if previous is not None:\n"
    "                previous.rename(tool_dir)\n"
    '            raise DownloadError(f"could not put the new {tool_dir.name} in place: {exc}") from exc\n'
    "        if previous is not None:\n"
    "            self._remove_tree(previous)\n"
    "\n"
    "    def _clear_leftovers(self, spec: ToolSpec) -> None:\n"
    '        """Remove what an interrupted earlier install of this tool left beside it."""\n'
    '        for pattern in (f".{spec.name}.staging-*", f".{spec.name}.previous-*"):\n'
    "            for path in list(self.tools_dir.glob(pattern)):\n"
    "                self._remove_tree(path)\n"
    "\n"
    "    def _remove_tree(self, path: Path) -> None:\n"
    '        """Remove ``path``: a file, or a directory and everything in it.\n'
    "\n"
    "        A file Windows still holds open is parked under a ``.stale-*`` name (see\n"
    "        :meth:`_unlink_or_park`), so it no longer shadows a binary of the same name;\n"
    "        ``rmtree`` then leaves it, and its directory, in place.\n"
    '        """\n'
    "        if path.is_dir():\n"
    '            for item in list(path.rglob("*")):\n'
    "                if item.is_file():\n"
    "                    self._unlink_or_park(item)\n"
    "            shutil.rmtree(path, ignore_errors=True)\n"
    "        elif path.exists():\n"
    "            self._unlink_or_park(path)\n",
)
installer.replace(
    "    def _remove_existing_binary(self, spec: ToolSpec) -> None:\n"
    '        """Remove stale copies of the binary anywhere under ``tools_dir``.\n',
    "    def _remove_existing_binary(self, spec: ToolSpec, *, keep: Path) -> None:\n"
    '        """Remove stale copies of the binary anywhere under ``tools_dir`` but ``keep``.\n',
)
installer.replace(
    "            if path.is_file() and path.name.lower() in wanted:\n"
    "                self._unlink_or_park(path)\n",
    "            if path.is_file() and path.name.lower() in wanted and keep not in path.parents:\n"
    "                self._unlink_or_park(path)\n",
)
installer.save()

manager = Source(root, "cyberfw/manager/__init__.py")
manager.replace("import json\nimport tempfile\n", "import json\nimport os\nimport tempfile\nimport uuid\n")
manager.replace(
    '        state_path = self.settings.tools_dir / f".{name}.install.json"\n'
    "        state_path.unlink(missing_ok=True)\n"
    "        installer = ToolInstaller(\n",
    '        state_path = self.settings.tools_dir / f".{name}.install.json"\n'
    "        installer = ToolInstaller(\n",
)
manager.replace(
    "        result = installer.install_locked(spec, entry.version, asset)\n"
    "        state_path.write_text(\n"
    "            json.dumps(\n"
    "                {\n"
    '                    "binary": str(result.binary.resolve()),\n'
    '                    "version": result.version,\n'
    '                    "sha256": asset.sha256,\n'
    '                    "os": self.mapping.os_name,\n'
    '                    "arch": self.mapping.arch,\n'
    "                }\n"
    "            ),\n"
    '            encoding="utf-8",\n'
    "        )\n"
    "        return result\n",
    "        result = installer.install_locked(spec, entry.version, asset)\n"
    "        _write_state(\n"
    "            state_path,\n"
    "            {\n"
    '                "binary": str(result.binary.resolve()),\n'
    '                "version": result.version,\n'
    '                "sha256": asset.sha256,\n'
    '                "os": self.mapping.os_name,\n'
    '                "arch": self.mapping.arch,\n'
    "            },\n"
    "        )\n"
    "        return result\n",
)
manager.text = manager.text.rstrip("\n") + (
    "\n\n\n"
    "def _write_state(path: Path, state: dict[str, str]) -> None:\n"
    '    """Write an install record whole or not at all — a temp file, then ``os.replace`` —\n'
    "    so a failed write leaves the record before it.\"\"\"\n"
    '    tmp = path.with_name(f"{path.name}.{uuid.uuid4().hex[:8]}.tmp")\n'
    "    try:\n"
    '        tmp.write_text(json.dumps(state), encoding="utf-8")\n'
    "        os.replace(tmp, path)\n"
    "    except BaseException:\n"
    "        tmp.unlink(missing_ok=True)\n"
    "        raise\n"
)
manager.save()

changelog = Source(root, "CHANGELOG.md")
changelog.replace(
    "### Fixed\n",
    "### Fixed\n"
    "- Обновление инструмента удаляло рабочую версию до того, как новая была\n"
    "  распакована: повреждённый архив, архив без исполняемого файла, превышение\n"
    "  лимита распаковки или сетевой сбой оставляли без инструмента и без записи о\n"
    "  его версии. Теперь новая версия распаковывается и проверяется рядом со старой\n"
    "  и встаёт на её место только целиком; при любом сбое — и при неудачной замене —\n"
    "  остаются прежний инструмент и его запись, а запись пишется атомарно.\n",
)
changelog.save()
```

```bash
uv run --quiet python "$W/task6_install.py" .
```

Expected: `edited cyberfw/manager/installer.py`, `edited cyberfw/manager/__init__.py`, `edited CHANGELOG.md`.

- [ ] **Step 4: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_installer.py tests/unit/test_manager.py tests/unit/test_lock.py -q -p no:cacheprovider
```

Expected: `131 passed`.

- [ ] **Step 5: The whole suite, lint, types, and the output**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1340 passed, 5 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 80 source files`.

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/6-all" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -rb "$W/transcripts/0-base" "$W/transcripts/6-all" && echo identical
```

Expected: `50 passed`, then `identical`. Two differences are not findings: an `elapsed <dur> (1m…s)` line (a loaded machine — capture again into an empty directory), and, in `pipeline-ffuf-verbose-topology`, nuclei's and ffuf's raw lines in the other order — two stages running at once print in whichever order they happen to, and starting each tool in its own group shifts that race (the dry run saw it once in four captures). Anything else is.

- [ ] **Step 6: Commit** — reread `CLAUDE_HANDOFF.local.md` in the main checkout first (Global Constraints): if Codex has reserved a file of this task meanwhile, stop and ask the user. Then:

```bash
git commit -m "An update unpacks beside the installed version and replaces it only whole; a failure keeps the old one and its record" -- cyberfw/manager/installer.py cyberfw/manager/__init__.py tests/unit/test_installer.py tests/unit/test_manager.py CHANGELOG.md
git log -1 --format=%B | grep -ci co-authored
```

Expected: `0` from the `grep`.

---

### After Task 6: push, and move the main checkout

- [ ] **Step 1: Push** — reread `CLAUDE_HANDOFF.local.md` once more, then:

```bash
git log --oneline 695b50b..HEAD
git push origin HEAD:main
```

Expected: the plan's commit and the six task commits; the push lands on `main`.

- [ ] **Step 2: Move the main checkout** — in `C:/Users/DaniilSirbu/Desktop/CS-TOOL_main`:

```bash
git status --short
git fetch origin && git merge --ff-only origin/main && git status --short
```

Expected: a fast-forward; `git status` lists the same files before and after — the user's staged `.gitignore` and `upgrades.md`, Codex's `.gitignore` lines and `tests/unit/test_upgrade_flows.py`.
