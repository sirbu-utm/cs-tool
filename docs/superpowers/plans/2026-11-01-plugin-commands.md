# Plugin Commands Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user see, enable and disable the plugin packages installed next to cyberfw from the command line — `cyberfw plugins`, `plugins enable <package> [--allow-code]`, `plugins disable <package>` — and show everywhere a tool is listed or reported where it came from.

**Architecture:** `cyberfw/manager/plugins.py` gains `write_plugins_file` (atomic). `cyberfw/core/plugins.py` (new, no UI) enables and disables a package: it finds the package by its normalised name, refuses a code package without `allow_code`, writes `plugins.yaml` only when it changes, and loads the package at once so its tools' states are known. `cyberfw/cli/plugins.py` (new) is the `plugins` command group over it, with the spec's exit codes. The tool inventory (`cli/views.py`, shared by `status` and the launcher) gains an origin column and `status` a plugins line; `RunInfo` gains `tool_plugins`, written to `report.json` only for a run that used a plugin tool.

**Tech Stack:** Python 3.14 via `uv`, Typer (command group), Rich, PyYAML, pytest, ruff, mypy `--strict`.

**Spec:** `docs/superpowers/specs/2026-10-26-tool-plugins-design.md` — this plan is its **Step 4** ("The CLI"), on top of Steps 1–3 (`8e537a6`…`53a3f70`) and the `upgrades.md` fixes since (`main` at `72f744a`). The docs (README «Плагины», the CHANGELOG) are Step 5.

Departures from the spec's text, each keeping its intent:

- **"`status` and `tools` get the origin column"**: cyberfw has no `tools` command — the tool inventory is the table `status` and the launcher's menu share, and that table gains the column.
- **`--help` lists `plugins` last**: Typer lists a command group after the plain commands. `tests/unit/test_cli_package.py`, which pins the commands, their order and the CLI's modules, records it.
- **The launcher and completion already offer enabled plugin tools** — since Step 3 they read the registry the manager builds; Task 3 pins it with a test. The hints in `run` and pipelines are Step 3's too (`test_a_plugin_tool_not_in_use_says_why_and_what_to_do`).
- **`--allow-code` on a manifest package allows nothing**: written to `allow_code`, it would let a later release that starts shipping Python load without a new decision.
- **The `status` line counts plugin tools by state** — the rows of `cyberfw plugins` — and says `none installed` without any.
- **Enabling lives in `cyberfw/core/plugins.py`**, not in the public API (the spec: running someone else's code is the user's decision).

Every file, script and `Expected:` line below comes from running this plan on a throwaway worktree of `main` at `72f744a`: the suite goes 1348 → 1360 → 1370 → 1373 → 1376 passed; ruff and mypy `--strict` are clean after each task; the transcripts of all 50 scenarios are identical to the baseline after Task 4 (but for the race named in Task 4, Step 5).

## Global Constraints

- Run everything through `uv run --quiet …`. Suite: `uv run --quiet python -m pytest -q`; lint: `uv run --quiet ruff check .`; types: `uv run --quiet mypy cyberfw`. All clean at the end of every task.
- **Without plugins, everything works as before** (spec, Compatibility) — except the three additions: the origin column, the plugins line in `status`, the `plugins` command in `--help`. `report.json` gains one optional field, only for a run that used a plugin tool.
- **Nothing of a package runs unless it is enabled — and, for code, allowed** (spec): enabling a code package without `--allow-code` changes nothing.
- **Work in a clean worktree of `main`, never in the main checkout**: the main checkout holds the user's staged `.gitignore` and `upgrades.md` (and an unstaged edit of it), Codex's unstaged `.gitignore` lines and its uncommitted `tests/unit/test_upgrade_flows.py`. Push with `git push origin HEAD:main` at the end; the main checkout then moves only by `git merge --ff-only`.
- Commits: one per task, by path only (`git commit -m "…" -- <paths>`); **no `Co-Authored-By` trailer** (the user's rule for this repo); never `CS-TOOL_presentation.pdf` or `CLAUDE_HANDOFF.local.md`.
- Before each commit and before the push, reread `CLAUDE_HANDOFF.local.md`: if Codex has reserved a file of the task meanwhile, stop and ask the user.
- Scratchpad: `SCRATCH=C:/Users/DANIIL~1/AppData/Local/Temp/claude/C--Users-DaniilSirbu-Desktop-CS-TOOL-main/6a8b772a-7993-414c-98b5-45500cbb762c/scratchpad`, `W="$SCRATCH/s4-exec"`. The plan's scripts and transcripts live in `$W`, never in the repo.

## Review Focus

1. A package named another way than it is installed (`CyberFW_Sample` for `cyberfw-sample`) is found, and written once, normalised → `test_a_package_is_found_however_its_name_is_spelled` (Task 1).
2. A `plugins.yaml` the user broke by hand is never overwritten by a guess — the commands refuse with exit 2 and leave it as it is → `test_a_plugins_yaml_that_cannot_be_read_is_left_as_it_is` (Task 1), `test_a_plugins_yaml_that_cannot_be_read_exits_2` (Task 2).
3. `--allow-code` given for a manifest package does not pre-authorise a later release that ships Python → `test_allowing_code_for_a_manifest_package_allows_none` (Task 1).
4. On an 80-column terminal the plugin table keeps every name whole; only the reason wraps → `test_plugins_lists_each_tool_with_its_package_kind_env_state_and_reason` (Task 2; the test runner's console is 80 wide).
5. A report of a run of built-in tools alone is exactly as before — no `tool_plugins` key → `test_a_run_of_built_in_tools_records_no_plugins` (Task 4) and the transcripts.

---

### Before Task 1: the worktree, the tools and a baseline

- [ ] **Step 1: A clean worktree of `main`** — from the main checkout:

```bash
mkdir -p "$W"
git fetch origin && git worktree add --detach "$W/repo" origin/main
cd "$W/repo" && uv sync --quiet --extra dev && git log --oneline -1
```

Expected: `72f744a No signal that ends cyberfw leaves a tool running, no leftover holds a stage open, no install leftover passes for the tool` (a later commit of `main` is fine if `git log 72f744a..origin/main` touches no file of this plan). Every later command runs in `$W/repo`.

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

Expected: `50 passed`; `1348 passed, 9 skipped, 8 deselected`; `git status` shows nothing.

---

### Task 1: Enabling and disabling a package, and writing plugins.yaml

**Files:**
- Create: `cyberfw/core/plugins.py`, `tests/unit/test_plugin_commands.py`
- Modify (by script): `cyberfw/manager/plugins.py` (`write_plugins_file`)

**Interfaces:**
- Consumes (Step 3): `discover`, `normalize` (`cyberfw/manager/discovery.py`); `PluginInfo`, `PluginsFile`, `read_plugins_file`, `load_plugins` (`cyberfw/manager/plugins.py`); `Settings.plugins_file`; `PluginError`.
- Produces, in `cyberfw/manager/plugins.py`: `write_plugins_file(path: Path, chosen: PluginsFile) -> None` (raises `PluginError`).
- Produces, in `cyberfw/core/plugins.py`: `enable_plugin(settings, package, *, allow_code=False) -> Enabled` (raises `UnknownPackage`, `CodeNotAllowed`, both `PluginError`s, or `PluginError`); `disable_plugin(settings, package) -> bool`; `Enabled(package: str, already: bool, tools: list[PluginInfo])` with `.working`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_plugin_commands.py`:

```python
"""Enabling and disabling plugin packages: ``plugins.yaml``, the states right after, and the commands."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from cyberfw.config import load_settings
from cyberfw.core import plugins as enabling
from cyberfw.exceptions import PluginError
from cyberfw.manager import plugins

from . import test_cli as base
from ._dists import install
from .test_plugin_tools import BAR, SAMPLE

#: A manifest the loader refuses: no install recipe.
BROKEN = "contract: 1\ntarget: ['-u', '{target}']\nrecord: {kind: http, target: url}\n"


@pytest.fixture(autouse=True)
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, site: Path) -> Path:
    """The CLI tests' workspace of fake tools and two plugin packages installed, none
    enabled: ``cyberfw-sample`` (a manifest) and ``cyberfw-bar`` (code)."""
    base._write_fake_binaries(tmp_path / "tools_bin")
    base._write_registry(tmp_path)
    base.TestBaselineComparison._tool_prints(tmp_path, "sample", {"url": "https://sample.example.com/", "status_code": 200})
    install(site, "cyberfw-sample", manifests={"sample": "cyberfw_sample"}, files={"cyberfw_sample/sample.yaml": SAMPLE})
    install(site, "cyberfw-bar", tools={"bar": "cyberfw_bar:PLUGIN"}, files={"cyberfw_bar/__init__.py": BAR})
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(plugins, "_LOADED", {})
    monkeypatch.setattr(plugins, "_WARNED", set())
    return tmp_path


def _file(workspace: Path) -> plugins.PluginsFile:
    return plugins.read_plugins_file(workspace / "plugins.yaml")


# -- enabling and disabling ----------------------------------------------------------------
def test_enabling_a_manifest_package_writes_plugins_yaml_and_loads_it_at_once(workspace: Path) -> None:
    result = enabling.enable_plugin(load_settings(), "cyberfw-sample")

    assert (result.package, result.already, result.working) == ("cyberfw-sample", False, True)
    assert [(info.tool, info.state) for info in result.tools] == [("sample", "enabled")]
    assert _file(workspace) == plugins.PluginsFile(enabled=frozenset({"cyberfw-sample"}))


def test_a_package_is_found_however_its_name_is_spelled(workspace: Path) -> None:
    assert enabling.enable_plugin(load_settings(), "CyberFW_Sample").package == "cyberfw-sample"
    assert _file(workspace).enabled == {"cyberfw-sample"}


def test_enabling_it_again_changes_nothing(workspace: Path) -> None:
    enabling.enable_plugin(load_settings(), "cyberfw-sample")
    before = (workspace / "plugins.yaml").read_bytes()

    again = enabling.enable_plugin(load_settings(), "cyberfw-sample")

    assert again.already and again.working
    assert (workspace / "plugins.yaml").read_bytes() == before


def test_a_code_package_is_enabled_only_when_its_code_is_allowed(workspace: Path) -> None:
    with pytest.raises(enabling.CodeNotAllowed, match="Python that would run inside cyberfw.*--allow-code"):
        enabling.enable_plugin(load_settings(), "cyberfw-bar")
    assert not (workspace / "plugins.yaml").exists()

    result = enabling.enable_plugin(load_settings(), "cyberfw-bar", allow_code=True)

    assert [(info.tool, info.state) for info in result.tools] == [("bar", "enabled")]
    assert _file(workspace) == plugins.PluginsFile(
        enabled=frozenset({"cyberfw-bar"}), allow_code=frozenset({"cyberfw-bar"})
    )


def test_allowing_code_for_a_manifest_package_allows_none(workspace: Path) -> None:
    # Were it written to allow_code, a release that starts shipping Python would load it.
    enabling.enable_plugin(load_settings(), "cyberfw-sample", allow_code=True)

    assert _file(workspace).allow_code == frozenset()


def test_an_unknown_package_names_those_that_declare_tools(workspace: Path) -> None:
    with pytest.raises(enabling.UnknownPackage, match=r"'cyberfw-nope'.*those that do: cyberfw-bar, cyberfw-sample"):
        enabling.enable_plugin(load_settings(), "cyberfw-nope")
    assert not (workspace / "plugins.yaml").exists()


def test_a_broken_package_stays_enabled_so_a_fixed_release_needs_nothing_more(workspace: Path, site: Path) -> None:
    install(site, "cyberfw-broken", manifests={"broken": "cyberfw_broken"}, files={"cyberfw_broken/broken.yaml": BROKEN})

    result = enabling.enable_plugin(load_settings(), "cyberfw-broken")

    assert not result.working and [info.state for info in result.tools] == ["broken"]
    assert _file(workspace).enabled == {"cyberfw-broken"}


def test_disabling_takes_a_package_off_both_lists_and_says_whether_it_was_there(workspace: Path) -> None:
    enabling.enable_plugin(load_settings(), "cyberfw-bar", allow_code=True)

    assert enabling.disable_plugin(load_settings(), "cyberfw-bar") is True
    assert _file(workspace) == plugins.PluginsFile()
    assert enabling.disable_plugin(load_settings(), "cyberfw-bar") is False


def test_disabling_a_package_that_is_gone_removes_it_from_the_file(workspace: Path) -> None:
    (workspace / "plugins.yaml").write_text("enabled: [cyberfw-gone, cyberfw-sample]\n", encoding="utf-8")

    assert enabling.disable_plugin(load_settings(), "cyberfw-gone") is True
    assert _file(workspace).enabled == {"cyberfw-sample"}


def test_a_plugins_yaml_that_cannot_be_read_is_left_as_it_is(workspace: Path) -> None:
    (workspace / "plugins.yaml").write_text("enabled: [unclosed\n", encoding="utf-8")

    with pytest.raises(PluginError, match="not valid YAML"):
        enabling.enable_plugin(load_settings(), "cyberfw-sample")
    with pytest.raises(PluginError, match="not valid YAML"):
        enabling.disable_plugin(load_settings(), "cyberfw-sample")
    assert (workspace / "plugins.yaml").read_text(encoding="utf-8") == "enabled: [unclosed\n"


def test_plugins_yaml_is_written_whole_and_reads_back(tmp_path: Path) -> None:
    where = tmp_path / "elsewhere"
    where.mkdir()
    path = where / "plugins.yaml"
    chosen = plugins.PluginsFile(enabled=frozenset({"cyberfw-foo", "123"}), allow_code=frozenset({"123"}))

    plugins.write_plugins_file(path, chosen)

    assert path.read_text(encoding="utf-8").startswith("# managed by `cyberfw plugins enable/disable`\n")
    assert yaml.safe_load(path.read_text(encoding="utf-8")) == {"enabled": ["123", "cyberfw-foo"], "allow_code": ["123"]}
    assert plugins.read_plugins_file(path) == chosen
    assert [p.name for p in where.iterdir()] == ["plugins.yaml"]  # no temp file left behind


def test_a_plugins_yaml_that_cannot_be_written_is_a_plugin_error(tmp_path: Path) -> None:
    with pytest.raises(PluginError, match="cannot be written"):
        plugins.write_plugins_file(tmp_path / "missing-dir" / "plugins.yaml", plugins.PluginsFile())
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python -m pytest tests/unit/test_plugin_commands.py -q -p no:cacheprovider
```

Expected: `ImportError: cannot import name 'plugins' from 'cyberfw.core'` and `1 error`.

- [ ] **Step 3: Write plugins.yaml whole, and enable and disable over it**

Save as `$W/task1_write.py`:

```python
"""Task 1: plugins.yaml can be written — whole or not at all.

Usage: python task1_write.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

plugins = Source(root, "cyberfw/manager/plugins.py")
plugins.replace(
    "import importlib.util\nimport re\nimport sys\n",
    "import importlib.util\nimport os\nimport re\nimport sys\n",
)
plugins.replace(
    '__all__ = ["RESERVED", "PluginInfo", "PluginSet", "PluginsFile", "State", "load_plugins", "read_plugins_file"]\n',
    "__all__ = [\n"
    '    "RESERVED",\n'
    '    "PluginInfo",\n'
    '    "PluginSet",\n'
    '    "PluginsFile",\n'
    '    "State",\n'
    '    "load_plugins",\n'
    '    "read_plugins_file",\n'
    '    "write_plugins_file",\n'
    "]\n",
)
plugins.replace(
    "    return PluginsFile(enabled=lists[\"enabled\"], allow_code=lists[\"allow_code\"])\n",
    "    return PluginsFile(enabled=lists[\"enabled\"], allow_code=lists[\"allow_code\"])\n"
    "\n"
    "\n"
    "def write_plugins_file(path: Path, chosen: PluginsFile) -> None:\n"
    '    """Write ``chosen`` to ``plugins.yaml`` at ``path`` whole or not at all — a temp\n'
    "    file, then ``os.replace``. Raises :class:`PluginError` when it cannot be written.\"\"\"\n"
    '    document = {"enabled": sorted(chosen.enabled), "allow_code": sorted(chosen.allow_code)}\n'
    '    text = "# managed by `cyberfw plugins enable/disable`\\n" + yaml.safe_dump(document, sort_keys=False)\n'
    '    tmp = path.with_name(path.name + ".tmp")\n'
    "    try:\n"
    '        tmp.write_text(text, encoding="utf-8", newline="\\n")\n'
    "        os.replace(tmp, path)\n"
    "    except OSError as exc:\n"
    "        tmp.unlink(missing_ok=True)\n"
    '        raise PluginError(f"{path}: cannot be written: {exc}") from exc\n',
)
plugins.save()
```

Create `cyberfw/core/plugins.py`:

```python
"""Enabling and disabling plugin packages — what ``cyberfw plugins enable/disable`` do.

``plugins.yaml`` is the record (CI commits it). Enabling writes a package to it and
loads it at once, so its tools' states are known before the command ends; a code
package — whose Python would run inside cyberfw — is enabled only when its code is
allowed. Running someone else's code is the user's decision, so none of this is in
the public API.
"""

from __future__ import annotations

from dataclasses import dataclass

from cyberfw.config import Settings
from cyberfw.exceptions import PluginError
from cyberfw.manager.discovery import discover, normalize
from cyberfw.manager.plugins import (
    PluginInfo,
    PluginsFile,
    load_plugins,
    read_plugins_file,
    write_plugins_file,
)

__all__ = ["CodeNotAllowed", "Enabled", "UnknownPackage", "disable_plugin", "enable_plugin"]


class UnknownPackage(PluginError):
    """No installed package by that name declares cyberfw tools."""


class CodeNotAllowed(PluginError):
    """A code package, enabled without allowing its code."""


@dataclass(frozen=True)
class Enabled:
    """What enabling a package did: its normalised name, whether it was enabled
    already, and its tools' states once loaded."""

    package: str
    already: bool
    tools: list[PluginInfo]

    @property
    def working(self) -> bool:
        """Every tool of the package loaded."""
        return all(info.state == "enabled" for info in self.tools)


def enable_plugin(settings: Settings, package: str, *, allow_code: bool = False) -> Enabled:
    """Enable ``package`` in ``settings``' ``plugins.yaml`` and load it.

    A code package needs ``allow_code``, which also writes it to ``allow_code``; for a
    manifest package the flag allows nothing (a release that starts shipping Python
    then stays ``code-not-allowed``). A package that loads broken stays enabled, so a
    fixed release works without enabling it again. Raises :class:`UnknownPackage`
    when no installed package by that name declares cyberfw tools,
    :class:`CodeNotAllowed`, or :class:`PluginError` when ``plugins.yaml`` cannot be
    read or written — and then changes nothing.
    """
    name = normalize(package)
    declared = discover()
    own = [point for point in declared if point.package == name]
    if not own:
        known = ", ".join(sorted({point.package for point in declared})) or "none is installed"
        raise UnknownPackage(f"no installed package {package!r} declares cyberfw tools (those that do: {known})")
    code = any(point.kind == "code" for point in own)
    if code and not allow_code:
        raise CodeNotAllowed(
            f"{name} ships Python that would run inside cyberfw, with access to everything cyberfw can "
            f"reach — your files, tokens and network. If you trust it: `cyberfw plugins enable {name} --allow-code`"
        )
    current = read_plugins_file(settings.plugins_file)
    wanted = PluginsFile(
        enabled=current.enabled | {name},
        allow_code=current.allow_code | ({name} if code else frozenset()),
    )
    if wanted != current:
        write_plugins_file(settings.plugins_file, wanted)
    tools = [info for info in load_plugins(settings).infos if info.package == name]
    return Enabled(package=name, already=wanted == current, tools=tools)


def disable_plugin(settings: Settings, package: str) -> bool:
    """Take ``package`` off both lists of ``plugins.yaml`` — installed or not; whether
    it was on one. Raises :class:`PluginError` when the file cannot be read or written."""
    name = normalize(package)
    current = read_plugins_file(settings.plugins_file)
    if name not in current.enabled | current.allow_code:
        return False
    write_plugins_file(
        settings.plugins_file,
        PluginsFile(enabled=current.enabled - {name}, allow_code=current.allow_code - {name}),
    )
    return True
```

```bash
uv run --quiet python "$W/task1_write.py" .
```

Expected: `edited cyberfw/manager/plugins.py`.

- [ ] **Step 4: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_plugin_commands.py tests/unit/test_plugin_loading.py tests/unit/test_core_layering.py -q -p no:cacheprovider
```

Expected: `40 passed`.

- [ ] **Step 5: The whole suite, lint, types**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1360 passed, 9 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 81 source files`.

- [ ] **Step 6: Commit** — reread `CLAUDE_HANDOFF.local.md` in the main checkout first (Global Constraints): if Codex has reserved a file of this task meanwhile, stop and ask the user. Then:

```bash
git add -- cyberfw/core/plugins.py tests/unit/test_plugin_commands.py
git commit -m "Enable and disable a plugin package: plugins.yaml written whole, a code package only with its code allowed" -- cyberfw/core/plugins.py cyberfw/manager/plugins.py tests/unit/test_plugin_commands.py
git log -1 --format=%B | grep -ci co-authored
```

Expected: `0` from the `grep`.

---

### Task 2: The `plugins` command

**Files:**
- Create: `cyberfw/cli/plugins.py`
- Modify (by script): `cyberfw/cli/__init__.py` (registers the module after `tools`), `tests/unit/test_cli_package.py` (the CLI's modules, layers and command order); tests `tests/unit/test_plugin_commands.py`

**Interfaces:**
- Consumes (Task 1): `enable_plugin`, `disable_plugin`, `Enabled`; `load_plugins`, `PluginInfo`.
- Produces: `cyberfw plugins` (a table: package, version, kind, tool, env, state, reason; a hint when nothing is installed), `cyberfw plugins enable <package> [--allow-code]` (exit 0 / 1 / 2), `cyberfw plugins disable <package>` (exit 0; 2 when `plugins.yaml` cannot be read or written).

- [ ] **Step 1: Write the failing tests**

Save as `$W/task2_tests.py`:

```python
"""Task 2, test first: the `cyberfw plugins` command — list, enable, disable.

Usage: python task2_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

TESTS = '''

# -- the plugins command ---------------------------------------------------------------------
#: A manifest tool whose recipe asks for a variable of its own.
KEYED = (
    "contract: 1\\n"
    "install: {repo: acme/keyed, asset_patterns: [], binary: keyed, env: [KEYED_TOKEN]}\\n"
    "target: ['-u', '{target}']\\n"
    "list: ['-l', '{input_file}']\\n"
    "record: {kind: http, target: url}\\n"
)


def _plugins(*args: str) -> Result:
    return base.runner.invoke(app, ["plugins", *args])


def _text(result: Result) -> str:
    """The output with Rich's line folding and padding undone."""
    return " ".join(result.stdout.split())


def _squashed(result: Result) -> str:
    """The output without any whitespace: a table cell folds mid-word on a narrow console."""
    return "".join(result.stdout.split())


def test_plugins_lists_each_tool_with_its_package_kind_env_state_and_reason(site: Path) -> None:
    install(site, "cyberfw-keyed", manifests={"keyed": "cyberfw_keyed"}, files={"cyberfw_keyed/keyed.yaml": KEYED})

    result = _plugins()

    assert result.exit_code == 0, result.stdout
    rows = {line.split()[0]: line.split() for line in result.stdout.splitlines() if line.startswith("cyberfw-")}
    assert rows["cyberfw-sample"][:6] == ["cyberfw-sample", "1.0", "manifest", "sample", "—", "disabled"]
    assert rows["cyberfw-bar"][:6] == ["cyberfw-bar", "1.0", "code", "bar", "—", "disabled"]
    # A disabled manifest's env: is read from its YAML — reading runs nothing.
    assert rows["cyberfw-keyed"][:6] == ["cyberfw-keyed", "1.0", "manifest", "keyed", "KEYED_TOKEN", "disabled"]
    assert "enableitwith`cyberfwpluginsenablecyberfw-sample`" in _squashed(result)


def test_with_no_plugin_installed_plugins_says_how_to_add_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(plugins, "discover", lambda: [])

    result = _plugins()

    assert result.exit_code == 0
    assert "`uv tool install cyberfw --with cyberfw-foo`, or `pip install cyberfw-foo`" in _text(result)


def test_enable_loads_the_package_and_shows_its_tools(workspace: Path) -> None:
    result = _plugins("enable", "cyberfw-sample")

    assert result.exit_code == 0, result.stdout
    assert _text(result).startswith("Enabled cyberfw-sample. kind tool env state reason manifest sample — enabled")
    assert _file(workspace).enabled == {"cyberfw-sample"}


def test_enabling_again_says_already_enabled_and_exits_0() -> None:
    _plugins("enable", "cyberfw-sample")

    result = _plugins("enable", "cyberfw-sample")

    assert result.exit_code == 0
    assert _text(result).startswith("cyberfw-sample: already enabled")


def test_a_code_package_without_allow_code_exits_2_and_says_what_it_would_reach(workspace: Path) -> None:
    refused = _plugins("enable", "cyberfw-bar")
    allowed = _plugins("enable", "cyberfw-bar", "--allow-code")

    assert refused.exit_code == 2
    assert "ships Python that would run inside cyberfw, with access to everything cyberfw can reach" in _text(refused)
    assert "`cyberfw plugins enable cyberfw-bar --allow-code`" in _text(refused)
    assert allowed.exit_code == 0, allowed.stdout
    assert _file(workspace).allow_code == {"cyberfw-bar"}


def test_an_unknown_package_exits_2_and_names_those_that_declare_tools() -> None:
    result = _plugins("enable", "cyberfw-nope")

    assert result.exit_code == 2
    assert "those that do: cyberfw-bar, cyberfw-sample" in _text(result)


def test_a_broken_package_exits_1_and_stays_enabled(workspace: Path, site: Path) -> None:
    install(site, "cyberfw-broken", manifests={"broken": "cyberfw_broken"}, files={"cyberfw_broken/broken.yaml": BROKEN})

    result = _plugins("enable", "cyberfw-broken")

    assert result.exit_code == 1
    assert " broken " in _text(result)
    assert _file(workspace).enabled == {"cyberfw-broken"}


def test_disable_says_what_it_did_and_can_be_repeated(workspace: Path) -> None:
    _plugins("enable", "cyberfw-sample")

    first, again = _plugins("disable", "cyberfw-sample"), _plugins("disable", "cyberfw-sample")

    assert (first.exit_code, _text(first)) == (0, "Disabled cyberfw-sample.")
    assert (again.exit_code, _text(again)) == (0, "cyberfw-sample was not enabled.")
    assert _file(workspace) == plugins.PluginsFile()


def test_a_plugins_yaml_that_cannot_be_read_exits_2(workspace: Path) -> None:
    (workspace / "plugins.yaml").write_text("enabled: [unclosed\\n", encoding="utf-8")

    for command in (("enable", "cyberfw-sample"), ("disable", "cyberfw-sample")):
        result = _plugins(*command)
        assert result.exit_code == 2
        assert "not valid YAML" in _text(result)


def test_help_lists_one_new_command_plugins_with_enable_and_disable_under_it() -> None:
    top = base.runner.invoke(app, ["--help"])
    own = _plugins("--help")

    listed = [line.strip("│| ").split()[0] for line in top.stdout.splitlines() if line.strip("│| ")[:1].isalpha()]
    assert listed.count("plugins") == 1
    assert {"enable", "disable"} <= set(_text(own).split())
'''

tests = Source(root, "tests/unit/test_plugin_commands.py")
tests.replace(
    "import pytest\nimport yaml\n\nfrom cyberfw.config import load_settings\n",
    "import pytest\nimport yaml\nfrom typer.testing import Result\n\nfrom cyberfw.cli import app\nfrom cyberfw.config import load_settings\n",
)
tests.text = tests.text.rstrip("\n") + "\n" + TESTS
tests.save()
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python "$W/task2_tests.py" .
uv run --quiet python -m pytest tests/unit/test_plugin_commands.py -q -p no:cacheprovider
```

Expected: `edited tests/unit/test_plugin_commands.py`; then `10 failed, 12 passed` — there is no `plugins` command yet (exit 2, empty output).

- [ ] **Step 3: The command, registered after the tools' commands**

Create `cyberfw/cli/plugins.py`:

```python
"""`plugins` — the plugin packages installed next to cyberfw: list them, enable or disable one."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.markup import escape
from rich.table import Table

from cyberfw.cli.app import app
from cyberfw.config import load_settings
from cyberfw.core.plugins import disable_plugin, enable_plugin
from cyberfw.exceptions import PluginError
from cyberfw.logging import console
from cyberfw.manager.plugins import PluginInfo, load_plugins

plugins_app = typer.Typer(
    help="List the plugin packages installed next to cyberfw; enable or disable one.",
    rich_markup_mode="rich",
)
app.add_typer(plugins_app, name="plugins")

#: A state's colour: what works, what waits for the user; anything else is a problem.
_STATE_STYLES = {"enabled": "ok", "disabled": "muted"}

_HOW_TO_ADD = (
    "No plugin packages are installed. Add one next to cyberfw — "
    "`uv tool install cyberfw --with cyberfw-foo`, or `pip install cyberfw-foo` in cyberfw's "
    "environment — then `cyberfw plugins enable cyberfw-foo`."
)


@plugins_app.callback(invoke_without_command=True)
def plugins_cmd(ctx: typer.Context) -> None:
    """List the plugin packages installed next to cyberfw: each tool, its kind, the
    extra variables it is given (``env:``), its state and why."""
    if ctx.invoked_subcommand is not None:
        return
    infos = load_plugins(load_settings()).infos
    if not infos:
        console.print(f"[muted]{escape(_HOW_TO_ADD)}[/muted]")
        return
    console.print(_table(infos, package=True))


@plugins_app.command("enable")
def enable_cmd(
    package: Annotated[str, typer.Argument(help="The installed package to enable, e.g. cyberfw-foo.")],
    allow_code: Annotated[bool, typer.Option(
        "--allow-code", help="Let a code package's Python run inside cyberfw, with access to all it can reach.",
    )] = False,
) -> None:
    """Enable a plugin package: write it to plugins.yaml and load it at once.

    Exit 0 when every tool of it loads (or it was enabled already); 1 when one is
    broken, incompatible or in conflict — it stays enabled, so a fixed release needs
    nothing more; 2 when no installed package by that name declares cyberfw tools,
    or a code package is enabled without --allow-code.
    """
    try:
        result = enable_plugin(load_settings(), package, allow_code=allow_code)
    except PluginError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(2) from exc
    console.print(f"{result.package}: already enabled" if result.already else f"Enabled {result.package}.")
    console.print(_table(result.tools, package=False))
    if not (result.already or result.working):
        raise typer.Exit(1)


@plugins_app.command("disable")
def disable_cmd(
    package: Annotated[str, typer.Argument(help="The package to disable, installed or not.")],
) -> None:
    """Disable a plugin package: take it off plugins.yaml, installed or not."""
    try:
        disabled = disable_plugin(load_settings(), package)
    except PluginError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        raise typer.Exit(2) from exc
    console.print(f"Disabled {escape(package)}." if disabled else f"{escape(package)} was not enabled.")


def _table(infos: list[PluginInfo], *, package: bool) -> Table:
    """Plugin tools one per row — with their package and version when ``package``. The
    names stay whole on a narrow terminal; only the reason wraps."""
    headers = [*(["package", "version"] if package else []), "kind", "tool", "env", "state", "reason"]
    table = Table.grid(padding=(0, 2))
    for header in headers:
        table.add_column(no_wrap=header != "reason", overflow="fold" if header == "reason" else "ellipsis")
    table.add_row(*(f"[muted]{header}[/muted]" for header in headers))
    for info in infos:
        style = _STATE_STYLES.get(info.state, "warn")
        cells = [escape(info.package), escape(info.version) or "—"] if package else []
        cells += [
            info.kind or "—",
            escape(info.tool) or "—",
            escape(", ".join(info.env)) or "—",
            f"[{style}]{info.state}[/{style}]",
            f"[muted]{escape(info.reason)}[/muted]",
        ]
        table.add_row(*cells)
    return table
```

Save as `$W/task2_wiring.py`:

```python
"""Task 2: register the `plugins` command module, right after the tools' commands.

Usage: python task2_wiring.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

cli = Source(root, "cyberfw/cli/__init__.py")
cli.replace(
    "for _module in ('tools', 'reports', 'triage', 'scan', 'schedule', 'launcher'):\n",
    "for _module in ('tools', 'plugins', 'reports', 'triage', 'scan', 'schedule', 'launcher'):\n",
)
cli.save()

# The package test pins the CLI's modules, their layers and the order of the commands.
package = Source(root, "tests/unit/test_cli_package.py")
package.replace(
    'LAYER = {"app": 0, "common": 1, "views": 2, "tools": 3, "reports": 3, "triage": 3, "scan": 3, "schedule": 3, "launcher": 4}\n',
    "LAYER = {\n"
    '    "app": 0, "common": 1, "views": 2,\n'
    '    "tools": 3, "plugins": 3, "reports": 3, "triage": 3, "scan": 3, "schedule": 3,\n'
    '    "launcher": 4,\n'
    "}\n",
)
package.replace(  # a command group comes after the commands
    '        "mute", "unmute", "mutes", "run", "pipeline", "schedule",\n',
    '        "mute", "unmute", "mutes", "run", "pipeline", "schedule", "plugins",\n',
)
package.save()
```

```bash
uv run --quiet python "$W/task2_wiring.py" .
```

Expected: `edited cyberfw/cli/__init__.py`, `edited tests/unit/test_cli_package.py`.

- [ ] **Step 4: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_plugin_commands.py tests/unit/test_cli_package.py -q -p no:cacheprovider
```

Expected: `27 passed`.

- [ ] **Step 5: The whole suite, lint, types**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1370 passed, 9 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 82 source files`.

- [ ] **Step 6: Commit** — reread `CLAUDE_HANDOFF.local.md` in the main checkout first (Global Constraints): if Codex has reserved a file of this task meanwhile, stop and ask the user. Then:

```bash
git add -- cyberfw/cli/plugins.py
git commit -m "cyberfw plugins lists, enables and disables plugin packages, with the spec's exit codes" -- cyberfw/cli/plugins.py cyberfw/cli/__init__.py tests/unit/test_cli_package.py tests/unit/test_plugin_commands.py
git log -1 --format=%B | grep -ci co-authored
```

Expected: `0` from the `grep`.

---

### Task 3: Where a tool comes from, in status and the launcher

**Files:**
- Modify (by script): `cyberfw/cli/views.py` (`_ToolRow.origin`, the origin column, `_plugins_line`, `_status_view(..., plugins=)`), `cyberfw/cli/tools.py` (`status` passes the plugin set); tests `tests/unit/test_plugin_commands.py`

**Interfaces:**
- Consumes (Step 3): `ToolManager.plugins: PluginSet | None`, `PluginSet.origin(tool)`, `State`.
- Produces: `_ToolRow(name, version, state, repo, origin="built-in")`; `_plugins_line(plugins) -> str`; `_status_view(rows, settings, *, chrome, plugins=None)`.

- [ ] **Step 1: Write the failing tests**

Save as `$W/task3_tests.py`:

```python
"""Task 3, test first: the tool inventory says where each tool comes from; status counts the plugins.

Usage: python task3_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

TESTS = '''

# -- where a tool comes from: status and the launcher ----------------------------------------
def _row(result: Result, tool: str) -> str:
    """The inventory row of ``tool`` without the panel's borders, whitespace squeezed."""
    (line,) = [line for line in result.stdout.splitlines() if line.strip("║│| ").split()[:1] == [tool]]
    return " ".join(line.strip("║│| ").split())


def test_status_says_where_each_tool_comes_from_and_counts_the_plugins() -> None:
    _plugins("enable", "cyberfw-sample")

    result = base.runner.invoke(app, ["status"])

    assert result.exit_code == 0, result.stdout
    assert _row(result, "sample").endswith("cyberfw-sample 1.0")
    assert _row(result, "subfinder").endswith("built-in")
    assert "plugins 1 enabled, 1 disabled" in _text(result)


def test_with_no_plugin_installed_status_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(plugins, "discover", lambda: [])

    result = base.runner.invoke(app, ["status"])

    assert "plugins none installed" in _text(result)


def test_the_launcher_offers_an_enabled_plugin_tool_and_no_other() -> None:
    def offered() -> list[str]:
        manager = open_manager(load_settings())
        try:
            return [option.name for option in launcher._menu_options(manager.registry.names())]
        finally:
            manager.close()

    before = offered()
    _plugins("enable", "cyberfw-sample")
    after = offered()

    assert "sample" not in before and "bar" not in before
    assert "sample" in after and "bar" not in after
'''

tests = Source(root, "tests/unit/test_plugin_commands.py")
tests.replace("from cyberfw.cli import app\n", "from cyberfw.cli import app, launcher\n")
tests.replace(
    "from cyberfw.core import plugins as enabling\n",
    "from cyberfw.core import plugins as enabling\nfrom cyberfw.core.workspace import open_manager\n",
)
tests.text = tests.text.rstrip("\n") + "\n" + TESTS
tests.save()
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python "$W/task3_tests.py" .
uv run --quiet python -m pytest tests/unit/test_plugin_commands.py -q -p no:cacheprovider -k "status or launcher_offers"
```

Expected: `edited tests/unit/test_plugin_commands.py`; then `2 failed, 1 passed` — no origin in the `sample` row (`AssertionError: assert False`) and no plugins line (`assert 'plugins none installed' in …`). The launcher test passes already: since Step 3 the launcher offers the registry's tools, and it guards that.

- [ ] **Step 3: The origin column and the plugins line**

Save as `$W/task3_origin.py`:

```python
"""Task 3: the tool inventory's origin column, and the plugins line in `status`.

Usage: python task3_origin.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

views = Source(root, "cyberfw/cli/views.py")
views.replace(
    "import shutil\nfrom dataclasses import dataclass\nfrom pathlib import Path\n",
    "import shutil\nfrom collections import Counter\nfrom dataclasses import dataclass\nfrom pathlib import Path\nfrom typing import get_args\n",
)
views.replace(
    "from cyberfw.manager import ToolManager\n",
    "from cyberfw.manager import ToolManager\nfrom cyberfw.manager.plugins import PluginSet, State\n",
)
views.replace(
    '    """One registered tool as the launcher and ``status`` show it."""\n'
    "\n"
    "    name: str\n"
    "    version: str\n"
    "    state: str\n"
    "    repo: str\n",
    '    """One registered tool as the launcher and ``status`` show it."""\n'
    "\n"
    "    name: str\n"
    "    version: str\n"
    "    state: str\n"
    "    repo: str\n"
    "    #: ``built-in``, or the plugin package it comes from: ``cyberfw-foo 0.3``.\n"
    '    origin: str = "built-in"\n',
)
views.replace(
    "        _ToolRow(name, _tool_version(manager, name), state, manager.spec(name).repo or \"local\")\n",
    "        _ToolRow(\n"
    "            name,\n"
    "            _tool_version(manager, name),\n"
    "            state,\n"
    '            manager.spec(name).repo or "local",\n'
    '            (manager.plugins.origin(name) if manager.plugins is not None else None) or "built-in",\n'
    "        )\n",
)
views.replace(
    '    """The tool inventory: number, tool, what it does, version, state, source.\n',
    '    """The tool inventory: number, tool, what it does, version, state, source, origin.\n',
)
views.replace(
    '    table.add_column("source", style="muted", no_wrap=True, overflow="ellipsis")\n',
    '    table.add_column("source", style="muted", no_wrap=True, overflow="ellipsis")\n'
    '    table.add_column("origin", style="muted", no_wrap=True)\n',
)
views.replace(
    "        cells += [Text(row.version or \"—\"), pip_word(row.state, state_style(row.state)), Text(row.repo)]\n",
    "        cells += [\n"
    '            Text(row.version or "—"),\n'
    "            pip_word(row.state, state_style(row.state)),\n"
    "            Text(row.repo),\n"
    "            Text(row.origin),\n"
    "        ]\n",
)
views.replace(
    "def _status_view(rows: list[_ToolRow], settings: Settings, *, chrome: str | None) -> HudFrame:\n"
    '    """``status`` as one panel: the tools (and where they are looked for), the\n'
    '    external dependencies, the effective settings."""\n',
    "def _plugins_line(plugins: PluginSet | None) -> str:\n"
    '    """``1 enabled, 2 disabled`` — the plugin tools by state; ``none installed`` without any."""\n'
    "    counts = Counter(info.state for info in (plugins.infos if plugins is not None else []))\n"
    "    if not counts:\n"
    '        return "none installed"\n'
    '    return ", ".join(f"{counts[state]} {state}" for state in get_args(State) if counts[state])\n'
    "\n"
    "\n"
    "def _status_view(\n"
    "    rows: list[_ToolRow], settings: Settings, *, chrome: str | None, plugins: PluginSet | None = None\n"
    ") -> HudFrame:\n"
    '    """``status`` as one panel: the tools (where they are looked for, and the plugins\n'
    '    by state), the external dependencies, the effective settings."""\n',
)
views.replace(
    '    tools_dir.add_row("tools dir", PathText(settings.tools_dir))\n',
    '    tools_dir.add_row("tools dir", PathText(settings.tools_dir))\n'
    '    tools_dir.add_row("plugins", Text(_plugins_line(plugins)))\n',
)
views.save()

tools = Source(root, "cyberfw/cli/tools.py")
tools.replace(
    "        console.print(_status_view(rows, settings, chrome=_find_chrome(settings.tools_dir)))\n",
    "        console.print(\n"
    "            _status_view(rows, settings, chrome=_find_chrome(settings.tools_dir), plugins=manager.plugins)\n"
    "        )\n",
)
tools.save()
```

```bash
uv run --quiet python "$W/task3_origin.py" .
```

Expected: `edited cyberfw/cli/views.py`, `edited cyberfw/cli/tools.py`.

- [ ] **Step 4: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_plugin_commands.py tests/unit/test_hud.py -q -p no:cacheprovider
```

Expected: `83 passed`.

- [ ] **Step 5: The whole suite, lint, types**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1373 passed, 9 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 82 source files`.

- [ ] **Step 6: Commit** — reread `CLAUDE_HANDOFF.local.md` in the main checkout first (Global Constraints): if Codex has reserved a file of this task meanwhile, stop and ask the user. Then:

```bash
git commit -m "The tool inventory says where each tool comes from, and status counts the plugins by state" -- cyberfw/cli/views.py cyberfw/cli/tools.py tests/unit/test_plugin_commands.py
git log -1 --format=%B | grep -ci co-authored
```

Expected: `0` from the `grep`.

---

### Task 4: report.json records each plugin tool's package

**Files:**
- Modify (by script): `cyberfw/report/run_info.py` (`RunInfo.tool_plugins`), `cyberfw/core/finish.py` (`run_info` fills it); tests `tests/unit/test_plugin_commands.py`

**Interfaces:**
- Consumes (Step 3): `PluginSet.origin(tool)`.
- Produces: `RunInfo.tool_plugins: dict[str, str]`; the `run` block's `tool_plugins` map, present only when it is not empty.

- [ ] **Step 1: Write the failing tests**

Save as `$W/task4_tests.py`:

```python
"""Task 4, test first: report.json records which plugin package each plugin tool of a run came from.

Usage: python task4_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

TESTS = '''

# -- where a run's plugin tools came from, in report.json -------------------------------------
def _run_block(workspace: Path, session: str) -> dict[str, object]:
    report = json.loads((workspace / "reports" / session / "report.json").read_text(encoding="utf-8"))
    return dict(report["run"])


def test_a_saved_run_of_a_plugin_tool_records_its_package(workspace: Path) -> None:
    _plugins("enable", "cyberfw-sample")

    result = base.runner.invoke(app, ["run", "sample", "-t", "https://sample.example.com/", "--save", "--session", "s1"])

    assert result.exit_code == 0, result.stdout
    assert _run_block(workspace, "s1")["tool_plugins"] == {"sample": "cyberfw-sample 1.0"}


def test_a_saved_pipeline_records_the_package_of_each_plugin_tool_it_ran(workspace: Path) -> None:
    (workspace / "pipelines").mkdir()
    (workspace / "pipelines" / "probe.yaml").write_text(PROBE, encoding="utf-8")
    _plugins("enable", "cyberfw-sample")

    result = base.runner.invoke(app, ["pipeline", "probe", "-t", "example.com", "--session", "p1", "--no-mail"])

    assert result.exit_code == 0, result.stdout
    assert _run_block(workspace, "p1")["tool_plugins"] == {"sample": "cyberfw-sample 1.0"}


def test_a_run_of_built_in_tools_records_no_plugins(workspace: Path) -> None:
    result = base.runner.invoke(app, ["run", "subfinder", "-t", "example.com", "--save", "--session", "s2"])

    assert result.exit_code == 0, result.stdout
    assert "tool_plugins" not in _run_block(workspace, "s2")
'''

tests = Source(root, "tests/unit/test_plugin_commands.py")
tests.replace("from __future__ import annotations\n\nfrom pathlib import Path\n", "from __future__ import annotations\n\nimport json\nfrom pathlib import Path\n")
tests.replace("from .test_plugin_tools import BAR, SAMPLE\n", "from .test_plugin_tools import BAR, PROBE, SAMPLE\n")
tests.text = tests.text.rstrip("\n") + "\n" + TESTS
tests.save()
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python "$W/task4_tests.py" .
uv run --quiet python -m pytest tests/unit/test_plugin_commands.py -q -p no:cacheprovider -k "records_its_package or records_the_package or records_no_plugins"
```

Expected: `edited tests/unit/test_plugin_commands.py`; then `2 failed, 1 passed` — two `KeyError: 'tool_plugins'`; the built-in run passes already and guards that its report stays as it is.

- [ ] **Step 3: Record the packages**

Save as `$W/task4_report.py`:

```python
"""Task 4: `tool_plugins` in report.json's run block — only for a run that used a plugin tool.

Usage: python task4_report.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

run_info = Source(root, "cyberfw/report/run_info.py")
run_info.replace(
    "    #: Installed version per tool used by the run; ``None`` when unrecorded.\n"
    "    tool_versions: dict[str, str | None] = field(default_factory=dict)\n",
    "    #: Installed version per tool used by the run; ``None`` when unrecorded.\n"
    "    tool_versions: dict[str, str | None] = field(default_factory=dict)\n"
    "    #: The plugin package each plugin tool of the run came from: ``{\"foo\": \"cyberfw-foo 0.3\"}``.\n"
    "    tool_plugins: dict[str, str] = field(default_factory=dict)\n",
)
run_info.replace(
    '    def as_dict(self, result: PipelineResult) -> dict[str, Any]:\n'
    '        """The ``run`` block of ``report.json`` (timestamps ISO-8601, UTC)."""\n'
    "        return {\n",
    '    def as_dict(self, result: PipelineResult) -> dict[str, Any]:\n'
    '        """The ``run`` block of ``report.json`` (timestamps ISO-8601, UTC). ``tool_plugins``\n'
    '        is there only for a run that used a plugin tool: reports without it read as before."""\n'
    "        return {\n",
)
run_info.replace(
    '            "tool_versions": dict(self.tool_versions),\n'
    "        }\n",
    '            "tool_versions": dict(self.tool_versions),\n'
    '            **({"tool_plugins": dict(self.tool_plugins)} if self.tool_plugins else {}),\n'
    "        }\n",
)
run_info.save()

finish = Source(root, "cyberfw/core/finish.py")
finish.replace(
    '    """The facts a report records about its run: what ran, against what, where, with which versions."""\n'
    "    return RunInfo(\n"
    "        pipeline=name,\n"
    "        seed=seed,\n"
    "        session_id=session_id,\n"
    "        platform=manager.mapping.label,\n"
    "        tool_versions={tool: (manager.install_state(tool) or {}).get(\"version\") for tool in sorted(tools)},\n"
    "    )\n",
    '    """The facts a report records about its run: what ran, against what, where, with which\n'
    '    versions — and which plugin package each plugin tool came from."""\n'
    "    plugins = manager.plugins\n"
    "    origins = {tool: plugins.origin(tool) for tool in sorted(tools)} if plugins is not None else {}\n"
    "    return RunInfo(\n"
    "        pipeline=name,\n"
    "        seed=seed,\n"
    "        session_id=session_id,\n"
    "        platform=manager.mapping.label,\n"
    "        tool_versions={tool: (manager.install_state(tool) or {}).get(\"version\") for tool in sorted(tools)},\n"
    "        tool_plugins={tool: origin for tool, origin in origins.items() if origin is not None},\n"
    "    )\n",
)
finish.save()
```

```bash
uv run --quiet python "$W/task4_report.py" .
```

Expected: `edited cyberfw/report/run_info.py`, `edited cyberfw/core/finish.py`.

- [ ] **Step 4: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_plugin_commands.py tests/unit/test_report.py tests/unit/test_core_finish.py tests/unit/test_diff.py -q -p no:cacheprovider
```

Expected: `103 passed`.

- [ ] **Step 5: The whole suite, lint, types, and the output**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1376 passed, 9 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 82 source files`.

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/4-all" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -rb "$W/transcripts/0-base" "$W/transcripts/4-all" && echo identical
```

Expected: `50 passed`, then `identical`. Two differences are not findings: an `elapsed <dur> (1m…s)` line (a loaded machine — capture again into an empty directory), and, in `pipeline-ffuf-verbose-topology`, nuclei's and ffuf's raw lines in the other order (two stages running at once — the dry run saw it). The harness has no `--help`, `status` or launcher scenario, so this step's additions to those show in the unit tests instead. Anything else is a finding.

- [ ] **Step 6: Commit** — reread `CLAUDE_HANDOFF.local.md` in the main checkout first (Global Constraints): if Codex has reserved a file of this task meanwhile, stop and ask the user. Then:

```bash
git commit -m "report.json records the plugin package each plugin tool of a run came from" -- cyberfw/report/run_info.py cyberfw/core/finish.py tests/unit/test_plugin_commands.py
git log -1 --format=%B | grep -ci co-authored
```

Expected: `0` from the `grep`.

---

### After Task 4: push, and move the main checkout

- [ ] **Step 1: Push** — reread `CLAUDE_HANDOFF.local.md` once more, then:

```bash
git log --oneline 72f744a..HEAD
git push origin HEAD:main
```

Expected: the plan's commit and the four task commits; the push lands on `main`.

- [ ] **Step 2: Move the main checkout** — in `C:/Users/DaniilSirbu/Desktop/CS-TOOL_main`:

```bash
git status --short
git fetch origin && git merge --ff-only origin/main && git status --short
```

Expected: a fast-forward; `git status` lists the same files before and after.
