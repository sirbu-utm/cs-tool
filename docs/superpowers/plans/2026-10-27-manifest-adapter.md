# Manifest Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a tool be described as data — a YAML manifest — and run by one generic adapter, so a manifest plugin never runs Python of its own inside cyberfw; prove the format by writing subfinder, httpx, naabu and nuclei as manifests.

**Architecture:** `cyberfw/tools/manifest.py` holds the format: a strict pydantic `Manifest` (with `RecordSpec` and `FindingSpec`) and `parse_manifest`, which reads the contract number first — `ContractError` for one this cyberfw does not load — and names the key for any other mistake (`ManifestError`). `cyberfw/tools/manifest_tool.py` holds the runtime: `ManifestTool` (a `BaseTool` whose command, input normalisation and parsing come from its manifest), `ManifestRecord` / `ManifestFinding` (records that keep every field of their line, their own fields mapped by the manifest), and `compile_manifest`, which makes each tool its own adapter and record subclass and returns a `ToolPlugin`. Discovery and loading are Step 3.

**Tech Stack:** Python 3.14 via `uv`, pydantic v2, PyYAML, pytest, ruff, mypy `--strict`.

**Spec:** `docs/superpowers/specs/2026-10-26-tool-plugins-design.md` — this plan is its **Step 2** ("The manifest adapter"), on top of Step 1 (`8e537a6`, `c319289`, `2e0af8f`) and the scrubbed tool environment (`5d716fc`).

Departures from the spec's text, each keeping its intent:

- **`severity:` and `tags:` join `rate:`, with `{severity}` / `{tags}` placeholders.** They are the other two fields of `ScanControls`, which is part of the contract; without them a template scanner such as nuclei could not be written as a manifest.
- **`record.target` and each finding field take a field path or a template of them** (`"{host}:{port}"`): naabu's record target is `host:port`, which no single field holds.
- **The finding mapping also takes `matched_at`** (default: the record's target) **and `remediation`** — the rest of `Finding`'s own fields.
- **Checks the spec implies but does not list:** `target` is required; a tool either runs `per_target` or takes a `list` (otherwise a pipeline stage would hand it hosts it has no way to take, and it would run with no input); a `vuln` record needs a `finding` block; each argument list passes its own placeholder, and `command` none but `{output_dir}`; unknown keys inside `install:` are mistakes too (`registry.yaml` ignores them, a manifest must not hide a typo); `name:` in `install:` is refused (a tool's name is its entry point's).
- **A line's keys never set the record's own fields** (`tool`, `line_number`, `raw`, `target`, `kind`; a finding's `template_id`, `matched_at`, `info`, `muted`). Step 1's review found that `ToolRecord.from_json` lets a line's `kind` override a finding's `"vuln"` (deferred minor M2); manifest records are built so it cannot.
- **`{output_dir}` without a session is the current directory** (`.`), as gowitness's adapter already does.
- **`ManifestError` (broken) and `ContractError` (incompatible) are new exceptions**, so Step 3 can map a manifest to its state; the contract number is read before anything else, so a newer manifest's new keys read as incompatible, not broken.
- **The two modules are internal** (`cyberfw/tools/`); the format authors write is pinned by a test, like the contract surface.
- **Step 1's "the built-in tools state their contract as a number" test looks at the nine built-in tools** rather than every module in `cyberfw/tools/`, which now also holds the manifest adapter (it passes its manifest's number).
- **subfinder as a manifest reduces upstream URLs to hosts** (`inputs: host`) where its code adapter passes them as they are — subfinder's `-dL` takes domains, so this is the better reading; the tests compare input preparation where the code adapter normalises too (naabu).

Every file, script and `Expected:` line below comes from running this plan end to end on a throwaway worktree of `main` at `5d716fc`: the suite goes 1136 → 1163 → 1194 passed; ruff and mypy `--strict` are clean after each task, and the transcripts of all 50 scenarios are identical to the baseline after each task.

## Global Constraints

- Run everything through `uv run --quiet …`. Suite: `uv run --quiet python -m pytest -q`; lint: `uv run --quiet ruff check .`; types: `uv run --quiet mypy cyberfw`. All clean at the end of every task.
- **No command changes what it does** (spec, Step 2 has no discovery yet): every command's console text, exit code and saved reports stay as they are — checked after every task with the transcript harness (50 scenarios).
- **The contract** (spec): nothing in `cyberfw.plugin` changes — `tests/unit/test_plugin_contract.py`'s pinned surface stays as it is; the manifest format gets a pin of its own.
- **The dependency rule** (Step 1): modules in `cyberfw/tools/` take the contract's names only from `cyberfw.plugin` — already checked by `test_the_built_in_tools_take_the_contract_from_cyberfw_plugin`, which covers the new modules too.
- Scratchpad: `SCRATCH=C:/Users/DANIIL~1/AppData/Local/Temp/claude/C--Users-DaniilSirbu-Desktop-CS-TOOL-main/6a8b772a-7993-414c-98b5-45500cbb762c/scratchpad`, `W="$SCRATCH/manifest-plan"`. The plan's scripts and transcripts live in `$W`, never in the repo.
- Commits: **no `Co-Authored-By` trailer** (the user's rule for this repo); stage only the task's files, never `CS-TOOL_presentation.pdf`. Push to `main` at the end (the user's standing instruction).

## Review Focus

1. A manifest written for a newer contract — with keys this cyberfw has never seen — reads as incompatible, not broken → `test_a_manifest_for_a_newer_contract_is_incompatible_not_broken` (Task 1).
2. A line whose keys share a name with the record's own fields (`kind`, `target`, `tool`, `raw`, `muted`, …) cannot change what the record is → `test_a_line_cannot_change_what_its_record_is` (Task 2).
3. A line that is not a JSON object is skipped as unparsed, never a crashed stage → `test_a_line_that_is_not_a_json_object_is_skipped_as_unparsed` (Task 2).
4. Mapped values that are not text, or are missing, render predictably — a port number as its digits, a missing field as nothing → `test_a_mapped_value_renders_as_text_and_a_missing_one_as_nothing` (Task 2).
5. In a real pipeline a manifest tool takes the seed as its target and an earlier stage's hosts through the list file the engine writes, reduced to bare hosts → `test_a_manifest_tool_takes_the_seed_and_a_previous_stage_s_hosts` (Task 2).

---

### Before Task 1: the tools and a baseline

The same two helpers as the previous plans, in a fresh `$W`: `edit.py` (checked edits: each names how often its pattern must match) and the transcript harness with its 50 scenarios.

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

Expected: `50 passed`; `1136 passed, 5 skipped, 8 deselected`; `git status` shows only `?? CS-TOOL_presentation.pdf`.

---

### Task 1: The manifest format

**Files:**
- Create: `cyberfw/tools/manifest.py`, `tests/unit/test_manifest_format.py`
- Modify (by script): `cyberfw/exceptions.py` (`ManifestError`, `ContractError`)

**Interfaces:**
- Produces, in `cyberfw/exceptions.py`: `ManifestError(CyberfwError)` — a manifest is not valid (the tool is `broken`); `ContractError(CyberfwError)` — written for a plugin contract this cyberfw does not load (`incompatible`).
- Produces, in `cyberfw/tools/manifest.py`: `PLACEHOLDER` (the `{name}` regex); `FindingSpec` (`template_id`, `matched_at`, `name`, `severity`, `description`, `remediation`: field paths or templates, all `""` by default); `RecordSpec` (`kind`, `target`, `finding: FindingSpec | None`); `Manifest` (`contract`, `install: ToolSpec`, `command`, `target`, `host_list` (YAML key `list`), `severity`, `tags`, `rate`, `per_target`, `inputs: Literal["any", "host"]`, `target_prompt`, `record: RecordSpec`); `parse_manifest(text: str, *, where: str) -> Manifest`, raising `ContractError` or `ManifestError` (messages begin `<where>: `).
- Produces, in `tests/unit/test_manifest_format.py`: `MANIFESTS: dict[str, str]` — subfinder, httpx, naabu and nuclei written as manifests (Task 2's tests use them).

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_manifest_format.py`:

```python
"""The manifest format: what a manifest plugin writes instead of Python, and how it is checked."""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from cyberfw.exceptions import ContractError, ManifestError
from cyberfw.tools.manifest import FindingSpec, Manifest, RecordSpec, parse_manifest

from .test_plugin_contract import _fields

#: Four built-in tools written as manifests — what a plugin author would write for them.
MANIFESTS = {
    "subfinder": """
contract: 1
install: {repo: projectdiscovery/subfinder, asset_patterns: ["subfinder_*_linux_amd64.zip"]}
command: ["-silent", "-json"]
target: ["-d", "{target}"]
list: ["-dL", "{input_file}"]
inputs: host
record: {kind: host, target: host}
""",
    "httpx": """
contract: 1
install: {repo: projectdiscovery/httpx, asset_patterns: ["httpx_*_linux_amd64.zip"]}
command: ["-silent", "-json", "-tls-grab"]
target: ["-u", "{target}"]
list: ["-l", "{input_file}"]
rate: ["-rate-limit", "{rate}"]
record: {kind: http, target: url}
""",
    "naabu": """
contract: 1
install: {repo: projectdiscovery/naabu, asset_patterns: ["naabu_*_linux_amd64.zip"]}
command: ["-silent", "-json"]
target: ["-host", "{target}"]
list: ["-iL", "{input_file}"]
rate: ["-rate", "{rate}"]
inputs: host
target_prompt: "Target host, IP or URL"
record: {kind: port, target: "{host}:{port}"}
""",
    "nuclei": """
contract: 1
install: {repo: projectdiscovery/nuclei, asset_patterns: ["nuclei_*_linux_amd64.zip"], env: [PDCP_API_KEY]}
command: ["-silent", "-jsonl"]
target: ["-u", "{target}"]
list: ["-l", "{input_file}"]
severity: ["-severity", "{severity}"]
tags: ["-tags", "{tags}"]
rate: ["-rate-limit", "{rate}"]
record:
  kind: vuln
  target: matched-at
  finding:
    template_id: template-id
    name: info.name
    severity: info.severity
    description: info.description
    remediation: info.remediation
""",
}

#: What contract 1's manifest format promises authors: its keys, their types and
#: defaults. A change here changes what manifests may say — decide whether the
#: contract moves (see cyberfw/plugin.py) before recording it.
FORMAT_1: dict[str, list[str]] = {
    "Manifest": [
        "contract: <class 'int'> = <required>",
        "install: <class 'cyberfw.manager.registry.ToolSpec'> = <required>",
        "command: list[str] = <factory list>",
        "target: list[str] = <required>",
        "host_list: list[str] = <factory list> (alias 'list')",
        "severity: list[str] = <factory list>",
        "tags: list[str] = <factory list>",
        "rate: list[str] = <factory list>",
        "per_target: <class 'bool'> = False",
        "inputs: typing.Literal['any', 'host'] = 'any'",
        "target_prompt: <class 'str'> = 'Target (domain, URL or host)'",
        "record: <class 'cyberfw.tools.manifest.RecordSpec'> = <required>"
    ],
    "RecordSpec": [
        "kind: <class 'str'> = <required>",
        "target: <class 'str'> = <required>",
        "finding: cyberfw.tools.manifest.FindingSpec | None = None"
    ],
    "FindingSpec": [
        "template_id: <class 'str'> = ''",
        "matched_at: <class 'str'> = ''",
        "name: <class 'str'> = ''",
        "severity: <class 'str'> = ''",
        "description: <class 'str'> = ''",
        "remediation: <class 'str'> = ''"
    ]
}


def _nuclei(**changes: Any) -> dict[str, Any]:
    """nuclei's manifest as data, with ``changes`` applied (``None`` drops a key)."""
    data: dict[str, Any] = yaml.safe_load(MANIFESTS["nuclei"])
    for key, value in changes.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    return data


def _check(data: dict[str, Any]) -> Manifest:
    return parse_manifest(yaml.safe_dump(data), where="nuclei.yaml")


@pytest.mark.parametrize("name", sorted(MANIFESTS))
def test_the_built_in_tools_can_be_written_as_manifests(name: str) -> None:
    manifest = parse_manifest(MANIFESTS[name], where=f"{name}.yaml")

    assert manifest.contract == 1 and manifest.target and manifest.host_list


def test_a_manifest_reads_as_written() -> None:
    manifest = parse_manifest(MANIFESTS["nuclei"], where="nuclei.yaml")

    assert manifest.install.repo == "projectdiscovery/nuclei" and manifest.install.env == ["PDCP_API_KEY"]
    assert (manifest.host_list, manifest.severity, manifest.inputs) == (["-l", "{input_file}"], ["-severity", "{severity}"], "any")
    assert manifest.record.finding is not None and manifest.record.finding.name == "info.name"


@pytest.mark.parametrize(
    ("data", "said"),
    [
        (_nuclei(comand=["-x"]), "comand: unknown key"),
        (_nuclei(install={"repo": "a/b", "sha256": "00"}), "install: unknown key 'sha256'"),
        (_nuclei(install={"repo": "a/b", "name": "other"}), "install: name: the tool's name is its entry point's"),
        (_nuclei(record=None), "record: Field required"),
        (_nuclei(target=None), "target: Field required"),
        (_nuclei(record={"kind": "host", "target": "host", "finding": {"name": "x"}}), "finding: only a vuln record is a finding"),
        (_nuclei(record={"kind": "vuln", "target": "matched-at"}), "finding: required for kind vuln"),
        (_nuclei(record={"kind": "Vuln!", "target": "x", "finding": {}}), "record.kind: String should match pattern"),
        (_nuclei(target=["-u", "{host}"]), "target: unknown placeholder {host} — it may use {output_dir}, {target}"),
        (_nuclei(target=["-u"]), "target: must pass {target}"),
        (_nuclei(rate=["-rate-limit", "{target}"]), "rate: unknown placeholder {target}"),
        (_nuclei(command=["-o", "{rate}"]), "command: unknown placeholder {rate} — it may use {output_dir}"),
        (_nuclei(per_target=True), "list: a per_target tool runs once per host and never takes a list"),
        (_nuclei(list=None), "list: required unless per_target is true"),
        (_nuclei(inputs="url"), "inputs: Input should be 'any' or 'host'"),
    ],
)
def test_a_mistake_in_a_manifest_is_named(data: dict[str, Any], said: str) -> None:
    with pytest.raises(ManifestError, match="^nuclei.yaml: ") as caught:
        _check(data)

    assert said in str(caught.value)


@pytest.mark.parametrize(
    ("text", "said"),
    [
        ("contract: [1", "not valid YAML"),
        ("- contract: 1\n", "a manifest is a mapping of keys"),
        ("install: {repo: a/b}\n", "contract: required"),
        ("contract: yes\n", "contract: required"),
    ],
)
def test_a_manifest_that_is_not_one_is_named(text: str, said: str) -> None:
    with pytest.raises(ManifestError, match=said):
        parse_manifest(text, where="foo.yaml")


def test_a_manifest_for_a_newer_contract_is_incompatible_not_broken() -> None:
    # Contract 2 may add keys contract 1 does not know: the version is read first.
    newer = _nuclei(contract=2, retries=3)

    with pytest.raises(ContractError, match="nuclei.yaml: written for plugin contract 2; this cyberfw loads 1"):
        _check(newer)


def test_a_per_target_tool_needs_no_list() -> None:
    manifest = _check(_nuclei(per_target=True, list=None))

    assert manifest.per_target and manifest.host_list == []


def test_the_manifest_format_is_what_contract_1_promises() -> None:
    assert {model.__name__: _fields(model) for model in (Manifest, RecordSpec, FindingSpec)} == FORMAT_1
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python -m pytest tests/unit/test_manifest_format.py -q -p no:cacheprovider
```

Expected: `ImportError: cannot import name 'ContractError' from 'cyberfw.exceptions'` and `1 error` (the file cannot even be collected).

- [ ] **Step 3: The two errors, and the format**

Save as `$W/task1_errors.py`:

```python
"""Task 1: the two ways a plugin's description can fail — broken, or written for another contract.

Usage: python task1_errors.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

exceptions = Source(root, "cyberfw/exceptions.py")
exceptions.text = exceptions.text.rstrip("\n") + '''


class ManifestError(CyberfwError):
    """A manifest plugin's manifest is not valid: the tool cannot be used (``broken``)."""


class ContractError(CyberfwError):
    """A plugin is written for a plugin contract this cyberfw does not load (``incompatible``)."""
'''
exceptions.save()
```

```bash
uv run --quiet python "$W/task1_errors.py" .
```

Expected: `edited cyberfw/exceptions.py`.

Create `cyberfw/tools/manifest.py`:

```python
"""The manifest format: a tool described as data instead of Python.

A manifest plugin ships one YAML file per tool — how to run it, and how each JSON
line it prints becomes a record — and cyberfw runs it with a generic adapter
(:mod:`cyberfw.tools.manifest_tool`), so no Python of the plugin's own ever runs
inside cyberfw. Contract 1's format::

    contract: 1
    install:                          # the same keys as an entry in registry.yaml
      repo: acme/foo
      asset_patterns: ["foo_*_linux_amd64.zip", "foo_*_windows_amd64.zip"]
      env: [FOO_API_KEY]              # extra environment variables the tool is given
    command: ["-json", "-silent"]     # always, right after the binary
    target: ["-u", "{target}"]        # a stage with one target
    list: ["-l", "{input_file}"]      # a stage given hosts (the engine writes the file)
    severity: ["-severity", "{severity}"]  # only with a severity filter set;
    tags: ["-tags", "{tags}"]              # likewise a tags filter,
    rate: ["-rate-limit", "{rate}"]        # and a rate limit
    per_target: false                 # true: one process per host, instead of a list
    inputs: any                       # any | host — host reduces URLs to bare hostnames
    target_prompt: "Target URL"       # what the launcher asks for
    record:
      kind: vuln                      # host, port, http, … — or vuln for findings
      target: matched-at              # a field path, or a template: "{host}:{port}"
      finding:                        # kind vuln only: where the finding's fields come from
        template_id: template-id
        name: info.name
        severity: info.severity
        description: info.description

The command is the binary, ``command``, the recipe's static flags, then
``severity``, ``tags`` and ``rate`` when set, then ``target`` or ``list``. Each
argument list uses its own placeholder and may use ``{output_dir}`` (the
session directory; the current one for a run without a session). A tool runs
either once per host (``per_target``) or on a ``list`` of them.
"""

from __future__ import annotations

import re
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from cyberfw.exceptions import ContractError, ManifestError
from cyberfw.plugin import SUPPORTED_CONTRACTS, BaseTool, ToolSpec

__all__ = ["FindingSpec", "Manifest", "RecordSpec", "parse_manifest"]

#: A ``{name}`` in an argument or a record template.
PLACEHOLDER = re.compile(r"\{([^{}]*)\}")

#: The placeholder each argument list fills — and must pass; ``command`` passes none.
OWN_PLACEHOLDER = {
    "command": None,
    "target": "target",
    "list": "input_file",
    "severity": "severity",
    "tags": "tags",
    "rate": "rate",
}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FindingSpec(_Strict):
    """Where a finding's own fields come from — each a field path of the line or a
    template of them; ``matched_at`` defaults to the record's target."""

    template_id: str = ""
    matched_at: str = ""
    name: str = ""
    severity: str = ""
    description: str = ""
    remediation: str = ""


class RecordSpec(_Strict):
    """How a line becomes a record: its kind, its target, and for a finding the rest."""

    kind: str = Field(pattern=r"^[a-z][a-z0-9_-]*$")
    #: A field path (``matched-at``, ``info.name``) or a template of them (``{host}:{port}``).
    target: str = Field(min_length=1)
    finding: FindingSpec | None = None

    @model_validator(mode="after")
    def _a_finding_is_a_vuln(self) -> RecordSpec:
        if self.kind == "vuln" and self.finding is None:
            raise ValueError("finding: required for kind vuln — where the finding's name and severity come from")
        if self.kind != "vuln" and self.finding is not None:
            raise ValueError(f"finding: only a vuln record is a finding, this one is {self.kind!r}")
        return self


class Manifest(_Strict):
    """One tool, as its manifest describes it (see the module docstring)."""

    contract: int
    install: ToolSpec
    command: list[str] = Field(default_factory=list)
    target: list[str] = Field(min_length=1)
    host_list: list[str] = Field(default_factory=list, alias="list")
    severity: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    rate: list[str] = Field(default_factory=list)
    per_target: bool = False
    inputs: Literal["any", "host"] = "any"
    target_prompt: str = BaseTool.target_prompt
    record: RecordSpec

    @field_validator("install", mode="before")
    @classmethod
    def _only_recipe_keys(cls, value: Any) -> Any:
        # registry.yaml tolerates unknown keys; a manifest must not hide a typo.
        if isinstance(value, dict):
            if "name" in value:
                raise ValueError("name: the tool's name is its entry point's, not the recipe's")
            unknown = sorted(set(value) - set(ToolSpec.model_fields))
            if unknown:
                raise ValueError(f"unknown key {unknown[0]!r}")
        return value

    @model_validator(mode="after")
    def _arguments_pass_their_own_placeholder(self) -> Manifest:
        for key, own in OWN_PLACEHOLDER.items():
            args: list[str] = self.host_list if key == "list" else getattr(self, key)
            used = {name for arg in args for name in PLACEHOLDER.findall(arg)}
            allowed = {"output_dir"} | ({own} if own else set())
            unknown = sorted(used - allowed)
            if unknown:
                names = ", ".join(f"{{{name}}}" for name in sorted(allowed))
                raise ValueError(f"{key}: unknown placeholder {{{unknown[0]}}} — it may use {names}")
            if args and own and own not in used:
                raise ValueError(f"{key}: must pass {{{own}}}")
        if self.per_target and self.host_list:
            raise ValueError("list: a per_target tool runs once per host and never takes a list")
        if not self.per_target and not self.host_list:
            raise ValueError("list: required unless per_target is true — how the tool takes a previous stage's hosts")
        return self


def parse_manifest(text: str, *, where: str) -> Manifest:
    """Check a manifest's YAML; ``where`` names it in messages.

    Raises :class:`ContractError` for a contract this cyberfw does not load —
    checked first, so a newer manifest's new keys never read as mistakes — and
    :class:`ManifestError` for anything else wrong, naming the key.
    """
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ManifestError(f"{where}: not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError(f"{where}: a manifest is a mapping of keys")
    contract = data.get("contract")
    if isinstance(contract, bool) or not isinstance(contract, int):
        raise ManifestError(f"{where}: contract: required — the plugin contract version it is written for, a number")
    if contract not in SUPPORTED_CONTRACTS:
        loads = ", ".join(str(version) for version in sorted(SUPPORTED_CONTRACTS))
        raise ContractError(f"{where}: written for plugin contract {contract}; this cyberfw loads {loads}")
    try:
        return Manifest.model_validate(data)
    except ValidationError as exc:
        raise ManifestError(f"{where}: {_explain(exc)}") from exc


def _explain(exc: ValidationError) -> str:
    """pydantic's errors as ``key: what is wrong``, one after another."""
    parts: list[str] = []
    for error in exc.errors():
        where = ".".join(str(part) for part in error["loc"])
        message = "unknown key" if error["type"] == "extra_forbidden" else error["msg"].removeprefix("Value error, ")
        parts.append(f"{where}: {message}" if where else message)
    return "; ".join(parts)
```

- [ ] **Step 4: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_manifest_format.py -q -p no:cacheprovider
```

Expected: `27 passed`.

- [ ] **Step 5: The whole suite, lint, types, and the output**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1163 passed, 5 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 76 source files`.

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/1-format" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -r "$W/transcripts/0-base" "$W/transcripts/1-format" && echo identical
```

Expected: `50 passed`, then `identical`. (If the only difference is an `elapsed <dur> (1m…s)` line, the machine was loaded enough for a stage to pass a minute — a format the harness does not normalise; capture again into an empty directory.)

- [ ] **Step 6: Commit**

```bash
git add cyberfw/exceptions.py cyberfw/tools/manifest.py tests/unit/test_manifest_format.py
git commit -m "Add the manifest format: a tool described as data, checked key by key"
```

---

### Task 2: The manifest adapter

**Files:**
- Create: `cyberfw/tools/manifest_tool.py`, `tests/unit/test_manifest_tool.py`
- Modify (by script): `tests/unit/test_plugin_contract.py` (the contract-number check looks at the built-in tools)

**Interfaces:**
- Consumes (Task 1): `Manifest`, `RecordSpec`, `PLACEHOLDER`, `parse_manifest` from `cyberfw/tools/manifest.py`; `MANIFESTS` from `tests/unit/test_manifest_format.py`.
- Produces, in `cyberfw/tools/manifest_tool.py`: `ManifestTool(BaseTool)` with class attributes `manifest: Manifest` and `record: type[ToolRecord]`; `ManifestRecord(ToolRecord)` and `ManifestFinding(Finding)`, each with class attribute `mapping: RecordSpec` and a `from_json` that keeps every field of the line and maps the record's own; `compile_manifest(name: str, manifest: Manifest) -> ToolPlugin` — `adapter` and `record` are subclasses made for that tool, `install` is the manifest's recipe with `name` filled in, `contract` is the manifest's.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_manifest_tool.py`:

```python
"""Manifest tools run like built-in ones — the same commands, the same records — and
nothing a tool prints can change what its record is."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from cyberfw.pipeline.engine import Node
from cyberfw.plugin import (
    BaseTool,
    Finding,
    ParseError,
    ScanControls,
    ToolContext,
    ToolPlugin,
    ToolRecord,
    ToolSpec,
)
from cyberfw.tools import adapter_for
from cyberfw.tools.manifest import parse_manifest
from cyberfw.tools.manifest_tool import ManifestTool, compile_manifest

from .test_engine import _make_engine, _stub_binary, _StubTool
from .test_manifest_format import MANIFESTS

BINARY = Path("tools_bin") / "tool"

#: What each tool prints, as the adapter and schema tests already have it.
LINES = {
    "subfinder": '{"host": "sub.example.com", "source": "crt.sh"}',
    "httpx": '{"url": "https://sub.example.com/", "status_code": 200, "title": "Home"}',
    "naabu": '{"host": "1.2.3.4", "port": 443, "protocol": "tcp"}',
    "nuclei": (
        '{"template-id": "xss", "matched-at": "https://sub.example.com/", '
        '"info": {"name": "XSS check", "severity": "medium"}}'
    ),
}

CONTEXTS = {
    "a target": ToolContext(target="https://Sub.Example.com:8443/login"),
    "a host list": ToolContext(inputs=["a.example.com", "b.example.com"], input_file=Path("stage.input")),
    "every control": ToolContext(
        target="example.com", controls=ScanControls(rate_limit=50, severity="critical,high", tags="cve")
    ),
}


def _compiled(name: str) -> ToolPlugin:
    return compile_manifest(name, parse_manifest(MANIFESTS[name], where=f"{name}.yaml"))


def _both(name: str) -> tuple[BaseTool, BaseTool]:
    """The tool's code adapter and its manifest's, on one recipe that has a static flag."""
    spec = ToolSpec(name=name, repo=f"org/{name}", asset_patterns=[], interactive_input={"-stats": ""})
    return adapter_for(spec, BINARY), _compiled(name).adapter(spec, BINARY)


def _view(record: ToolRecord) -> dict[str, object]:
    """What the rest of cyberfw reads of a record: whose line it is, its target and
    kind — and a finding's own fields."""
    fields = record.as_dict()
    return {key: fields.get(key) for key in ("tool", "line_number", "raw", "target", "kind", "template_id", "matched_at", "info")}


@pytest.mark.parametrize("context", sorted(CONTEXTS))
@pytest.mark.parametrize("name", sorted(MANIFESTS))
def test_a_manifest_builds_the_command_its_tool_s_adapter_builds(name: str, context: str) -> None:
    code, manifest = _both(name)

    assert manifest.build_cmd(CONTEXTS[context]) == code.build_cmd(CONTEXTS[context])


@pytest.mark.parametrize("name", sorted(MANIFESTS))
def test_a_manifest_reads_a_line_as_its_tool_s_adapter_does(name: str) -> None:
    code, manifest = _both(name)

    assert _view(manifest.parse_line(LINES[name], 3)) == _view(code.parse_line(LINES[name], 3))


@pytest.mark.parametrize("name", sorted(MANIFESTS))
def test_a_manifest_tool_tells_the_engine_and_the_launcher_what_its_adapter_does(name: str) -> None:
    code, manifest = _both(name)

    assert (manifest.input_flag, manifest.per_target, type(manifest).target_prompt) == (
        code.input_flag, code.per_target, type(code).target_prompt,
    )


def test_a_host_only_manifest_reduces_upstream_urls_as_naabu_s_adapter_does() -> None:
    code, manifest = _both("naabu")
    upstream = ["https://a.example.com/", "http://b.example.com:8080/x", "c.example.com"]

    assert manifest.prepare_inputs(upstream) == code.prepare_inputs(upstream) == ["a.example.com", "b.example.com", "c.example.com"]


def test_a_compiled_manifest_is_a_plugin_like_any_other() -> None:
    nuclei = _compiled("nuclei")

    assert nuclei.contract == 1 and nuclei.install is not None
    assert (nuclei.install.name, nuclei.install.repo, nuclei.install.env) == ("nuclei", "projectdiscovery/nuclei", ["PDCP_API_KEY"])
    assert issubclass(nuclei.adapter, ManifestTool) and issubclass(nuclei.record, Finding)
    assert not issubclass(_compiled("httpx").record, Finding)


def test_a_finding_from_a_manifest_reads_like_nuclei_s() -> None:
    finding = _compiled("nuclei").record.from_json("nuclei", LINES["nuclei"], 1)

    assert isinstance(finding, Finding)
    assert (finding.kind, finding.name, finding.severity) == ("vuln", "XSS check", "medium")


def test_a_record_keeps_every_field_of_its_line() -> None:
    host = _compiled("subfinder").record.from_json("subfinder", LINES["subfinder"], 1).as_dict()
    finding = _compiled("nuclei").record.from_json("nuclei", LINES["nuclei"], 1).as_dict()

    assert host["source"] == "crt.sh"
    assert (finding["template-id"], finding["matched-at"]) == ("xss", "https://sub.example.com/")


def test_a_line_cannot_change_what_its_record_is() -> None:
    line = json.dumps({
        "template-id": "x", "matched-at": "https://a.example.com/", "info": {"name": "N", "severity": "high"},
        "kind": "Pod", "target": "elsewhere", "tool": "other", "raw": "forged", "line_number": 99,
        "template_id": "forged", "muted": {"reason": "false positive"},
    })

    record = _compiled("nuclei").record.from_json("nuclei", line, 4)

    assert (record.tool, record.line_number, record.raw, record.target, record.kind) == (
        "nuclei", 4, line, "https://a.example.com/", "vuln",
    )
    assert (record.as_dict()["template_id"], record.as_dict()["muted"], record.as_dict()["info"]) == (
        "x", None, {"name": "N", "severity": "high"},
    )


@pytest.mark.parametrize("line", ["not json", "[1, 2]", "42"])
def test_a_line_that_is_not_a_json_object_is_skipped_as_unparsed(line: str) -> None:
    with pytest.raises(ParseError):
        _compiled("httpx").record.from_json("httpx", line, 1)


def test_a_mapped_value_renders_as_text_and_a_missing_one_as_nothing() -> None:
    naabu = _compiled("naabu").record
    nuclei = _compiled("nuclei").record

    assert naabu.from_json("naabu", '{"host": "10.0.0.1", "port": 8443}', 1).target == "10.0.0.1:8443"
    assert naabu.from_json("naabu", '{"host": "10.0.0.1"}', 1).target == "10.0.0.1:"
    finding = nuclei.from_json("nuclei", '{"matched-at": "https://a.example.com/", "info": {"severity": "low"}}', 1)
    assert (finding.as_dict()["template_id"], finding.as_dict()["info"]) == ("", {"severity": "low"})


def test_output_dir_is_the_session_directory_or_else_the_current_one(tmp_path: Path) -> None:
    text = MANIFESTS["httpx"].replace('command: ["-silent", "-json", "-tls-grab"]', 'command: ["-o", "{output_dir}/httpx.json"]')
    tool = compile_manifest("httpx", parse_manifest(text, where="httpx.yaml")).adapter(ToolSpec(name="httpx", repo="o/h"), BINARY)

    assert tool.build_cmd(ToolContext(target="x", output_dir=tmp_path))[1:3] == ["-o", f"{tmp_path}/httpx.json"]
    assert tool.build_cmd(ToolContext(target="x"))[1:3] == ["-o", "./httpx.json"]


async def test_a_manifest_tool_takes_the_seed_and_a_previous_stage_s_hosts(tmp_path: Path) -> None:
    # A real pipeline: the seed reaches it as its target, an earlier stage's hosts
    # through the list file the engine writes — reduced to bare hosts first.
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import json, sys\n"
        "flag, value = sys.argv[1], sys.argv[2]\n"
        "hosts = [value] if flag == '-u' else open(value, encoding='utf-8').read().split()\n"
        "for host in hosts:\n"
        "    print(json.dumps({'url': f'https://{host}/', 'status_code': 200}))\n",
        encoding="utf-8",
    )
    manifest = parse_manifest(
        "contract: 1\n"
        "install: {source: local}\n"
        f"command: [{json.dumps(probe.as_posix())}]\n"
        'target: ["-u", "{target}"]\n'
        'list: ["-l", "{input_file}"]\n'
        "inputs: host\n"
        "record: {kind: http, target: url}\n",
        where="probe.yaml",
    )
    plugin = compile_manifest("probe", manifest)
    assert plugin.install is not None
    registry_path = tmp_path / "registry.yaml"
    registry_path.write_text("subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n", encoding="utf-8")
    engine = _make_engine(tmp_path, registry_path)
    tools = {
        "subfinder": _StubTool(engine.tool_manager.spec("subfinder"), _stub_binary(tmp_path)),
        "probe": plugin.adapter(plugin.install, Path(sys.executable)),
    }
    engine.build_tool = lambda name: tools[name]  # type: ignore[method-assign]

    alone = await engine.run([Node(tool="probe", stage="live")], seed="https://seed.example.com/login")
    after = await engine.run(
        [Node(tool="subfinder", stage="subdomains"), Node(tool="probe", stage="live")], seed="sub.example.com"
    )

    assert alone.succeeded() and after.succeeded()
    assert [(record.target, record.kind) for record in alone.records] == [("https://seed.example.com/", "http")]
    assert [record.target for record in after.records if record.tool == "probe"] == ["https://sub.example.com/"]
```

and the contract-number check — Save as `$W/task2_tests.py`:

```python
"""Task 2, test first: the check that the built-in tools state their contract as a number
looks at the built-in tools themselves — not at every module in cyberfw/tools/, which
now also holds the manifest adapter (whose contract is whatever its manifest says).

Usage: python task2_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

contract = Source(root, "tests/unit/test_plugin_contract.py")
contract.replace(
    '''    written: dict[str, object] = {}
    for path in sorted((PACKAGE / "tools").glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "ToolPlugin":
                (contract,) = (keyword.value for keyword in node.keywords if keyword.arg == "contract")
                written[path.stem] = contract.value if isinstance(contract, ast.Constant) else ast.unparse(contract)

    assert written == dict.fromkeys(
        ("ffuf", "gitleaks", "gowitness", "httpx_tool", "naabu", "nmap", "nuclei", "rustscan", "subfinder"), 1
    )
''',
    '''    written: dict[str, object] = {}
    for name, tool in BUILTIN.items():
        source = Path(inspect.getfile(tool.adapter)).read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "ToolPlugin":
                (contract,) = (keyword.value for keyword in node.keywords if keyword.arg == "contract")
                written[name] = contract.value if isinstance(contract, ast.Constant) else ast.unparse(contract)

    assert written == dict.fromkeys(BUILTIN, 1)
''',
)
contract.save()
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python "$W/task2_tests.py" .
uv run --quiet python -m pytest tests/unit/test_manifest_tool.py -q -p no:cacheprovider
uv run --quiet python -m pytest tests/unit/test_plugin_contract.py -q -p no:cacheprovider
```

Expected: `edited tests/unit/test_plugin_contract.py`; then `ModuleNotFoundError: No module named 'cyberfw.tools.manifest_tool'` and `1 error`; then `13 passed` (the reworded check holds before the adapter exists, and must keep holding after).

- [ ] **Step 3: Write the adapter**

Create `cyberfw/tools/manifest_tool.py`:

```python
"""Running a manifest tool: one generic adapter and record model, made into each tool's own.

:func:`compile_manifest` turns a checked :class:`~cyberfw.tools.manifest.Manifest`
into a :class:`~cyberfw.plugin.ToolPlugin` — a subclass of :class:`ManifestTool`
and one of :class:`ManifestRecord` (or :class:`ManifestFinding`) that carry the
manifest — so from then on the registry, the lock, the engine and the reports
treat the tool like any other.

A record keeps every field of the line it comes from, so ``report.json`` and the
CSV export carry the tool's own data. Its own fields — ``tool``, ``line_number``,
``raw``, ``target``, ``kind``, and a finding's ``template_id``, ``matched_at``,
``info`` and ``muted`` — are cyberfw's: they come from the manifest's mapping,
never from a key of the line that happens to share the name.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar, cast

from pydantic import ConfigDict, ValidationError, create_model

from cyberfw.plugin import (
    BaseTool,
    Finding,
    ParseError,
    ToolContext,
    ToolPlugin,
    ToolRecord,
    ToolSpec,
)
from cyberfw.tools.manifest import PLACEHOLDER, Manifest, RecordSpec
from cyberfw.tools.targets import hostname_of

__all__ = ["ManifestFinding", "ManifestRecord", "ManifestTool", "compile_manifest"]


def _value(data: dict[str, Any], path: str) -> Any:
    """The value at a dotted field path of the line (``info.name``), or ``None``."""
    value: Any = data
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _render(spec: str, data: dict[str, Any]) -> str:
    """A field path's value as text — or, for a template, each ``{path}`` filled in;
    a field the line does not have is empty."""
    if "{" not in spec:
        value = _value(data, spec)
        return "" if value is None else str(value)
    return PLACEHOLDER.sub(lambda match: _render(match[1], data), spec)


def _mapped(mapping: RecordSpec, data: dict[str, Any]) -> dict[str, Any]:
    """The record's own fields, as the manifest maps them from the line."""
    target = _render(mapping.target, data)
    fields: dict[str, Any] = {"target": target, "kind": mapping.kind}
    finding = mapping.finding
    if finding is not None:
        info = {
            key: _render(path, data)
            for key, path in (
                ("name", finding.name),
                ("severity", finding.severity),
                ("description", finding.description),
                ("remediation", finding.remediation),
            )
            if path
        }
        fields["template_id"] = _render(finding.template_id, data) if finding.template_id else ""
        fields["matched_at"] = _render(finding.matched_at, data) if finding.matched_at else target
        fields["info"] = {key: value for key, value in info.items() if value}
    return fields


def _from_line(cls: type[ManifestRecord] | type[ManifestFinding], tool: str, text: str, lineno: int) -> ToolRecord:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError(f"[{tool}:{lineno}] invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError(f"[{tool}:{lineno}] expected a JSON object")
    theirs = {key: value for key, value in data.items() if key not in cls.model_fields}
    try:
        return cls(**theirs, **_mapped(cls.mapping, data), tool=tool, line_number=lineno, raw=text)
    except ValidationError as exc:
        raise ParseError(f"[{tool}:{lineno}] {exc}") from exc


class ManifestRecord(ToolRecord):
    """A manifest tool's record: every field of its line, ``target`` and ``kind`` as mapped."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)
    #: The manifest's ``record`` block — set on each tool's own subclass.
    mapping: ClassVar[RecordSpec]

    @classmethod
    def from_json(cls, tool: str, text: str, lineno: int) -> ToolRecord:
        return _from_line(cls, tool, text, lineno)


class ManifestFinding(Finding):
    """A manifest tool's finding: a :class:`ManifestRecord` that is a :class:`Finding`."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)
    #: The manifest's ``record`` block — set on each tool's own subclass.
    mapping: ClassVar[RecordSpec]

    @classmethod
    def from_json(cls, tool: str, text: str, lineno: int) -> ToolRecord:
        return _from_line(cls, tool, text, lineno)


def _fill(args: list[str], values: dict[str, str]) -> list[str]:
    return [PLACEHOLDER.sub(lambda match: values[match[1]], arg) for arg in args]


class ManifestTool(BaseTool):
    """The adapter of a manifest tool — each tool gets its own subclass, made by
    :func:`compile_manifest`, that carries its manifest and record model."""

    manifest: ClassVar[Manifest]
    record: ClassVar[type[ToolRecord]]

    @property
    def input_flag(self) -> str | None:
        return self.manifest.host_list[0] if self.manifest.host_list else None

    def prepare_inputs(self, inputs: list[str]) -> list[str]:
        return [hostname_of(item) for item in inputs] if self.manifest.inputs == "host" else inputs

    def build_cmd(self, ctx: ToolContext) -> list[str]:
        manifest, controls = self.manifest, ctx.controls
        values = {"output_dir": str(ctx.output_dir) if ctx.output_dir is not None else "."}
        cmd = [str(self.binary), *_fill(manifest.command, values), *self.static_flags()]
        rate = str(controls.rate_limit) if controls.rate_limit else ""
        for args, name, value in (
            (manifest.severity, "severity", controls.severity),
            (manifest.tags, "tags", controls.tags),
            (manifest.rate, "rate", rate),
        ):
            if args and value:
                cmd += _fill(args, {**values, name: value})
        if ctx.target:
            target = hostname_of(ctx.target) if manifest.inputs == "host" else ctx.target
            cmd += _fill(manifest.target, {**values, "target": target})
        elif ctx.input_file is not None and manifest.host_list:
            cmd += _fill(manifest.host_list, {**values, "input_file": str(ctx.input_file)})
        return cmd

    def parse_line(self, line: str, lineno: int) -> ToolRecord:
        return self.record.from_json(self.name, line, lineno)


def compile_manifest(name: str, manifest: Manifest) -> ToolPlugin:
    """The :class:`ToolPlugin` of the manifest tool ``name``: an adapter and a record
    model made for it, and its install recipe with its name filled in."""
    base: type[ManifestRecord] | type[ManifestFinding] = (
        ManifestFinding if manifest.record.finding is not None else ManifestRecord
    )
    record = cast("type[ManifestRecord] | type[ManifestFinding]", create_model(f"{base.__name__}_{name}", __base__=base, __module__=__name__))
    record.mapping = manifest.record
    adapter = type(
        f"ManifestTool_{name}",
        (ManifestTool,),
        {
            "__module__": __name__,
            "manifest": manifest,
            "record": record,
            "per_target": manifest.per_target,
            "target_prompt": manifest.target_prompt,
        },
    )
    install = ToolSpec.model_validate({**manifest.install.model_dump(), "name": name})
    return ToolPlugin(contract=manifest.contract, adapter=adapter, record=record, install=install)
```

- [ ] **Step 4: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_manifest_tool.py tests/unit/test_plugin_contract.py -q -p no:cacheprovider
```

Expected: `44 passed`.

- [ ] **Step 5: The whole suite, lint, types, and the output**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1194 passed, 5 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 77 source files`.

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/2-tool" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -r "$W/transcripts/0-base" "$W/transcripts/2-tool" && echo identical
```

Expected: `50 passed`, then `identical`. (If the only difference is an `elapsed <dur> (1m…s)` line, the machine was loaded enough for a stage to pass a minute — a format the harness does not normalise; capture again into an empty directory.)

- [ ] **Step 6: Commit and push**

```bash
git add cyberfw/tools/manifest_tool.py tests/unit/test_manifest_tool.py tests/unit/test_plugin_contract.py
git commit -m "Add the manifest adapter: compile a manifest into a ToolPlugin that runs like a built-in tool"
git push origin main
```
