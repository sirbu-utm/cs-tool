# Plugin Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give tool adapters one public, versioned contract — `cyberfw.plugin` — and describe cyberfw's nine built-in tools through it, exactly as a plugin will describe its own, without changing anything cyberfw does.

**Architecture:** `cyberfw/plugin.py` becomes the home of the adapter types (`BaseTool`, `ToolContext`, `ScanControls`, moved from `cyberfw/tools/base.py`) and adds the contract's own pieces: `CONTRACT`, `SUPPORTED_CONTRACTS`, the `ToolPlugin` description, and re-exports of `ToolRecord`, the new `Finding` base (the nuclei-shaped finding that `PostureFinding` now subclasses), `ToolSpec` and `ParseError`. Each built-in tool's module then describes its tool as a `ToolPlugin`, and `cyberfw.tools` builds `BUILTIN`, `ADAPTERS` and `MODELS` from those descriptions. A test pins the contract's whole surface, so a change to it is a decision, never an accident.

**Tech Stack:** Python 3.14 via `uv`, pydantic v2, pytest, ruff, mypy `--strict`.

**Spec:** `docs/superpowers/specs/2026-10-26-tool-plugins-design.md` — this plan is its **Step 1** ("The contract, without plugins"). Discovery, `plugins.yaml`, the CLI and the docs are Steps 2–4, each with its own plan.

Departures from the spec's text, each keeping its intent:

- **The adapter types live in `cyberfw/plugin.py`, and `cyberfw/tools/base.py` goes.** Re-exporting them from `cyberfw.tools.base` would be a circular import: importing the `cyberfw.tools` package runs its `__init__`, which imports the adapters, which import `cyberfw.plugin`.
- **`ParseError` joins the contract.** It is how `parse_line` / `parse_output` reject a line, which the executor then skips; a plugin needs it to do the same.
- **"The built-in adapters import only from `cyberfw.plugin`" is checked as: they take the contract's names only from `cyberfw.plugin`.** Their own record models and cyberfw's internal helpers (`hostname_of`, `default_wordlist`, the Chromium lookup, `ToolNotFoundError`) stay internal imports — the built-in tools are part of cyberfw.
- **`MODELS` moves to `cyberfw.tools`**, built from the descriptions plus `virustotal` (records cyberfw makes itself); `validate_record` imports it when called, since the tools import the schemas module. One consequence: `validate_record("nmap", …)` now validates against `NmapResult` instead of raising "no schema" — no caller does that, as nmap's XML is parsed by its adapter's `parse_output`.
- **`Finding` defaults `kind` to `"vuln"`**, so a plugin's finding need not set it; the shape `PostureFinding` is saved in does not move (a test pins its keys).
- **`cyberfw.plugin` gets the checks the core has:** no UI import in the module, and importing it leaves `cyberfw.cli` and `typer` unloaded. Rich arrives through cyberfw's logging, as it does for the core and the API.
- **Docs:** the README's structure lists `plugin.py`; the CHANGELOG entry waits for Step 2, when a plugin can first be loaded.

Every file, script and `Expected:` line below comes from running this plan end to end on a throwaway worktree of `main` at `0fb3fdd`: the suite goes 1119 → 1128 → 1130 passed; ruff and mypy `--strict` are clean after each task, and the transcripts of all 50 scenarios are identical to the baseline after each task.

## Global Constraints

- Run everything through `uv run --quiet …`. Suite: `uv run --quiet python -m pytest -q`; lint: `uv run --quiet ruff check .`; types: `uv run --quiet mypy cyberfw`. All clean at the end of every task.
- **No behaviour changes** (spec, Step 1): every command's console text, exit code and saved reports stay as they are — checked after every task with the transcript harness (50 scenarios).
- **The contract** (spec): everything in `cyberfw.plugin.__all__`, versioned by `CONTRACT` (`1`), independent of cyberfw's version; the rest of cyberfw stays internal.
- **The dependency rule** (spec): `cyberfw.plugin` loads neither the CLI, typer nor the presentation modules — `tests/unit/test_core_layering.py` checks it from Task 1 on.
- Scratchpad: `SCRATCH=C:/Users/DANIIL~1/AppData/Local/Temp/claude/C--Users-DaniilSirbu-Desktop-CS-TOOL-main/6a8b772a-7993-414c-98b5-45500cbb762c/scratchpad`, `W="$SCRATCH/plugin-plan"`. The plan's scripts and transcripts live in `$W`, never in the repo.
- Commits: **no `Co-Authored-By` trailer** (the user's rule for this repo); stage only the task's files, never `CS-TOOL_presentation.pdf`. Push to `main` at the end (the user's standing instruction).

## Review Focus

1. A plugin author's first line, `from cyberfw.plugin import …`, in a fresh interpreter — and every other order cyberfw's own code imports these types in — works without a circular import → `test_the_contract_imports_in_any_order` (Task 1), four orders, each in its own interpreter.
2. Saved runs keep their shape: cyberfw's own findings, now `Finding`s, are written with exactly the keys they had → `test_cyberfw_s_own_findings_are_findings_and_saved_as_before` (Task 1), on top of the harness's `report.json` digests.
3. A change to the contract — a renamed hook, a new required argument, a different default — fails a test rather than shipping silently → `test_the_contract_is_what_version_1_promises` (Task 1).
4. A tool written only against `cyberfw.plugin` builds its command as a built-in one does, with the now-public helpers → `test_a_tool_written_against_the_contract_builds_its_command_with_its_helpers` (Task 1), and the CLI test that registers a new adapter (`test_a_new_adapter_brings_its_own_prompt`).
5. Every record a run makes still validates against the model it did, `virustotal` included → `test_records_validate_against_the_model_each_tool_s_description_names` (Task 2).

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

Expected: `50 passed`; `1119 passed, 5 skipped, 8 deselected`; `git status` shows only `?? CS-TOOL_presentation.pdf`.

---

### Task 1: The contract module

**Files:**
- Create: `cyberfw/plugin.py`, `tests/unit/test_plugin_contract.py`
- Delete: `cyberfw/tools/base.py` (its types move to `cyberfw/plugin.py`)
- Modify (by script): `cyberfw/pipeline/schemas.py` (the `Finding` base), the nine adapters in `cyberfw/tools/` and `cyberfw/tools/__init__.py` (imports, helper names), `cyberfw/pipeline/engine.py`, `cyberfw/core/tool_run.py`; tests `tests/unit/test_core_layering.py`, `tests/unit/test_engine.py`, `tests/unit/test_tool_adapters.py`, `tests/unit/test_cli.py`, `tests/integration/test_real_tools.py` (import paths only)

**Interfaces:**
- Produces, in `cyberfw/plugin.py`: `CONTRACT = 1`; `SUPPORTED_CONTRACTS = frozenset({1})`; `BaseTool`, `ToolContext`, `ScanControls` (moved unchanged, except that `BaseTool._rate_args` / `_static_flags` / `_u` are now `rate_args` / `static_flags` / `unique`); `ToolPlugin(contract: int, adapter: type[BaseTool], record: type[ToolRecord], install: ToolSpec | None = None)`, a frozen dataclass; re-exports `Finding`, `ToolRecord`, `ToolSpec`, `ParseError`.
- Produces, in `cyberfw/pipeline/schemas.py`: `Finding(ToolRecord)` with `kind = "vuln"`, `template_id`, `matched_at`, `info`, `muted` and the `name` / `severity` properties; `PostureFinding(Finding)` keeps `make`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_plugin_contract.py`:

```python
"""cyberfw.plugin: the contract tool adapters are written against — what it holds, and that it holds still."""

from __future__ import annotations

import ast
import dataclasses
import inspect
import os
import subprocess
import sys
from pathlib import Path

import pytest

import cyberfw
from cyberfw import plugin
from cyberfw.pipeline.schemas import PostureFinding

PACKAGE = Path(cyberfw.__file__).resolve().parent

#: What contract 1 promises plugin authors. A test failing against this is a change
#: to every plugin's ground: decide whether ``plugin.CONTRACT`` moves (the module
#: docstring says when it must) before recording the new surface here.
CONTRACT_1: dict[str, object] = {
    "__all__": [
        "CONTRACT",
        "SUPPORTED_CONTRACTS",
        "BaseTool",
        "Finding",
        "ParseError",
        "ScanControls",
        "ToolContext",
        "ToolPlugin",
        "ToolRecord",
        "ToolSpec"
    ],
    "CONTRACT": 1,
    "SUPPORTED_CONTRACTS": [
        1
    ],
    "BaseTool": {
        "fields": [],
        "members": {
            "__init__": "def(self, spec: 'ToolSpec', binary: 'Path') -> 'None'",
            "buffered": "False",
            "build_cmd": "def(self, ctx: 'ToolContext') -> 'list[str]'",
            "extra_input_prompt": "None",
            "input_flag": "property",
            "missing_requirement": "classmethod(cls, tools_dir: 'Path | None' = None) -> 'str | None'",
            "name": "property",
            "parse_line": "def(self, line: 'str', lineno: 'int') -> 'ToolRecord'",
            "parse_output": "def(self, text: 'str') -> 'list[ToolRecord]'",
            "per_target": "False",
            "prepare_inputs": "def(self, inputs: 'list[str]') -> 'list[str]'",
            "rate_args": "def(self, ctx: 'ToolContext', flag: 'str' = '-rate-limit') -> 'list[str]'",
            "static_flags": "def(self) -> 'list[str]'",
            "target_prompt": "'Target (domain, URL or host)'",
            "unique": "staticmethod(inputs: 'list[str]') -> 'list[str]'",
            "validate_target": "classmethod(cls, target: 'str') -> 'None'"
        }
    },
    "ToolContext": {
        "fields": [
            "target: str | None",
            "inputs: list[str]",
            "input_file: Path | None",
            "extra_input: str | None",
            "output_dir: Path | None",
            "controls: ScanControls"
        ],
        "members": {
            "__init__": "def(self, target: 'str | None' = None, inputs: 'list[str]' = <factory>, input_file: 'Path | None' = None, extra_input: 'str | None' = None, output_dir: 'Path | None' = None, controls: 'ScanControls' = <factory>) -> None",
            "extra_input": "None",
            "input_file": "None",
            "output_dir": "None",
            "target": "None"
        }
    },
    "ScanControls": {
        "fields": [
            "rate_limit: int | None",
            "severity: str",
            "tags: str"
        ],
        "members": {
            "__init__": "def(self, rate_limit: 'int | None' = None, severity: 'str' = '', tags: 'str' = '') -> None",
            "rate_limit": "None",
            "severity": "''",
            "tags": "''"
        }
    },
    "ToolPlugin": {
        "fields": [
            "contract: int",
            "adapter: type[BaseTool]",
            "record: type[ToolRecord]",
            "install: ToolSpec | None"
        ],
        "members": {
            "__init__": "def(self, contract: 'int', adapter: 'type[BaseTool]', record: 'type[ToolRecord]', install: 'ToolSpec | None' = None) -> None",
            "install": "None"
        }
    },
    "ToolRecord": {
        "fields": [
            "tool",
            "line_number",
            "raw",
            "target",
            "kind"
        ],
        "members": {
            "as_dict": "def(self) -> 'dict[str, Any]'",
            "from_json": "classmethod(cls, tool: 'str', text: 'str', lineno: 'int') -> 'ToolRecord'"
        }
    },
    "Finding": {
        "fields": [
            "tool",
            "line_number",
            "raw",
            "target",
            "kind",
            "template_id",
            "matched_at",
            "info",
            "muted"
        ],
        "members": {
            "name": "property",
            "severity": "property"
        }
    },
    "ToolSpec": {
        "fields": [
            "name",
            "source",
            "repo",
            "asset_patterns",
            "archive",
            "binary",
            "path",
            "version",
            "check_deps",
            "interactive_input"
        ],
        "members": {
            "is_local": "property",
            "pinned_version": "property",
            "repo_name": "property",
            "repo_owner": "property"
        }
    }
}


def _members(cls: type) -> dict[str, str]:
    """``cls``'s own public members and ``__init__``: a method's signature, a property, or a value."""
    out: dict[str, str] = {}
    for name, member in sorted(vars(cls).items()):
        if (name.startswith("_") and name != "__init__") or name.startswith("model_"):
            continue
        if isinstance(member, property):
            out[name] = "property"
        elif isinstance(member, classmethod):
            out[name] = f"classmethod{inspect.signature(member.__func__)}"
        elif isinstance(member, staticmethod):
            out[name] = f"staticmethod{inspect.signature(member.__func__)}"
        elif inspect.isfunction(member):
            out[name] = f"def{inspect.signature(member)}"
        else:
            out[name] = repr(member)
    return out


def _fields(cls: type) -> list[str]:
    """A dataclass's fields with their types, a pydantic model's field names; none for a plain class."""
    if dataclasses.is_dataclass(cls):
        return [f"{item.name}: {item.type}" for item in dataclasses.fields(cls)]
    return list(getattr(cls, "model_fields", {}))


def _surface() -> dict[str, object]:
    types = ("BaseTool", "ToolContext", "ScanControls", "ToolPlugin", "ToolRecord", "Finding", "ToolSpec")
    return {
        "__all__": list(plugin.__all__),
        "CONTRACT": plugin.CONTRACT,
        "SUPPORTED_CONTRACTS": sorted(plugin.SUPPORTED_CONTRACTS),
        **{name: {"fields": _fields(getattr(plugin, name)), "members": _members(getattr(plugin, name))} for name in types},
    }


def test_the_contract_is_what_version_1_promises() -> None:
    assert _surface() == CONTRACT_1


def test_the_built_in_tools_take_the_contract_from_cyberfw_plugin() -> None:
    # The nine built-in tools use exactly what a plugin gets — never a way around it.
    offenders = []
    for path in sorted((PACKAGE / "tools").glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("cyberfw"):
                taken = {alias.name for alias in node.names} & set(plugin.__all__)
                if taken and node.module != "cyberfw.plugin":
                    offenders.append(f"{path.name}: {', '.join(sorted(taken))} from {node.module}")

    assert offenders == []


@pytest.mark.parametrize("first", ["cyberfw.plugin", "cyberfw.tools", "cyberfw.pipeline.engine", "cyberfw.pipeline.schemas"])
def test_the_contract_imports_in_any_order(first: str) -> None:
    # A plugin's first line is `from cyberfw.plugin import ...`; cyberfw's own code reaches
    # the same types through its tools, its engine and its record models.
    code = (
        f"import importlib; importlib.import_module({first!r})\n"
        "import cyberfw.plugin, cyberfw.tools\n"
        "from cyberfw.pipeline.schemas import validate_record\n"
        "print(cyberfw.tools.adapter_class('nuclei').__name__, type(validate_record('subfinder', '{}', 1)).__name__)\n"
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
    assert run.stdout.split() == ["NucleiTool", "SubfinderResult"]


def test_a_finding_is_a_vuln_shaped_like_nuclei_s() -> None:
    finding = plugin.Finding(tool="foo", template_id="foo-weak-cipher", info={"name": "Weak cipher"})

    assert (finding.kind, finding.name, finding.severity) == ("vuln", "Weak cipher", "unknown")


def test_cyberfw_s_own_findings_are_findings_and_saved_as_before() -> None:
    # Saved runs hold posture findings; their shape on disk must not move.
    found = PostureFinding.make(
        "tlscheck", "tls-expired", "https://a.example.com",
        name="Expired", severity="high", description="d", remediation="r",
    )

    assert isinstance(found, plugin.Finding)
    assert list(found.as_dict()) == [
        "tool", "line_number", "raw", "target", "kind", "template_id", "matched_at", "info", "muted",
    ]
    assert (found.kind, found.name, found.severity) == ("vuln", "Expired", "high")


class Echo(plugin.BaseTool):
    def build_cmd(self, ctx: plugin.ToolContext) -> list[str]:
        return [str(self.binary), *self.static_flags(), *self.rate_args(ctx, "-rate")]


def test_a_tool_written_against_the_contract_builds_its_command_with_its_helpers() -> None:
    spec = plugin.ToolSpec(name="echo", source="local", interactive_input={"-json": "", "-c": "5"})
    tool = Echo(spec, Path("echo"))

    assert tool.build_cmd(plugin.ToolContext(controls=plugin.ScanControls(rate_limit=20))) == [
        "echo", "-json", "-c", "5", "-rate", "20",
    ]
    assert tool.build_cmd(plugin.ToolContext()) == ["echo", "-json", "-c", "5"]
    assert plugin.BaseTool.unique(["a", "b", "a"]) == ["a", "b"]
```

and the layering checks — Save as `$W/task1_tests.py`:

```python
"""Task 1, test first: the contract module is checked like the core — no UI, imported cleanly.

Usage: python task1_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

layering = Source(root, "tests/unit/test_core_layering.py")
layering.replace(
    '"""cyberfw.core and cyberfw.api never reach for the UI:',
    '"""cyberfw.core, cyberfw.api and cyberfw.plugin never reach for the UI:',
)
layering.replace(
    "#: The core's modules, and the public API on top of them.\n"
    'CHECKED = [*sorted(CORE.glob("*.py")), PACKAGE / "api.py"]\n',
    "#: The core's modules, the public API on top of them, and the contract tool adapters\n"
    "#: are written against.\n"
    'CHECKED = [*sorted(CORE.glob("*.py")), PACKAGE / "api.py", PACKAGE / "plugin.py"]\n',
)
layering.replace('    modules.append("cyberfw.api")\n', '    modules += ["cyberfw.api", "cyberfw.plugin"]\n')
layering.save()
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python "$W/task1_tests.py" .
uv run --quiet python -m pytest tests/unit/test_plugin_contract.py -q -p no:cacheprovider
uv run --quiet python -m pytest tests/unit/test_core_layering.py -q -p no:cacheprovider
```

Expected: `edited tests/unit/test_core_layering.py`; then `ImportError: cannot import name 'plugin' from 'cyberfw'` and `1 error` (the new file cannot even be collected); then `2 failed` — `FileNotFoundError` for `cyberfw/plugin.py`, and `ModuleNotFoundError: No module named 'cyberfw.plugin'` in the subprocess.

- [ ] **Step 3: Write the contract module**

Create `cyberfw/plugin.py`:

```python
"""The contract a tool adapter is written against — cyberfw's own tools and plugins alike.

A plugin is a Python package that declares each of its tools as an entry point
in the ``cyberfw.tools`` group, pointing at a :class:`ToolPlugin`::

    [project.entry-points."cyberfw.tools"]
    foo = "cyberfw_foo:PLUGIN"

The entry point's name is the tool's name. The adapter subclasses
:class:`BaseTool`: ``build_cmd`` turns the stage's :class:`ToolContext` into the
command line, and ``parse_line`` — or ``parse_output``, for a tool that prints
one document — turns what the tool prints into records: a :class:`ToolRecord`,
or a :class:`Finding` for a problem the tool found, which the reports, SARIF,
the run comparison and triage then treat like a nuclei finding. A line that is
not the tool's output raises :class:`ParseError` and is skipped. ``install`` is
the recipe for the tool's binary — the same :class:`ToolSpec` as an entry in
``registry.yaml``.

Everything in ``__all__`` is the contract, versioned by :data:`CONTRACT` rather
than by cyberfw's own version. Adding something optional — a hook with a
default, a context field with a default — keeps the version; removing, renaming
or changing the meaning of anything bumps it, and cyberfw goes on loading the
previous version for a while (:data:`SUPPORTED_CONTRACTS`). The rest of cyberfw
is internal.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from cyberfw.exceptions import ParseError
from cyberfw.manager.registry import ToolSpec
from cyberfw.pipeline.schemas import Finding, ToolRecord, validate_record

__all__ = [
    "CONTRACT",
    "SUPPORTED_CONTRACTS",
    "BaseTool",
    "Finding",
    "ParseError",
    "ScanControls",
    "ToolContext",
    "ToolPlugin",
    "ToolRecord",
    "ToolSpec",
]

#: The contract version this cyberfw writes for.
CONTRACT = 1
#: The contract versions this cyberfw loads.
SUPPORTED_CONTRACTS = frozenset({1})


@dataclass(frozen=True)
class ScanControls:
    """Optional per-run knobs the CLI/settings pass to the tools that honour them.

    Each is off by default; an unset control adds no flag, so a command is
    unchanged from today when nothing is configured. ``rate_limit`` maps to each
    tool's own rate flag; ``severity`` / ``tags`` are nuclei's template filters.
    """

    rate_limit: int | None = None
    severity: str = ""
    tags: str = ""


@dataclass
class ToolContext:
    """Net-new, cross-stage inputs a stage runs with.

    .. attribute:: target
       The explicit ``-d`` style seed for the first stage (e.g. a domain).

    .. attribute:: inputs
       Targets passed through from the previous stage (hosts / URLs).

    .. attribute:: input_file
       Engine-materialised file with the ``inputs`` (one per line) when the
       tool accepts a host list (``-l`` / ``-iL``).

    .. attribute:: extra_input
       Optional secondary path (e.g. a fuzz wordlist) supplied by the user.

    .. attribute:: output_dir
       The session directory, for a tool that writes files of its own (gowitness
       screenshots) — so they live and die with the session's reports.
       ``None`` when the run has no session (an unsaved ``cyberfw run``).
    """

    target: str | None = None
    inputs: list[str] = field(default_factory=list)
    input_file: Path | None = None
    extra_input: str | None = None
    output_dir: Path | None = None
    #: Optional scan controls (rate limit, nuclei severity/tags); the engine
    #: fills this from settings and every stage receives it.
    controls: ScanControls = field(default_factory=ScanControls)


class BaseTool(ABC):
    """Thin adapter over one external, precompiled binary.

    Configured by its :class:`ToolSpec` (repo, archive patterns, static CLI
    flags), it supplies what cannot be derived from that: ``build_cmd`` — the
    concrete argv for a stage — and how to read the tool's output.
    """

    #: True when this tool scans one target per invocation (fan-out per input),
    #: False when it can consume the whole input list in one process.
    per_target: bool = False

    #: True for tools that emit a single JSON document (not JSONL), so the whole
    #: stdout is collected and parsed once via :meth:`parse_output` (e.g. gitleaks).
    buffered: bool = False

    #: What the launcher asks for as this tool's single target.
    target_prompt: ClassVar[str] = "Target (domain, URL or host)"

    #: Prompt for a secondary input (e.g. a wordlist); ``None`` = nothing to ask.
    extra_input_prompt: ClassVar[str | None] = None

    def __init__(self, spec: ToolSpec, binary: Path) -> None:
        self.spec: ToolSpec = spec
        self.binary: Path = binary

    @classmethod
    def missing_requirement(cls, tools_dir: Path | None = None) -> str | None:
        """Why this tool cannot run at all right now, or ``None`` when it can.

        ``tools_dir`` lets an adapter honour a dependency the framework itself
        provisions there (gowitness's portable Chromium under ``tools_bin/``).
        For something the framework cannot ship and the tool cannot work
        without — gowitness's headless Chrome. Returned as a finished,
        user-facing sentence so the pre-flight can print it before a scan and
        the adapter can raise the same words if it gets that far. A *soft*
        dependency (RustScan's Nmap, which only adds version detection) belongs
        in ``check_deps`` in registry.yaml instead: it warns, it never blocks.
        """
        return None

    @classmethod  # noqa: B027 - intentional no-op default, not an abstract method
    def validate_target(cls, target: str) -> None:
        """Reject a target this tool cannot use, with a user-facing message.

        A classmethod so the CLI can check the *kind* of target (a URL handed
        to gitleaks, say) before it even looks for the binary — a usage error,
        not a crashed process. Raises :class:`ValueError`; accepts anything by
        default.
        """

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def input_flag(self) -> str | None:
        """The ``-l`` / ``-iL``/other flag this tool uses for a host list."""
        return None

    def prepare_inputs(self, inputs: list[str]) -> list[str]:
        """Normalise upstream targets before the engine hands them to this tool.

        Called on ``ctx.inputs`` ahead of materialising the ``input_flag`` file,
        so a tool that only understands bare hosts can strip schemes/ports from
        URLs or ``host:port`` records produced by an earlier stage. Identity by
        default; the engine deduplicates afterwards.
        """
        return inputs

    @abstractmethod
    def build_cmd(self, ctx: ToolContext) -> list[str]:
        """Return the full argv (including the binary path) to run this tool."""

    def parse_line(self, line: str, lineno: int) -> ToolRecord:
        """Validate one JSONL stdout line for this tool."""
        return validate_record(self.name, line, lineno)

    def parse_output(self, text: str) -> list[ToolRecord]:
        """Parse a whole-document stdout at once (only used when ``buffered``)."""
        return []

    # -- helpers for build_cmd -------------------------------------------------
    def rate_args(self, ctx: ToolContext, flag: str = "-rate-limit") -> list[str]:
        """``[flag, N]`` when a rate limit is set, else ``[]`` — most tools spell
        the flag ``-rate-limit``; naabu/ffuf use ``-rate``."""
        limit = ctx.controls.rate_limit
        return [flag, str(limit)] if limit else []

    def static_flags(self) -> list[str]:
        """Flatten ``spec.interactive_input`` ({flag: value}) into argv args.

        A flag with an empty value is emitted alone (a switch); a flag with a
        value emits ``[flag, value]``. Order follows the YAML mapping order.
        """
        flags: list[str] = []
        for flag, value in (self.spec.interactive_input or {}).items():
            flags.append(flag)
            if value:
                flags.append(str(value))
        return flags

    @staticmethod
    def unique(inputs: list[str]) -> list[str]:
        """Deduplicate while preserving order."""
        seen: set[str] = set()
        out: list[str] = []
        for item in inputs:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out


@dataclass(frozen=True)
class ToolPlugin:
    """One tool as cyberfw sees it: what a plugin's entry point points at, and how
    cyberfw describes each of its own tools."""

    #: The contract version the tool is written for (:data:`CONTRACT`).
    contract: int
    #: How to build the command and read the output.
    adapter: type[BaseTool]
    #: The model the tool's records validate against.
    record: type[ToolRecord]
    #: The recipe for the tool's binary. Required for a plugin; cyberfw's own tools
    #: leave it ``None``, their recipe being their entry in ``registry.yaml``.
    install: ToolSpec | None = None
```

- [ ] **Step 4: Move the adapters, the engine and the tests onto it**

Save as `$W/task1_contract.py`:

```python
"""Task 1: the built-in tools, the engine and the tests take the contract from cyberfw.plugin.

Run after `git rm cyberfw/tools/base.py` (its types now live in cyberfw/plugin.py).
Usage: python task1_contract.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])
OLD = "from cyberfw.tools.base import BaseTool, ToolContext\n"
NEW = "from cyberfw.plugin import BaseTool, ToolContext\n"

# -- the record models: a Finding base, which cyberfw's own findings now are ----
schemas = Source(root, "cyberfw/pipeline/schemas.py")
schemas.replace('    "CveIntel",\n    "PostureFinding",\n', '    "CveIntel",\n    "Finding",\n    "PostureFinding",\n')
schemas.replace_span(
    "class PostureFinding(ToolRecord):\n",
    '        return str(self.info.get("severity") or "unknown")\n',
    '''class Finding(ToolRecord):
    """A problem a scan found, shaped like a nuclei finding.

    ``template_id``, ``matched_at`` and an ``info`` block with ``name`` /
    ``severity`` / ``description`` / ``remediation``: the report, SARIF, the run
    comparison and triage read every finding that way, so a record of this
    shape is treated exactly like one of nuclei's. A tool whose records are
    findings subclasses it (see :mod:`cyberfw.plugin`).
    """

    kind: str = "vuln"
    template_id: str = ""
    matched_at: str = ""
    info: dict[str, Any] = Field(default_factory=dict)
    muted: dict[str, Any] | None = None  # see NucleiResult.muted

    @property
    def name(self) -> str:
        return str(self.info.get("name") or self.template_id)

    @property
    def severity(self) -> str:
        return str(self.info.get("severity") or "unknown")


class PostureFinding(Finding):
    """A finding cyberfw works out itself (TLS certificates, email spoofing,
    subdomain takeover); ``tool`` names the check (``tlscheck`` / ``mailcheck`` /
    ``takeover``)."""
''',
)
schemas.save()

# -- the nine adapters: the contract's names from cyberfw.plugin, the helpers public
for name in ("httpx_tool", "nuclei", "subfinder", "naabu"):
    Source(root, f"cyberfw/tools/{name}.py").replace(OLD, NEW).save()
Source(root, "cyberfw/tools/ffuf.py").replace(
    "from cyberfw.resources import default_wordlist\n" + OLD,
    NEW + "from cyberfw.resources import default_wordlist\n",
).save()
Source(root, "cyberfw/tools/gowitness.py").replace(OLD, NEW).save()
Source(root, "cyberfw/tools/gitleaks.py").replace(
    "from cyberfw.exceptions import ParseError\n"
    "from cyberfw.pipeline.schemas import GitleaksResult, ToolRecord\n" + OLD,
    "from cyberfw.pipeline.schemas import GitleaksResult\n"
    "from cyberfw.plugin import BaseTool, ParseError, ToolContext, ToolRecord\n",
).save()
Source(root, "cyberfw/tools/nmap.py").replace(
    "from cyberfw.pipeline.schemas import NmapResult, ToolRecord\n" + OLD,
    "from cyberfw.pipeline.schemas import NmapResult\n"
    "from cyberfw.plugin import BaseTool, ToolContext, ToolRecord\n",
).save()
Source(root, "cyberfw/tools/rustscan.py").replace(
    "from cyberfw.exceptions import ParseError, ToolNotFoundError\n"
    "from cyberfw.pipeline.schemas import RustscanResult\n" + OLD,
    "from cyberfw.exceptions import ToolNotFoundError\n"
    "from cyberfw.pipeline.schemas import RustscanResult\n"
    "from cyberfw.plugin import BaseTool, ParseError, ToolContext\n",
).save()
Source(root, "cyberfw/tools/__init__.py").replace(
    "from cyberfw.manager.registry import ToolSpec\nfrom cyberfw.tools.base import BaseTool\n",
    "from cyberfw.plugin import BaseTool, ToolSpec\n",
).save()

RATE = {"ffuf": 1, "httpx_tool": 1, "naabu": 1, "nuclei": 1}
for name in ("ffuf", "gitleaks", "gowitness", "httpx_tool", "naabu", "nmap", "nuclei", "rustscan", "subfinder"):
    adapter = Source(root, f"cyberfw/tools/{name}.py")
    adapter.sub(r"self\._static_flags\(", "self.static_flags(", count=1)
    adapter.sub(r"self\._rate_args\(", "self.rate_args(", count=RATE.get(name, 0))
    adapter.save()

# -- the engine and the one-tool run --------------------------------------------
Source(root, "cyberfw/pipeline/engine.py").replace(
    "from cyberfw.tools.base import BaseTool, ScanControls, ToolContext\n",
    "from cyberfw.plugin import BaseTool, ScanControls, ToolContext\n",
).save()
Source(root, "cyberfw/core/tool_run.py").replace(
    "from cyberfw.tools import adapter_class\nfrom cyberfw.tools.base import ToolContext\n",
    "from cyberfw.plugin import ToolContext\nfrom cyberfw.tools import adapter_class\n",
).save()

# -- tests: only their import paths change ----------------------------------------
Source(root, "tests/unit/test_engine.py").replace(OLD, NEW).save()
Source(root, "tests/unit/test_tool_adapters.py").replace(
    "from cyberfw.tools import adapter_for\nfrom cyberfw.tools.base import ScanControls, ToolContext\n",
    "from cyberfw.plugin import ScanControls, ToolContext\nfrom cyberfw.tools import adapter_for\n",
).save()
Source(root, "tests/integration/test_real_tools.py").replace(
    "from cyberfw.tools import adapter_for\n" + OLD,
    NEW + "from cyberfw.tools import adapter_for\n",
).save()
Source(root, "tests/unit/test_cli.py").replace(
    "        from cyberfw.tools import ADAPTERS\n        from cyberfw.tools.base import BaseTool\n",
    "        from cyberfw.plugin import BaseTool\n        from cyberfw.tools import ADAPTERS\n",
).save()
```

```bash
git rm -q cyberfw/tools/base.py
uv run --quiet python "$W/task1_contract.py" .
```

Expected: `edited` lines for `cyberfw/pipeline/schemas.py`, each of the nine adapters (twice: imports, then helper names) and `cyberfw/tools/__init__.py`, `cyberfw/pipeline/engine.py`, `cyberfw/core/tool_run.py`, and the four test files — and no `expected … found` line.

- [ ] **Step 5: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_plugin_contract.py tests/unit/test_core_layering.py -q -p no:cacheprovider
```

Expected: `11 passed`.

- [ ] **Step 6: The whole suite, lint, types, and the output**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1128 passed, 5 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 75 source files`.

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/1-contract" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -r "$W/transcripts/0-base" "$W/transcripts/1-contract" && echo identical
```

Expected: `50 passed`, then `identical`.

- [ ] **Step 7: Commit**

```bash
git add cyberfw/plugin.py cyberfw/tools cyberfw/pipeline/engine.py cyberfw/pipeline/schemas.py cyberfw/core/tool_run.py tests/unit/test_plugin_contract.py tests/unit/test_core_layering.py tests/unit/test_engine.py tests/unit/test_tool_adapters.py tests/unit/test_cli.py tests/integration/test_real_tools.py
git commit -m "Add cyberfw.plugin: the contract tool adapters are written against"
```

---

### Task 2: The built-in tools, described as plugins

**Files:**
- Replace: `cyberfw/tools/__init__.py`
- Modify (by script): the nine adapters in `cyberfw/tools/` (a `PLUGIN` each), `cyberfw/pipeline/schemas.py` (`MODELS` leaves; `validate_record` uses `cyberfw.tools.MODELS`), `README.md` (structure); `tests/unit/test_plugin_contract.py`

**Interfaces:**
- Consumes (Task 1): `CONTRACT`, `ToolPlugin`, `ToolRecord` from `cyberfw.plugin`.
- Produces: in each built-in adapter module, `PLUGIN = ToolPlugin(contract=CONTRACT, adapter=<Tool>, record=<Result>)`; in `cyberfw/tools/__init__.py`, `BUILTIN: dict[str, ToolPlugin]` (registry name → description), `ADAPTERS: dict[str, type[BaseTool]]` and `MODELS: dict[str, type[ToolRecord]]` built from it (`MODELS` also maps `virustotal`); `adapter_class` / `adapter_for` unchanged.

- [ ] **Step 1: Write the failing tests**

Save as `$W/task2_tests.py`:

```python
"""Task 2, test first: each built-in tool is described as a ToolPlugin, and the maps come from those.

Usage: python task2_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

TESTS = '''

def test_every_built_in_tool_is_described_the_way_a_plugin_describes_its_own() -> None:
    registry = load_registry(PACKAGE.parent / "registry.yaml")

    assert sorted(BUILTIN) == registry.names()
    for name, tool in BUILTIN.items():
        assert isinstance(tool, plugin.ToolPlugin) and tool.contract == plugin.CONTRACT, name
        assert issubclass(tool.adapter, plugin.BaseTool) and issubclass(tool.record, plugin.ToolRecord), name
        assert tool.install is None, f"{name}'s recipe is its registry.yaml entry"
    assert ADAPTERS == {name: tool.adapter for name, tool in BUILTIN.items()}


def test_records_validate_against_the_model_each_tool_s_description_names() -> None:
    assert {name: model.__name__ for name, model in MODELS.items()} == {
        "subfinder": "SubfinderResult",
        "naabu": "NaabuResult",
        "nmap": "NmapResult",
        "rustscan": "RustscanResult",
        "httpx": "HttpxResult",
        "ffuf": "FfufResult",
        "nuclei": "NucleiResult",
        "gitleaks": "GitleaksResult",
        "gowitness": "GowitnessResult",
        "virustotal": "VirusTotalResult",
    }
    assert all(MODELS[name] is tool.record for name, tool in BUILTIN.items())
'''

contract = Source(root, "tests/unit/test_plugin_contract.py")
contract.replace(
    "from cyberfw import plugin\nfrom cyberfw.pipeline.schemas import PostureFinding\n",
    "from cyberfw import plugin\n"
    "from cyberfw.manager.registry import load_registry\n"
    "from cyberfw.pipeline.schemas import PostureFinding\n"
    "from cyberfw.tools import ADAPTERS, BUILTIN, MODELS\n",
)
contract.text = contract.text.rstrip("\n") + "\n" + TESTS
contract.save()
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python "$W/task2_tests.py" .
uv run --quiet python -m pytest tests/unit/test_plugin_contract.py -q -p no:cacheprovider
```

Expected: `edited tests/unit/test_plugin_contract.py`; then `ImportError: cannot import name 'BUILTIN' from 'cyberfw.tools'` and `1 error`.

- [ ] **Step 3: Build the maps from the descriptions**

Replace the whole of `cyberfw/tools/__init__.py` with:

```python
"""The tools cyberfw ships, and the lookups the rest of the framework uses.

Each built-in tool's module describes it as a :class:`~cyberfw.plugin.ToolPlugin`
— its adapter and its record model — exactly as a plugin describes its own
tools; its install recipe is its entry in ``registry.yaml``. Every map from a
tool's name to its code is built from these descriptions, which makes them the
only place the framework couples the two.
"""

from __future__ import annotations

from pathlib import Path

from cyberfw.exceptions import RegistryError
from cyberfw.pipeline.schemas import VirusTotalResult
from cyberfw.plugin import BaseTool, ToolPlugin, ToolRecord, ToolSpec
from cyberfw.tools import (
    ffuf,
    gitleaks,
    gowitness,
    httpx_tool,
    naabu,
    nmap,
    nuclei,
    rustscan,
    subfinder,
)

__all__ = ["ADAPTERS", "BUILTIN", "MODELS", "adapter_class", "adapter_for"]

#: The built-in tools, by registry name.
BUILTIN: dict[str, ToolPlugin] = {
    "subfinder": subfinder.PLUGIN,
    "naabu": naabu.PLUGIN,
    "nmap": nmap.PLUGIN,
    "rustscan": rustscan.PLUGIN,
    "httpx": httpx_tool.PLUGIN,
    "ffuf": ffuf.PLUGIN,
    "nuclei": nuclei.PLUGIN,
    "gitleaks": gitleaks.PLUGIN,
    "gowitness": gowitness.PLUGIN,
}

#: Tool name → adapter class.
ADAPTERS: dict[str, type[BaseTool]] = {name: tool.adapter for name, tool in BUILTIN.items()}

#: Name → the model its records validate against: each tool's, and that of the
#: reputation records cyberfw makes itself (VirusTotal).
MODELS: dict[str, type[ToolRecord]] = {
    **{name: tool.record for name, tool in BUILTIN.items()},
    "virustotal": VirusTotalResult,
}


def adapter_class(name: str) -> type[BaseTool]:
    """Return the adapter class for tool ``name`` (no binary needed).

    Lets the CLI use class-level knowledge — prompts, target validation —
    before the tool is installed.
    """
    cls = ADAPTERS.get(name)
    if cls is None:
        raise RegistryError(f"no adapter registered for tool {name!r}")
    return cls


def adapter_for(spec: ToolSpec, binary: Path) -> BaseTool:
    """Instantiate the adapter for ``spec``, given its installed binary path."""
    return adapter_class(spec.name)(spec, binary)
```

- [ ] **Step 4: Describe each tool**

Save as `$W/task2_builtins.py`:

```python
"""Task 2: each built-in tool's module describes it as a ToolPlugin; records validate from those.

Run after `cyberfw/tools/__init__.py` is replaced (it builds BUILTIN, ADAPTERS and MODELS).
Usage: python task2_builtins.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])
PLAIN = "from cyberfw.plugin import BaseTool, ToolContext\n"
DESCRIBED = "from cyberfw.plugin import CONTRACT, BaseTool, ToolContext, ToolPlugin\n"

#: module → (adapter class, record model, the plugin import before → after)
TOOLS = {
    "subfinder": ("SubfinderTool", "SubfinderResult", PLAIN, "from cyberfw.pipeline.schemas import SubfinderResult\n" + DESCRIBED),
    "naabu": ("NaabuTool", "NaabuResult", PLAIN, "from cyberfw.pipeline.schemas import NaabuResult\n" + DESCRIBED),
    "nmap": (
        "NmapTool", "NmapResult",
        "from cyberfw.plugin import BaseTool, ToolContext, ToolRecord\n",
        "from cyberfw.plugin import CONTRACT, BaseTool, ToolContext, ToolPlugin, ToolRecord\n",
    ),
    "rustscan": (
        "RustscanTool", "RustscanResult",
        "from cyberfw.plugin import BaseTool, ParseError, ToolContext\n",
        "from cyberfw.plugin import CONTRACT, BaseTool, ParseError, ToolContext, ToolPlugin\n",
    ),
    "httpx_tool": ("HttpxTool", "HttpxResult", PLAIN, "from cyberfw.pipeline.schemas import HttpxResult\n" + DESCRIBED),
    "ffuf": ("FfufTool", "FfufResult", PLAIN, "from cyberfw.pipeline.schemas import FfufResult\n" + DESCRIBED),
    "nuclei": ("NucleiTool", "NucleiResult", PLAIN, "from cyberfw.pipeline.schemas import NucleiResult\n" + DESCRIBED),
    "gitleaks": (
        "GitleaksTool", "GitleaksResult",
        "from cyberfw.plugin import BaseTool, ParseError, ToolContext, ToolRecord\n",
        "from cyberfw.plugin import CONTRACT, BaseTool, ParseError, ToolContext, ToolPlugin, ToolRecord\n",
    ),
    "gowitness": ("GowitnessTool", "GowitnessResult", PLAIN, "from cyberfw.pipeline.schemas import GowitnessResult\n" + DESCRIBED),
}

for module, (adapter, record, before, after) in TOOLS.items():
    tool = Source(root, f"cyberfw/tools/{module}.py")
    tool.replace(before, after)
    tool.text = tool.text.rstrip("\n") + f"\n\n\nPLUGIN = ToolPlugin(contract=CONTRACT, adapter={adapter}, record={record})\n"
    tool.save()

schemas = Source(root, "cyberfw/pipeline/schemas.py")
schemas.replace_span(
    "#: Dispatch map — registry name → validating model.\n",
    "    model = MODELS.get(tool)\n",
    '''def validate_record(tool: str, line: str, lineno: int) -> ToolRecord:
    """Validate one raw JSONL line for ``tool``, with the record model its
    description names (:data:`cyberfw.tools.MODELS`).

    Raises :class:`ParseError` for malformed or unknown-tool input.
    """
    from cyberfw.tools import MODELS  # the tools import this module, so not at its top

    model = MODELS.get(tool)
''',
)
schemas.save()

readme = Source(root, "README.md")
readme.replace(
    "  tools/                 адаптеры девяти внешних инструментов (вкл. локальный nmap)\n",
    "  plugin.py              контракт адаптера инструмента: по нему описаны встроенные инструменты\n"
    "                         и пишутся плагины (стабилен в пределах своей версии)\n"
    "  tools/                 адаптеры девяти внешних инструментов (вкл. локальный nmap)\n",
)
readme.save()
```

```bash
uv run --quiet python "$W/task2_builtins.py" .
```

Expected: `edited` lines for the nine adapters, `cyberfw/pipeline/schemas.py` and `README.md`.

- [ ] **Step 5: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_plugin_contract.py -q -p no:cacheprovider
```

Expected: `11 passed`.

- [ ] **Step 6: The whole suite, lint, types, and the output**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1130 passed, 5 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 75 source files`.

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/2-builtins" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -r "$W/transcripts/0-base" "$W/transcripts/2-builtins" && echo identical
```

Expected: `50 passed`, then `identical`.

- [ ] **Step 7: Commit and push**

```bash
git add cyberfw/tools cyberfw/pipeline/schemas.py tests/unit/test_plugin_contract.py README.md
git commit -m "Describe the built-in tools as ToolPlugins; build ADAPTERS and MODELS from them"
git push origin main
```
