# Plugin Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Find the plugin packages installed next to cyberfw from their metadata alone, load the ones `plugins.yaml` enables — manifests by reading them, code only where allowed — and make their tools usable wherever cyberfw looks a tool up, without a plugin ever breaking cyberfw.

**Architecture:** `cyberfw/manager/discovery.py` reads the `cyberfw.manifests` and `cyberfw.tools` entry points of the installed distributions and verifies each package's kind from the files it recorded — nothing is imported. `cyberfw/manager/plugins.py` reads `plugins.yaml`, gives every declared tool its state (`enabled`, `disabled`, `code-not-allowed`, `conflict`, `incompatible`, `broken`, `missing`) and loads the enabled ones into a `PluginSet`. `open_manager` lays the loaded tools' recipes under `registry.yaml`'s entries and hands the set to `ToolManager`, which now carries the tools in use: the engine, a single run, pipelines and the launcher look adapters up there, a tool reads its lines with its own record model, and a tool that is not available says why. First, the executor stops letting a line its parser cannot take fail a stage — what the spec relies on before any plugin runs.

**Tech Stack:** Python 3.14 via `uv`, `importlib.metadata`, pydantic v2, PyYAML, pytest, ruff, mypy `--strict`.

**Spec:** `docs/superpowers/specs/2026-10-26-tool-plugins-design.md` — this plan is its **Step 3** ("Discovery and states"), on top of Steps 1–2 (`8e537a6`…`7680019`). The `plugins` commands, the origin column and `tool_plugins` in `report.json` are Step 4; the docs are Step 5.

Departures from the spec's text, each keeping its intent:

- **Task 1 comes first: a line its parser cannot take — whatever it raises — is dropped and counted, never the stage.** The spec's Errors section counts on it ("exactly as for a built-in tool"), and Step 1's review found built-in tools fail a whole stage on one wrong-typed value; it is fixed for them too, with a CHANGELOG line.
- **Discovery and loading live in `cyberfw/manager/`** (`discovery.py`, `plugins.py`), which `cyberfw/manager/__init__.py` does not import (it would import `cyberfw.plugin`, which imports the manager's registry module); `open_manager` wires them.
- **`PluginError` arrives now**, for reading `plugins.yaml`: one that cannot be read enables nothing and says so once — the rest of cyberfw keeps working. **`ContractError` gains `.contract`** (Step 2's review, minor M8), so a manifest's and a code plugin's incompatibility read the same.
- **Warnings only for packages the user enabled** (and missing ones). A package nobody enabled that conflicts or breaks stays quiet — a warning on every run about a package never chosen is noise; it still shows in `api.list_plugins`.
- **A manifest tool's `env:` is read from its YAML even while disabled** (reading runs nothing), so a plugin asking for a secret is visible before it is enabled; a code tool's `env:` is known once it loads.
- **A `registry.yaml` entry for a plugin tool not in use is left out** rather than parsed: it is often a partial overlay (`version:` alone) that is no recipe by itself and would break the whole registry; using the tool gives its reason instead.
- **A package declaring one tool both as a manifest and as code is `broken`**, reported once.
- **The tool set lives on `ToolManager`** (`tools`, `adapter_class`, `adapter_for`, `unavailable`); the module-level `ADAPTERS`, `MODELS`, `adapter_class` and `adapter_for` stay the built-in tools'. Each adapter gets its record model per instance (Step 1 review's recommendation) through `BaseTool._record`, set by `ToolManager.adapter_for` — private, so the pinned contract does not move.
- **The CLI test that registers a new tool** (`test_a_new_adapter_brings_its_own_prompt`) registers a `ToolPlugin` in `BUILTIN`, since lookups now go through the manager.
- **Loading is cached per process keyed on `plugins.yaml`'s path and bytes and `sys.path`**, so a changed file or newly installed package is seen.

Every file, script and `Expected:` line below comes from running this plan on a throwaway worktree of `main` at `7680019`: the suite goes 1196 → 1198 → 1207 → 1230 → 1237 passed; ruff and mypy `--strict` are clean after each task, and the transcripts of all 50 scenarios are identical to the baseline after each task.

## Global Constraints

- Run everything through `uv run --quiet …`. Suite: `uv run --quiet python -m pytest -q`; lint: `uv run --quiet ruff check .`; types: `uv run --quiet mypy cyberfw`. All clean at the end of every task.
- **Built-in tools behave as before** — every command's console text, exit code and saved reports stay as they are, checked after every task with the transcript harness (50 scenarios) — except the one fix of Task 1.
- **A plugin never breaks cyberfw** (spec): any problem with one puts only its tools in their state; built-in tools and other plugins keep working.
- **Nothing of a package runs unless it is enabled — and, for code, allowed** (spec): discovery reads metadata only.
- **The contract** (spec): nothing in `cyberfw.plugin.__all__` changes; `tests/unit/test_plugin_contract.py`'s pinned surface stays as it is.
- Scratchpad: `SCRATCH=C:/Users/DANIIL~1/AppData/Local/Temp/claude/C--Users-DaniilSirbu-Desktop-CS-TOOL-main/6a8b772a-7993-414c-98b5-45500cbb762c/scratchpad`, `W="$SCRATCH/discovery-plan"`. The plan's scripts and transcripts live in `$W`, never in the repo.
- Commits: **no `Co-Authored-By` trailer** (the user's rule for this repo); stage only the task's files, never `CS-TOOL_presentation.pdf`. Push to `main` at the end (the user's standing instruction).

## Review Focus

1. A package that is not enabled — or ships code without `allow_code` — never runs: finding it, listing it and running other tools import nothing of it → `test_finding_a_package_runs_none_of_its_code` (Task 2), `test_a_code_package_runs_only_when_allowed_to` and `test_a_manifest_package_that_starts_shipping_python_is_not_loaded` (Task 3).
2. A plugin problem never breaks cyberfw — an unreadable `plugins.yaml`, a broken, conflicting or incompatible package, a partial `registry.yaml` entry for a plugin not in use → `test_an_unreadable_plugins_yaml_enables_nothing_and_says_so` (Task 3), `test_an_entry_for_a_plugin_not_in_use_leaves_the_registry_working` (Task 4).
3. No plugin takes a built-in or a reserved name, and two packages cannot share one → `test_a_plugin_cannot_take_a_name_cyberfw_uses`, `test_two_packages_declaring_one_name_both_lose_it` (Task 3).
4. Using a plugin tool that is not available says why and what to do, in the same words for a run and a pipeline → `test_a_plugin_tool_not_in_use_says_why_and_what_to_do` (Task 4).
5. Disabling a plugin never silently re-pins its binary → `test_the_lock_keeps_a_disabled_plugin_tool_s_pin` (Task 4).

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

Expected: `50 passed`; `1196 passed, 5 skipped, 8 deselected`; `git status` shows only `?? CS-TOOL_presentation.pdf`.

---

### Task 1: A line its parser cannot take costs that line, never the stage

**Files:**
- Modify (by script): `cyberfw/pipeline/executor.py`, `CHANGELOG.md`; tests `tests/unit/test_executor.py`

**Interfaces:**
- Produces: `run_stage` drops any line whose parser raises — not only `ParseError` — and counts it in the "did not match the expected schema" summary.

- [ ] **Step 1: Write the failing tests**

Save as `$W/task1_tests.py`:

```python
"""Task 1, test first: a line a tool's parser cannot take costs that line, never the stage.

Usage: python task1_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

TESTS = '''

class TestALineAParserCannotTake:
    """A plugin's parser may raise anything on an odd line, a built-in schema a
    ValidationError: either way that line is dropped and counted, the stage goes on."""

    async def test_any_exception_costs_the_line_not_the_stage(self, tmp_path: Path) -> None:
        script = _write_script(tmp_path, "for line in ('good', 'wrong type', 'too deep', 'good'):\\n    print(line)\\n")

        def parse(line: str, lineno: int) -> ToolRecord:
            if line == "wrong type":
                raise TypeError("an int where a str was due")
            if line == "too deep":
                raise RecursionError("maximum recursion depth exceeded")
            return ToolRecord(tool="plug", line_number=lineno, raw=line, target=line)

        records = await run_stage([sys.executable, str(script)], tool="plug", stage="s", context=None, parse_line=parse)

        assert [record.line_number for record in records] == [1, 4]

    async def test_a_line_a_built_in_schema_refuses_is_dropped(self, tmp_path: Path) -> None:
        script = _write_script(
            tmp_path,
            "import json\\n"
            "print(json.dumps({'host': 'a.example.com', 'port': 'abc'}))\\n"
            "print(json.dumps({'host': 'b.example.com', 'port': 443}))\\n",
        )

        records = await run_stage([sys.executable, str(script)], tool="naabu", stage="ports", context=None)

        assert [record.target for record in records] == ["b.example.com:443"]
'''

tests = Source(root, "tests/unit/test_executor.py")
tests.text = tests.text.rstrip("\n") + "\n" + TESTS
tests.save()
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python "$W/task1_tests.py" .
uv run --quiet python -m pytest "tests/unit/test_executor.py::TestALineAParserCannotTake" -q -p no:cacheprovider
```

Expected: `edited tests/unit/test_executor.py`; then `2 failed` — `TypeError: an int where a str was due` (the plugin parser's exception escaped), and the naabu line's validation error failing the stage.

- [ ] **Step 3: Drop the line instead, and say so in the CHANGELOG**

Save as `$W/task1_lines.py`:

```python
"""Task 1: the executor drops a line its parser cannot take, whatever the parser raises.

Usage: python task1_lines.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

executor = Source(root, "cyberfw/pipeline/executor.py")
executor.replace(
    "            except ParseError as exc:\n"
    "                logger.debug(\"%s\", exc)\n"
    "                unparsed += 1\n"
    "                rec = None\n",
    "            except ParseError as exc:\n"
    "                logger.debug(\"%s\", exc)\n"
    "                unparsed += 1\n"
    "                rec = None\n"
    "            except Exception as exc:\n"
    "                # A schema's ValidationError, a plugin's TypeError, a line nested too\n"
    "                # deep: the line is not the tool's output as its parser knows it, and\n"
    "                # costs that line, never the stage and its other records.\n"
    "                logger.debug(\"[%s:%d] %s: %s\", tool, lineno, type(exc).__name__, exc)\n"
    "                unparsed += 1\n"
    "                rec = None\n",
)
executor.save()
```

Save as `$W/task1_docs.py`:

```python
"""Task 1: the CHANGELOG says a line a parser cannot take no longer fails its stage.

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
    "### Fixed\n- Два прогона, начатые в одну секунду",
    "### Fixed\n"
    "- Строка вывода, которую не принимает схема инструмента (например, порт\n"
    "  строкой вместо числа у naabu), роняла весь этап вместе с уже найденными\n"
    "  записями. Теперь такая строка отбрасывается и попадает в сводку «did not\n"
    "  match the expected schema», как строки не в JSON; этап идёт дальше.\n"
    "- Два прогона, начатые в одну секунду",
)
changelog.save()
```

```bash
uv run --quiet python "$W/task1_lines.py" .
uv run --quiet python "$W/task1_docs.py" .
```

Expected: `edited cyberfw/pipeline/executor.py`, `edited CHANGELOG.md`.

- [ ] **Step 4: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_executor.py -q -p no:cacheprovider
```

Expected: `43 passed, 2 skipped`.

- [ ] **Step 5: The whole suite, lint, types, and the output**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1198 passed, 5 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 77 source files`.

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/1-lines" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -r "$W/transcripts/0-base" "$W/transcripts/1-lines" && echo identical
```

Expected: `50 passed`, then `identical`. (If the only difference is an `elapsed <dur> (1m…s)` line, the machine was loaded enough for a stage to pass a minute — capture again into an empty directory.)

- [ ] **Step 6: Commit**

```bash
git add cyberfw/pipeline/executor.py CHANGELOG.md tests/unit/test_executor.py
git commit -m "Drop a line a tool's parser cannot take, whatever it raises; never the stage"
```

---

### Task 2: Finding plugin packages from their metadata

**Files:**
- Create: `cyberfw/manager/discovery.py`, `tests/unit/_dists.py`, `tests/unit/test_plugin_discovery.py`
- Modify (by script): `tests/conftest.py` (the `site` fixture)

**Interfaces:**
- Produces, in `cyberfw/manager/discovery.py`: `CODE_GROUP = "cyberfw.tools"`, `MANIFEST_GROUP = "cyberfw.manifests"`, `Kind = Literal["manifest", "code"]`, `normalize(name) -> str` (PEP 503), `Declared(tool, package, version, group, value, kind)` (frozen), `package_kind(dist) -> Kind`, `discover() -> list[Declared]` sorted by package, tool, group.
- Produces, for tests: the `site` fixture (a directory on `sys.path`; the `cyberfw_*` modules imported from it leave with it) and `tests/unit/_dists.py`'s `install(site, name, *, version, manifests, tools, files, record)`.

- [ ] **Step 1: Write the failing tests**

Save as `$W/task2_tests.py`:

```python
"""Task 2, test first: the ``site`` fixture test plugin packages are installed into.

Usage: python task2_tests.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

FIXTURE = '''

@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A directory on ``sys.path`` for test plugin packages (``tests/unit/_dists.py``
    installs them); the modules they import leave with it."""
    directory = tmp_path / "site"
    directory.mkdir()
    monkeypatch.syspath_prepend(str(directory))
    before = set(sys.modules)
    yield directory
    for name in set(sys.modules) - before:
        if name.startswith("cyberfw_"):
            del sys.modules[name]
'''

conftest = Source(root, "tests/conftest.py")
conftest.text = conftest.text.rstrip("\n") + "\n" + FIXTURE
conftest.save()
```

Create `tests/unit/_dists.py`:

```python
"""Plugin packages for tests: real distributions, not mocks.

:func:`install` writes a package's files and a ``*.dist-info`` — its metadata,
its entry points and the ``RECORD`` of what it installed — into the directory
the ``site`` fixture (``tests/conftest.py``) puts on ``sys.path``, where
``importlib.metadata`` finds it like any installed package.
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from pathlib import Path

from cyberfw.manager.discovery import CODE_GROUP, MANIFEST_GROUP


def install(
    site: Path,
    name: str,
    *,
    version: str = "1.0",
    manifests: Mapping[str, str] | None = None,
    tools: Mapping[str, str] | None = None,
    files: Mapping[str, str] | None = None,
    record: bool = True,
) -> None:
    """Install the package ``name`` into ``site``: ``files`` (path → text), and a
    dist-info declaring ``manifests`` and ``tools`` (tool → entry point value).
    Without ``record`` its files cannot be listed, as with some installers."""
    files = dict(files or {})
    for relative, text in files.items():
        path = site / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    info = site / f"{name.replace('-', '_')}-{version}.dist-info"
    info.mkdir()
    (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8")
    points = ""
    for group, entries in ((MANIFEST_GROUP, manifests), (CODE_GROUP, tools)):
        if entries:
            points += f"[{group}]\n" + "".join(f"{tool} = {value}\n" for tool, value in entries.items()) + "\n"
    (info / "entry_points.txt").write_text(points, encoding="utf-8")
    if record:
        listed = [*files, f"{info.name}/METADATA", f"{info.name}/entry_points.txt", f"{info.name}/RECORD"]
        (info / "RECORD").write_text("".join(f"{path},,\n" for path in listed), encoding="utf-8")
    importlib.invalidate_caches()
```

Create `tests/unit/test_plugin_discovery.py`:

```python
"""Finding plugin packages: from their metadata alone, each with its verified kind."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from cyberfw.manager.discovery import CODE_GROUP, MANIFEST_GROUP, Declared, discover, normalize

from ._dists import install

MANIFEST = "contract: 1\n"  # its content is not read here


def _ours(found: list[Declared]) -> list[Declared]:
    return [declared for declared in found if declared.package.startswith("cyberfw-")]


def test_both_groups_are_read_from_the_metadata(site: Path) -> None:
    install(site, "cyberfw-sample", version="0.3", manifests={"sample": "cyberfw_sample"},
            files={"cyberfw_sample/sample.yaml": MANIFEST})
    install(site, "cyberfw-bar", tools={"bar": "cyberfw_bar:PLUGIN"}, files={"cyberfw_bar/__init__.py": "PLUGIN = None\n"})

    assert _ours(discover()) == [
        Declared(tool="bar", package="cyberfw-bar", version="1.0", group=CODE_GROUP, value="cyberfw_bar:PLUGIN", kind="code"),
        Declared(tool="sample", package="cyberfw-sample", version="0.3", group=MANIFEST_GROUP, value="cyberfw_sample", kind="manifest"),
    ]


def test_finding_a_package_runs_none_of_its_code(site: Path) -> None:
    install(site, "cyberfw-boom", tools={"boom": "cyberfw_boom:PLUGIN"},
            files={"cyberfw_boom/__init__.py": "raise RuntimeError('cyberfw_boom was imported')\n"})

    assert [declared.tool for declared in _ours(discover())] == ["boom"]
    assert "cyberfw_boom" not in sys.modules


@pytest.mark.parametrize(
    ("files", "tools", "record", "kind"),
    [
        ({"cyberfw_k/k.yaml": MANIFEST}, None, True, "manifest"),
        ({"cyberfw_k/k.yaml": MANIFEST, "cyberfw_k/__init__.py": ""}, None, True, "code"),
        ({"cyberfw_k/k.yaml": MANIFEST, "cyberfw_k.pth": "import os\n"}, None, True, "code"),
        ({"cyberfw_k/k.yaml": MANIFEST, "cyberfw_k/fast.pyd": ""}, None, True, "code"),
        ({"cyberfw_k/k.yaml": MANIFEST}, {"other": "cyberfw_k:PLUGIN"}, True, "code"),
        ({"cyberfw_k/k.yaml": MANIFEST}, None, False, "code"),
    ],
    ids=["data only", "a .py file", "a .pth file", "a compiled module", "a code tool too", "files unlisted"],
)
def test_a_package_is_a_manifest_package_only_when_it_installed_no_python(
    site: Path, files: dict[str, str], tools: dict[str, str] | None, record: bool, kind: str
) -> None:
    install(site, "cyberfw-k", manifests={"k": "cyberfw_k"}, tools=tools, files=files, record=record)

    assert {declared.kind for declared in _ours(discover())} == {kind}


def test_package_names_are_compared_normalised(site: Path) -> None:
    install(site, "CyberFW_Sample.Extra", manifests={"sample": "cyberfw_sample"}, files={"cyberfw_sample/sample.yaml": MANIFEST})

    assert normalize("CyberFW_Sample.Extra") == "cyberfw-sample-extra"
    assert [declared.package for declared in _ours(discover())] == ["cyberfw-sample-extra"]
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python "$W/task2_tests.py" .
uv run --quiet python -m pytest tests/unit/test_plugin_discovery.py -q -p no:cacheprovider
```

Expected: `edited tests/conftest.py`; then `ModuleNotFoundError: No module named 'cyberfw.manager.discovery'` and `1 error`.

- [ ] **Step 3: Write discovery**

Create `cyberfw/manager/discovery.py`:

```python
"""Plugin packages, as their metadata describes them — nothing of theirs is imported.

A plugin package declares each of its tools as an entry point: in
``cyberfw.manifests`` for a tool its manifest describes, in ``cyberfw.tools``
for one whose adapter is Python. :func:`discover` reads those from the
installed distributions' metadata alone, with each package's name, version and
kind — ``manifest`` only when the files its installation recorded hold no
Python and it declares no code tool, so a package cannot claim to be data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib.metadata import Distribution, entry_points
from typing import Literal

__all__ = ["CODE_GROUP", "MANIFEST_GROUP", "Declared", "Kind", "discover", "normalize", "package_kind"]

#: Tools whose adapter is Python: each entry point names a ``ToolPlugin``.
CODE_GROUP = "cyberfw.tools"
#: Tools a manifest describes: each entry point names the package that holds it.
MANIFEST_GROUP = "cyberfw.manifests"
#: Files that are Python or run it — a package that installed any is a code package.
_CODE_FILES = (".py", ".pyc", ".pth", ".so", ".pyd")

Kind = Literal["manifest", "code"]


def normalize(name: str) -> str:
    """A package name as PEP 503 compares it: case-insensitive, ``-``, ``_`` and ``.`` alike."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class Declared:
    """One tool an installed package declares."""

    tool: str
    #: The package's name, normalised.
    package: str
    version: str
    #: :data:`MANIFEST_GROUP` or :data:`CODE_GROUP`.
    group: str
    #: What the entry point names: the manifest's package, or the ``module:attribute`` of a ``ToolPlugin``.
    value: str
    #: The package's kind, verified from its files.
    kind: Kind


def package_kind(dist: Distribution) -> Kind:
    """``manifest`` when the files ``dist`` installed hold no Python and it declares
    no code tool; ``code`` otherwise — and when its files cannot be listed."""
    files = dist.files
    if files is None:
        return "code"
    if any(str(file).lower().endswith(_CODE_FILES) for file in files):
        return "code"
    return "code" if dist.entry_points.select(group=CODE_GROUP) else "manifest"


def discover() -> list[Declared]:
    """Every tool the installed packages declare, by package, then tool."""
    found: list[Declared] = []
    kinds: dict[str, Kind] = {}
    for group in (MANIFEST_GROUP, CODE_GROUP):
        for point in entry_points(group=group):
            dist = point.dist
            if dist is None:
                continue
            package = normalize(dist.name)
            if package not in kinds:
                kinds[package] = package_kind(dist)
            found.append(
                Declared(
                    tool=point.name, package=package, version=dist.version, group=group, value=point.value,
                    kind=kinds[package],
                )
            )
    return sorted(found, key=lambda declared: (declared.package, declared.tool, declared.group))
```

- [ ] **Step 4: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_plugin_discovery.py -q -p no:cacheprovider
```

Expected: `9 passed`.

- [ ] **Step 5: The whole suite, lint, types**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1207 passed, 5 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 78 source files`.

- [ ] **Step 6: Commit**

```bash
git add cyberfw/manager/discovery.py tests/conftest.py tests/unit/_dists.py tests/unit/test_plugin_discovery.py
git commit -m "Find plugin packages from their metadata alone, each with its verified kind"
```

---

### Task 3: plugins.yaml, every tool's state, and loading

**Files:**
- Create: `cyberfw/manager/plugins.py`, `tests/unit/test_plugin_loading.py`
- Modify (by script): `cyberfw/exceptions.py` (`PluginError`; `ContractError.contract`), `cyberfw/tools/manifest.py` (passes the contract number), `cyberfw/config.py` (`plugins_file`), `cyberfw/api.py` (`list_plugins`, `PluginInfo`)

**Interfaces:**
- Consumes (Task 2): `discover`, `Declared`, `normalize`, `CODE_GROUP`.
- Produces, in `cyberfw/manager/plugins.py`: `State` (the seven states), `PluginInfo(package, version, kind, tool, state, reason="", env=())` (frozen), `PluginsFile(enabled, allow_code)`, `read_plugins_file(path) -> PluginsFile` (raises `PluginError`), `PluginSet(infos, tools)` with `declared() -> frozenset[str]`, `origin(tool) -> str | None`, `unavailable(tool) -> str | None`; `load_plugins(settings) -> PluginSet` (cached per process); `RESERVED`.
- Produces: `Settings.plugins_file` (`plugins.yaml`, resolved like `triage_file`); `api.list_plugins(settings=None) -> list[PluginInfo]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_plugin_loading.py`:

```python
"""Which plugin tools are in use: plugins.yaml, every state a tool can be in, and loading."""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
import yaml

from cyberfw import api
from cyberfw.config import Settings
from cyberfw.exceptions import PluginError
from cyberfw.manager import plugins
from cyberfw.manager.plugins import PluginInfo, load_plugins, read_plugins_file

from ._dists import install

SAMPLE = """\
contract: 1
install: {repo: acme/sample, asset_patterns: [], binary: sample, env: [SAMPLE_KEY]}
target: ["-u", "{target}"]
list: ["-l", "{input_file}"]
record: {kind: http, target: url}
"""

CODE = """\
from cyberfw.plugin import BaseTool, ToolContext, ToolPlugin, ToolRecord, ToolSpec


class BarTool(BaseTool):
    def build_cmd(self, ctx: ToolContext) -> list[str]:
        return [str(self.binary), "-u", ctx.target or ""]


PLUGIN = ToolPlugin(contract={contract}, adapter=BarTool, record=ToolRecord, install={install})
"""


@pytest.fixture(autouse=True)
def _fresh(monkeypatch: pytest.MonkeyPatch) -> None:
    # Loading is cached and its warnings deduplicated per process: each test starts clean.
    monkeypatch.setattr(plugins, "_LOADED", {})
    monkeypatch.setattr(plugins, "_WARNED", set())


@pytest.fixture
def warned(caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[], list[str]]]:
    """The warnings logged on the cyberfw logger — which stops propagating once the
    CLI has set logging up, so it is made to reach caplog for the test."""
    monkeypatch.setattr(logging.getLogger("cyberfw"), "propagate", True)
    caplog.set_level(logging.WARNING, logger="cyberfw")
    yield lambda: [record.getMessage() for record in caplog.records if record.levelno >= logging.WARNING]


def _sample(site: Path, *, package: str = "cyberfw-sample", tool: str = "sample", manifest: str = SAMPLE, **files: str) -> None:
    install(site, package, manifests={tool: "cyberfw_sample"}, files={f"cyberfw_sample/{tool}.yaml": manifest, **files})


def _bar(site: Path, *, contract: int = 1, install_spec: str = 'ToolSpec(repo="acme/bar", env=["BAR_KEY"])', body: str | None = None) -> None:
    source = body if body is not None else CODE.format(contract=contract, install=install_spec)
    install(site, "cyberfw-bar", tools={"bar": "cyberfw_bar:PLUGIN"}, files={"cyberfw_bar/__init__.py": source})


def _settings(tmp_path: Path, enabled: tuple[str, ...] = (), allow_code: tuple[str, ...] = ()) -> Settings:
    (tmp_path / "plugins.yaml").write_text(
        yaml.safe_dump({"enabled": list(enabled), "allow_code": list(allow_code)}), encoding="utf-8"
    )
    return Settings(root_dir=tmp_path)


def _info(settings: Settings, tool: str) -> PluginInfo:
    (info,) = [info for info in load_plugins(settings).infos if (info.tool or info.package) == tool]
    return info


def test_an_installed_package_stays_off_until_enabled(site: Path, tmp_path: Path) -> None:
    _sample(site)
    _bar(site)
    settings = _settings(tmp_path)

    assert (_info(settings, "sample").state, _info(settings, "sample").env) == ("disabled", ("SAMPLE_KEY",))
    assert _info(settings, "bar").state == "disabled"
    assert load_plugins(settings).tools == {} and "cyberfw_bar" not in sys.modules


def test_an_enabled_manifest_package_loads_its_tools(site: Path, tmp_path: Path) -> None:
    _sample(site)
    settings = _settings(tmp_path, enabled=("cyberfw-sample",))

    loaded = load_plugins(settings)

    assert _info(settings, "sample") == PluginInfo(
        package="cyberfw-sample", version="1.0", kind="manifest", tool="sample", state="enabled", env=("SAMPLE_KEY",)
    )
    assert loaded.tools["sample"].install is not None and loaded.tools["sample"].install.name == "sample"
    assert loaded.origin("sample") == "cyberfw-sample 1.0"


def test_a_code_package_runs_only_when_allowed_to(site: Path, tmp_path: Path) -> None:
    _bar(site)

    refused = _info(_settings(tmp_path, enabled=("cyberfw-bar",)), "bar")
    assert refused.state == "code-not-allowed" and "--allow-code" in refused.reason
    assert "cyberfw_bar" not in sys.modules

    allowed = load_plugins(_settings(tmp_path, enabled=("cyberfw-bar",), allow_code=("cyberfw-bar",)))
    assert _info(_settings(tmp_path, enabled=("cyberfw-bar",), allow_code=("cyberfw-bar",)), "bar").state == "enabled"
    assert allowed.tools["bar"].adapter.__name__ == "BarTool"
    assert allowed.tools["bar"].install is not None and allowed.tools["bar"].install.name == "bar"


def test_a_manifest_package_that_starts_shipping_python_is_not_loaded(site: Path, tmp_path: Path) -> None:
    # A release that adds Python is a code package now: enabled as data, it stays off.
    _sample(site, **{"cyberfw_sample/__init__.py": "raise RuntimeError('cyberfw_sample was imported')\n"})

    info = _info(_settings(tmp_path, enabled=("cyberfw-sample",)), "sample")

    assert (info.kind, info.state) == ("code", "code-not-allowed")
    assert "cyberfw_sample" not in sys.modules


@pytest.mark.parametrize(
    ("bar", "state", "reason"),
    [
        ({"contract": 99}, "incompatible", "written for plugin contract 99; this cyberfw loads 1 — update cyberfw"),
        ({"body": "PLUGIN = 42\n"}, "broken", "cyberfw_bar:PLUGIN is a int, not a ToolPlugin"),
        ({"body": "raise RuntimeError('no luck')\n"}, "broken", "RuntimeError: no luck"),
        ({"install_spec": "None"}, "broken", "it brings no install recipe"),
    ],
    ids=["another contract", "not a ToolPlugin", "fails to import", "no recipe"],
)
def test_a_code_plugin_that_cannot_be_used_says_why(
    site: Path, tmp_path: Path, bar: dict[str, object], state: str, reason: str
) -> None:
    _bar(site, **bar)  # type: ignore[arg-type]

    info = _info(_settings(tmp_path, enabled=("cyberfw-bar",), allow_code=("cyberfw-bar",)), "bar")

    assert info.state == state and reason in info.reason


@pytest.mark.parametrize(
    ("manifest", "state", "reason"),
    [
        (SAMPLE.replace('target: ["-u"', 'comand: [x]\ntarget: ["-u"'), "broken", "comand: unknown key"),
        (SAMPLE.replace("contract: 1", "contract: 2"), "incompatible", "written for plugin contract 2"),
    ],
)
def test_a_manifest_that_cannot_be_used_says_why(site: Path, tmp_path: Path, manifest: str, state: str, reason: str) -> None:
    _sample(site, manifest=manifest)

    info = _info(_settings(tmp_path, enabled=("cyberfw-sample",)), "sample")

    assert info.state == state and reason in info.reason


@pytest.mark.parametrize(
    ("tool", "reason"),
    [("nuclei", "nuclei is a built-in tool"), ("virustotal", "virustotal names records cyberfw makes itself")],
)
def test_a_plugin_cannot_take_a_name_cyberfw_uses(site: Path, tmp_path: Path, tool: str, reason: str) -> None:
    _sample(site, tool=tool)

    info = _info(_settings(tmp_path, enabled=("cyberfw-sample",)), tool)

    assert (info.state, info.reason) == ("conflict", reason)
    assert tool not in load_plugins(_settings(tmp_path, enabled=("cyberfw-sample",))).tools


def test_two_packages_declaring_one_name_both_lose_it(site: Path, tmp_path: Path) -> None:
    _sample(site, package="cyberfw-one", tool="dup")
    install(site, "cyberfw-two", manifests={"dup": "cyberfw_two"}, files={"cyberfw_two/dup.yaml": SAMPLE})

    loaded = load_plugins(_settings(tmp_path, enabled=("cyberfw-one", "cyberfw-two")))

    assert {(info.package, info.state) for info in loaded.infos if info.tool == "dup"} == {
        ("cyberfw-one", "conflict"), ("cyberfw-two", "conflict"),
    }
    assert "dup" not in loaded.tools


def test_a_tool_name_that_is_not_one_is_broken(site: Path, tmp_path: Path) -> None:
    _sample(site, tool="Bad")

    info = _info(_settings(tmp_path, enabled=("cyberfw-sample",)), "Bad")

    assert info.state == "broken" and "is not a tool name" in info.reason


def test_an_enabled_package_that_is_not_installed_is_missing(tmp_path: Path, warned: Callable[[], list[str]]) -> None:
    info = _info(_settings(tmp_path, enabled=("cyberfw-gone",)), "cyberfw-gone")

    assert (info.state, info.tool, info.reason) == ("missing", "", "not installed, or it declares no cyberfw tool")
    assert warned() == ["plugin cyberfw-gone: missing — not installed, or it declares no cyberfw tool"]


def test_package_names_in_plugins_yaml_are_compared_normalised(site: Path, tmp_path: Path) -> None:
    _sample(site)

    assert _info(_settings(tmp_path, enabled=("CyberFW_Sample",)), "sample").state == "enabled"


def test_an_unreadable_plugins_yaml_enables_nothing_and_says_so(
    site: Path, tmp_path: Path, warned: Callable[[], list[str]]
) -> None:
    _sample(site)
    (tmp_path / "plugins.yaml").write_text("enabled: [cyberfw-sample\n", encoding="utf-8")

    info = _info(Settings(root_dir=tmp_path), "sample")

    assert info.state == "disabled"
    assert len(warned()) == 1 and "not valid YAML" in warned()[0] and "no plugin is enabled until it is fixed" in warned()[0]


def test_a_problem_is_warned_about_once_per_process(site: Path, tmp_path: Path, warned: Callable[[], list[str]]) -> None:
    _bar(site, contract=99)
    load_plugins(_settings(tmp_path, enabled=("cyberfw-bar",), allow_code=("cyberfw-bar",)))
    (tmp_path / "plugins.yaml").write_text("# reordered\nallow_code: [cyberfw-bar]\nenabled: [cyberfw-bar]\n", encoding="utf-8")
    load_plugins(Settings(root_dir=tmp_path))

    assert warned() == [
        "plugin cyberfw-bar (bar): incompatible — written for plugin contract 99; this cyberfw loads 1 — update cyberfw"
    ]


def test_a_package_nobody_enabled_stays_quiet(site: Path, tmp_path: Path, warned: Callable[[], list[str]]) -> None:
    _sample(site, tool="nuclei")

    assert _info(_settings(tmp_path), "nuclei").state == "conflict"
    assert warned() == []


@pytest.mark.parametrize(
    ("text", "said"),
    [("enabled: cyberfw-x\n", "enabled: a list of package names"), ("enable: [x]\n", "expected the keys enabled and allow_code")],
)
def test_a_plugins_yaml_that_is_not_one_is_named(tmp_path: Path, text: str, said: str) -> None:
    (tmp_path / "plugins.yaml").write_text(text, encoding="utf-8")

    with pytest.raises(PluginError, match=said):
        read_plugins_file(tmp_path / "plugins.yaml")


def test_a_tool_that_is_not_available_says_why_and_what_to_do(site: Path, tmp_path: Path) -> None:
    _sample(site)

    loaded = load_plugins(_settings(tmp_path))

    assert loaded.unavailable("sample") == (
        "sample is not available: plugin cyberfw-sample 1.0 is disabled — enable it with `cyberfw plugins enable cyberfw-sample`"
    )
    assert loaded.unavailable("nuclei") is None and loaded.declared() >= {"sample"}


def test_the_api_lists_the_plugins(site: Path, tmp_path: Path) -> None:
    _sample(site)
    settings = _settings(tmp_path, enabled=("cyberfw-sample",))

    assert api.list_plugins(settings) == load_plugins(settings).infos
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python -m pytest tests/unit/test_plugin_loading.py -q -p no:cacheprovider
```

Expected: `ImportError: cannot import name 'PluginError' from 'cyberfw.exceptions'` and `1 error`.

- [ ] **Step 3: The errors, the setting, the API call — and loading**

Save as `$W/task3_support.py`:

```python
"""Task 3: what loading plugins needs around it — its errors, its setting, and the API call.

Usage: python task3_support.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

exceptions = Source(root, "cyberfw/exceptions.py")
exceptions.replace(
    'class ContractError(CyberfwError):\n'
    '    """A plugin is written for a plugin contract this cyberfw does not load (``incompatible``)."""\n',
    'class ContractError(CyberfwError):\n'
    '    """A plugin is written for a plugin contract this cyberfw does not load (``incompatible``)."""\n'
    "\n"
    "    def __init__(self, message: str, *, contract: int) -> None:\n"
    "        #: The contract version the plugin is written for.\n"
    "        self.contract = contract\n"
    "        super().__init__(message)\n"
    "\n"
    "\n"
    "class PluginError(CyberfwError):\n"
    '    """``plugins.yaml`` cannot be read or written, or names a package that is not installed."""\n',
)
exceptions.save()

manifest = Source(root, "cyberfw/tools/manifest.py")
manifest.replace(
    '        raise ContractError(f"{where}: written for plugin contract {contract}; this cyberfw loads {loads}")\n',
    '        raise ContractError(f"{where}: written for plugin contract {contract}; this cyberfw loads {loads}", contract=contract)\n',
)
manifest.save()

config = Source(root, "cyberfw/config.py")
config.replace(
    '        "managed with `cyberfw mute` / `unmute` / `mutes`.",\n    )\n',
    '        "managed with `cyberfw mute` / `unmute` / `mutes`.",\n    )\n'
    "    plugins_file: Path = Field(\n"
    '        default=Path("plugins.yaml"),\n'
    '        description="The plugin packages enabled — and, of those, the code packages allowed to run "\n'
    '        "Python inside cyberfw; managed with `cyberfw plugins enable` / `disable`.",\n'
    "    )\n",
)
config.replace(
    '        for name in ("tools_dir", "reports_dir", "logs_dir", "pipelines_dir", "triage_file"):\n',
    '        for name in ("tools_dir", "reports_dir", "logs_dir", "pipelines_dir", "triage_file", "plugins_file"):\n',
)
config.save()

api = Source(root, "cyberfw/api.py")
api.replace(
    "from cyberfw.pipeline.engine import NodeResult, PipelineResult, StageEvent\n",
    "from cyberfw.manager.plugins import PluginInfo, load_plugins\n"
    "from cyberfw.pipeline.engine import NodeResult, PipelineResult, StageEvent\n",
)
api.replace('    "PlanStage",\n', '    "PlanStage",\n    "PluginInfo",\n')
api.replace('    "export_sarif",\n', '    "export_sarif",\n    "list_plugins",\n')
api.text = api.text.rstrip("\n") + '''


def list_plugins(settings: Settings | None = None) -> list[PluginInfo]:
    """Every plugin tool the installed packages declare — its package, version and
    kind (``manifest`` / ``code``), its state and why, the extra environment
    variables it asks for — and each package ``plugins.yaml`` enables that is missing.
    Reads the packages' metadata; only enabled packages are loaded."""
    settings = settings if settings is not None else load_settings()
    return list(load_plugins(settings).infos)
'''
api.save()
```

```bash
uv run --quiet python "$W/task3_support.py" .
```

Expected: `edited` lines for `cyberfw/exceptions.py`, `cyberfw/tools/manifest.py`, `cyberfw/config.py` and `cyberfw/api.py`.

Create `cyberfw/manager/plugins.py`:

```python
"""Which plugin tools are in use: ``plugins.yaml``, each tool's state, and loading them.

``plugins.yaml`` names the packages the user enabled and, of those, the code
packages allowed to run Python inside cyberfw::

    # managed by `cyberfw plugins enable/disable`
    enabled:
      - cyberfw-foo        # a manifest package
      - cyberfw-bar
    allow_code:
      - cyberfw-bar        # a code package: its Python runs inside cyberfw

:func:`load_plugins` turns what :func:`~cyberfw.manager.discovery.discover`
found into a :class:`PluginSet`: the tools that loaded, and every declared tool's
state and why. Only enabled packages are loaded — a manifest by reading its YAML,
a code tool (only from a package in ``allow_code``) by importing its entry point —
and a plugin never breaks cyberfw: a problem puts its tools in their state, with
one warning per problem per process on the ``cyberfw`` logger.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from importlib.metadata import EntryPoint
from pathlib import Path
from typing import Literal

import yaml

from cyberfw.config import Settings
from cyberfw.exceptions import ContractError, ManifestError, PluginError
from cyberfw.logging import get_logger
from cyberfw.manager.discovery import CODE_GROUP, Declared, discover, normalize
from cyberfw.plugin import SUPPORTED_CONTRACTS, BaseTool, ToolPlugin, ToolRecord, ToolSpec
from cyberfw.tools import BUILTIN
from cyberfw.tools.manifest import parse_manifest
from cyberfw.tools.manifest_tool import compile_manifest

__all__ = ["RESERVED", "PluginInfo", "PluginSet", "PluginsFile", "State", "load_plugins", "read_plugins_file"]

LOG = get_logger("plugins")

#: Names cyberfw gives records of its own (its post-scan checks): no plugin tool may take one.
RESERVED = frozenset({"tlscheck", "mailcheck", "takeover", "virustotal"})
#: What a tool's name may be.
TOOL_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*$")

State = Literal["enabled", "disabled", "code-not-allowed", "conflict", "incompatible", "broken", "missing"]


@dataclass(frozen=True)
class PluginInfo:
    """One plugin tool as ``cyberfw plugins`` lists it — or a package that is missing."""

    package: str
    version: str
    #: ``manifest`` or ``code``; empty for a missing package.
    kind: str
    #: Empty for a missing package.
    tool: str
    state: State
    #: Why the tool is in a state other than ``enabled``.
    reason: str = ""
    #: The extra environment variables its recipe asks for, when its manifest or plugin could be read.
    env: tuple[str, ...] = ()


@dataclass(frozen=True)
class PluginsFile:
    """``plugins.yaml``: the enabled packages, and those allowed to run code (names normalised)."""

    enabled: frozenset[str] = frozenset()
    allow_code: frozenset[str] = frozenset()


def read_plugins_file(path: Path) -> PluginsFile:
    """``plugins.yaml`` at ``path``; nothing enabled when there is none.
    Raises :class:`PluginError` when it cannot be read or is not one."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return PluginsFile()
    except OSError as exc:
        raise PluginError(f"{path}: cannot be read: {exc}") from exc
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise PluginError(f"{path}: not valid YAML: {exc}") from exc
    if not isinstance(data, dict) or set(data) - {"enabled", "allow_code"}:
        raise PluginError(f"{path}: expected the keys enabled and allow_code, each a list of package names")
    lists: dict[str, frozenset[str]] = {}
    for key in ("enabled", "allow_code"):
        names = data.get(key) or []
        if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
            raise PluginError(f"{path}: {key}: a list of package names")
        lists[key] = frozenset(normalize(name) for name in names)
    return PluginsFile(enabled=lists["enabled"], allow_code=lists["allow_code"])


@dataclass
class PluginSet:
    """The plugin tools that loaded, and every declared tool's state."""

    infos: list[PluginInfo] = field(default_factory=list)
    #: The tools that loaded, by name — each with its install recipe.
    tools: dict[str, ToolPlugin] = field(default_factory=dict)

    def declared(self) -> frozenset[str]:
        """Every tool name an installed plugin package declares, whatever its state."""
        return frozenset(info.tool for info in self.infos if info.tool)

    def origin(self, tool: str) -> str | None:
        """``cyberfw-foo 0.3`` for a tool that loaded."""
        for info in self.infos:
            if info.tool == tool and info.state == "enabled":
                return f"{info.package} {info.version}"
        return None

    def unavailable(self, tool: str) -> str | None:
        """Why a declared plugin tool cannot be used, as a sentence; ``None`` when it can,
        or when no plugin declares it."""
        if tool in self.tools:
            return None
        for info in self.infos:
            if info.tool == tool:
                return f"{tool} is not available: plugin {info.package} {info.version} is {_PHRASE[info.state]} — {info.reason}"
        return None


#: Each state as the sentence about a plugin reads it.
_PHRASE: dict[State, str] = {
    "enabled": "enabled",
    "disabled": "disabled",
    "code-not-allowed": "not allowed to run code",
    "conflict": "in conflict",
    "incompatible": "incompatible",
    "broken": "broken",
    "missing": "missing",
}


#: (plugins file, its bytes, sys.path) → the set loaded for them; and the problems already warned about.
_LOADED: dict[tuple[str, bytes | None, tuple[str, ...]], PluginSet] = {}
_WARNED: set[tuple[str, str, str]] = set()


def load_plugins(settings: Settings) -> PluginSet:
    """The plugin tools for ``settings``' ``plugins.yaml``, loaded once per process for
    the same file and the same installed packages."""
    path = settings.plugins_file
    try:
        content: bytes | None = path.read_bytes()
    except OSError:
        content = None
    key = (str(path), content, tuple(sys.path))
    if key not in _LOADED:
        _LOADED.clear()
        _LOADED[key] = _load(path)
    return _LOADED[key]


def _load(path: Path) -> PluginSet:
    try:
        chosen = read_plugins_file(path)
    except PluginError as exc:
        _warn("plugins.yaml", "", f"{exc} — no plugin is enabled until it is fixed")
        chosen = PluginsFile()
    declared = discover()
    packages = Counter(point.tool for point in {(d.package, d.tool): d for d in declared}.values())
    twice = Counter((d.package, d.tool) for d in declared)
    result = PluginSet()
    for point in declared:
        if twice[(point.package, point.tool)] > 1 and point.group == CODE_GROUP:
            continue  # reported once, with its manifest entry
        state, reason, env, plugin = _state(point, chosen, packages, twice)
        result.infos.append(
            PluginInfo(
                package=point.package, version=point.version, kind=point.kind, tool=point.tool,
                state=state, reason=reason, env=env,
            )
        )
        if plugin is not None:
            result.tools[point.tool] = plugin
        elif point.package in chosen.enabled:
            # Only what the user asked for is a problem: a package nobody enabled stays quiet.
            _warn(point.package, point.tool, f"{_PHRASE[state]} — {reason}")
    found = {point.package for point in declared}
    for package in sorted(chosen.enabled - found):
        reason = "not installed, or it declares no cyberfw tool"
        result.infos.append(PluginInfo(package=package, version="", kind="", tool="", state="missing", reason=reason))
        _warn(package, "", f"{_PHRASE['missing']} — {reason}")
    return result


def _state(
    point: Declared, chosen: PluginsFile, packages: Counter[str], twice: Counter[tuple[str, str]]
) -> tuple[State, str, tuple[str, ...], ToolPlugin | None]:
    """A declared tool's state, the reason, its ``env:`` when known, and the plugin when it loaded."""
    if not TOOL_NAME.match(point.tool):
        return "broken", f"{point.tool!r} is not a tool name (lowercase letters, digits, - and _)", (), None
    if twice[(point.package, point.tool)] > 1:
        return "broken", f"{point.package} declares {point.tool} both as a manifest and as code", (), None
    if point.tool in BUILTIN:
        return "conflict", f"{point.tool} is a built-in tool", (), None
    if point.tool in RESERVED:
        return "conflict", f"{point.tool} names records cyberfw makes itself", (), None
    if packages[point.tool] > 1:
        return "conflict", f"another installed package declares {point.tool} too: disable one of them", (), None
    env = _manifest_env(point) if point.group != CODE_GROUP else ()
    if point.package not in chosen.enabled:
        return "disabled", f"enable it with `cyberfw plugins enable {point.package}`", env, None
    if point.kind == "code" and point.package not in chosen.allow_code:
        return (
            "code-not-allowed",
            "it ships Python that would run inside cyberfw — "
            f"allow that with `cyberfw plugins enable {point.package} --allow-code`",
            env,
            None,
        )
    try:
        plugin = _load_manifest(point) if point.group != CODE_GROUP else _load_code(point)
    except ContractError as exc:
        loads = ", ".join(str(version) for version in sorted(SUPPORTED_CONTRACTS))
        return "incompatible", f"written for plugin contract {exc.contract}; this cyberfw loads {loads} — update cyberfw", env, None
    except (ManifestError, ValueError) as exc:
        return "broken", str(exc), env, None
    except Exception as exc:  # whatever a plugin's own import raises
        return "broken", f"{type(exc).__name__}: {exc}", env, None
    assert plugin.install is not None
    return "enabled", "", tuple(plugin.install.env), plugin


def _manifest_path(point: Declared) -> Path:
    """The manifest file of a manifest tool, located without running anything: its
    entry point names a top-level package, which ``find_spec`` finds without importing."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", point.value):
        raise ManifestError(f"the cyberfw.manifests entry point must name a top-level package, not {point.value!r}")
    spec = importlib.util.find_spec(point.value)
    for location in (spec.submodule_search_locations or []) if spec is not None else []:
        path = Path(location) / f"{point.tool}.yaml"
        if path.is_file():
            return path
    raise ManifestError(f"{point.tool}.yaml was not found in the package {point.value}")


def _manifest_env(point: Declared) -> tuple[str, ...]:
    """A manifest tool's ``env:`` — read from its YAML, which runs nothing — or nothing when it cannot be read."""
    try:
        path = _manifest_path(point)
        return tuple(parse_manifest(path.read_text(encoding="utf-8"), where=str(path)).install.env)
    except Exception:  # its state says what is wrong when it is loaded
        return ()


def _load_manifest(point: Declared) -> ToolPlugin:
    path = _manifest_path(point)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ManifestError(f"{path}: cannot be read: {exc}") from exc
    return compile_manifest(point.tool, parse_manifest(text, where=str(path)))


def _load_code(point: Declared) -> ToolPlugin:
    """Import a code tool's entry point and check that it is a usable ``ToolPlugin``."""
    plugin = EntryPoint(name=point.tool, value=point.value, group=point.group).load()
    if not isinstance(plugin, ToolPlugin):
        raise ValueError(f"{point.value} is a {type(plugin).__name__}, not a ToolPlugin")
    if plugin.contract not in SUPPORTED_CONTRACTS:
        raise ContractError(f"written for plugin contract {plugin.contract}", contract=plugin.contract)
    if not (isinstance(plugin.adapter, type) and issubclass(plugin.adapter, BaseTool)):
        raise ValueError("its adapter is not a BaseTool subclass")
    if not (isinstance(plugin.record, type) and issubclass(plugin.record, ToolRecord)):
        raise ValueError("its record is not a ToolRecord subclass")
    if not isinstance(plugin.install, ToolSpec):
        raise ValueError("it brings no install recipe (install=ToolSpec(...))")
    install = ToolSpec.model_validate({**plugin.install.model_dump(), "name": point.tool})
    return ToolPlugin(contract=plugin.contract, adapter=plugin.adapter, record=plugin.record, install=install)


def _warn(package: str, tool: str, problem: str) -> None:
    if (package, tool, problem) not in _WARNED:
        _WARNED.add((package, tool, problem))
        LOG.warning("plugin %s%s: %s", package, f" ({tool})" if tool else "", problem)
```

- [ ] **Step 4: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_plugin_loading.py -q -p no:cacheprovider
```

Expected: `23 passed`.

- [ ] **Step 5: The whole suite, lint, types, and the output**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1230 passed, 5 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 79 source files`.

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/3-loading" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -r "$W/transcripts/0-base" "$W/transcripts/3-loading" && echo identical
```

Expected: `50 passed`, then `identical`. (If the only difference is an `elapsed <dur> (1m…s)` line, the machine was loaded enough for a stage to pass a minute — capture again into an empty directory.)

- [ ] **Step 6: Commit**

```bash
git add cyberfw/manager/plugins.py cyberfw/exceptions.py cyberfw/tools/manifest.py cyberfw/config.py cyberfw/api.py tests/unit/test_plugin_loading.py
git commit -m "Load the plugins plugins.yaml enables, and give every declared tool its state"
```

---

### Task 4: The tools in use, on the tool manager

**Files:**
- Create: `tests/unit/test_plugin_tools.py`
- Modify (by script): `cyberfw/manager/registry.py` (overlays, skip), `cyberfw/manager/__init__.py` (the tools in use; the lock keeps declared tools), `cyberfw/plugin.py` (`BaseTool._record`), `cyberfw/core/workspace.py` (`open_manager`), `cyberfw/core/scan.py`, `cyberfw/core/tool_run.py`, `cyberfw/pipeline/engine.py`, `cyberfw/cli/launcher.py`, `cyberfw/cli/tools.py`; `tests/unit/test_cli.py`

**Interfaces:**
- Consumes (Task 3): `PluginSet`, `load_plugins`.
- Produces: `load_registry(path, *, overlays=None, skip=())`; `ToolManager(..., plugins: PluginSet | None = None)` with `plugins`, `tools -> dict[str, ToolPlugin]`, `unavailable(name)`, `adapter_class(name)`, `adapter_for(name, binary)`, and `spec(name)` raising the plugin's reason for a tool not available; `BaseTool._record` (set by `adapter_for`); `open_manager(settings)` loading the plugins in use.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_plugin_tools.py`:

```python
"""Plugin tools in use, wherever cyberfw looks a tool up: a run, a pipeline, the registry, the lock."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from cyberfw import api
from cyberfw.config import load_settings
from cyberfw.core.workspace import open_manager
from cyberfw.exceptions import CyberfwError, RegistryError
from cyberfw.manager import ToolManager, plugins
from cyberfw.manager.lock import LockedTool, ToolLock, read_lock, write_lock
from cyberfw.manager.registry import ToolSpec

from . import test_cli as base
from ._dists import install

SAMPLE = """\
contract: 1
install: {repo: acme/sample, asset_patterns: [], binary: sample}
target: ["-u", "{target}"]
list: ["-l", "{input_file}"]
record: {kind: http, target: url}
"""

BAR = """\
from cyberfw.plugin import BaseTool, ToolContext, ToolPlugin, ToolRecord, ToolSpec


class BarRecord(ToolRecord):
    url: str = ""

    @classmethod
    def from_json(cls, tool, text, lineno):
        record = super().from_json(tool, text, lineno)
        record.target, record.kind = record.url, "http"
        return record


class BarTool(BaseTool):
    def build_cmd(self, ctx: ToolContext) -> list[str]:
        return [str(self.binary), "-u", ctx.target or ""]


PLUGIN = ToolPlugin(
    contract=1, adapter=BarTool, record=BarRecord, install=ToolSpec(repo="acme/bar", asset_patterns=[], binary="bar")
)
"""

PROBE = "description: One stage, a plugin's tool\nnodes:\n  - tool: sample\n    stage: live\n"


@pytest.fixture(autouse=True)
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, site: Path) -> Path:
    """The CLI tests' workspace of fake tools, two plugin packages installed (none
    enabled), their fake binaries, and a YAML pipeline that names a plugin's tool."""
    base._write_fake_binaries(tmp_path / "tools_bin")
    base._write_registry(tmp_path)
    for tool in ("sample", "bar"):
        base.TestBaselineComparison._tool_prints(tmp_path, tool, {"url": f"https://{tool}.example.com/", "status_code": 200})
    (tmp_path / "pipelines").mkdir()
    (tmp_path / "pipelines" / "probe.yaml").write_text(PROBE, encoding="utf-8")
    install(site, "cyberfw-sample", manifests={"sample": "cyberfw_sample"}, files={"cyberfw_sample/sample.yaml": SAMPLE})
    install(site, "cyberfw-bar", tools={"bar": "cyberfw_bar:PLUGIN"}, files={"cyberfw_bar/__init__.py": BAR})
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(plugins, "_LOADED", {})
    monkeypatch.setattr(plugins, "_WARNED", set())
    return tmp_path


def _enable(workspace: Path, *packages: str, allow_code: tuple[str, ...] = ()) -> None:
    (workspace / "plugins.yaml").write_text(
        yaml.safe_dump({"enabled": list(packages), "allow_code": list(allow_code)}), encoding="utf-8"
    )


def test_an_enabled_manifest_tool_runs_like_a_built_in_one(workspace: Path) -> None:
    _enable(workspace, "cyberfw-sample")

    outcome = api.run_tool("sample", target="https://sample.example.com")

    assert outcome.succeeded
    assert [(record.tool, record.target, record.kind) for record in outcome.result.records] == [
        ("sample", "https://sample.example.com/", "http"),
    ]


def test_a_code_plugin_reads_its_lines_with_its_own_record_model(workspace: Path) -> None:
    # Its adapter keeps BaseTool's parse_line: the model comes from its description.
    _enable(workspace, "cyberfw-bar", allow_code=("cyberfw-bar",))

    (record,) = api.run_tool("bar", target="bar.example.com").result.records

    assert (type(record).__name__, record.target, record.kind) == ("BarRecord", "https://bar.example.com/", "http")


def test_a_yaml_pipeline_may_name_a_plugin_tool(workspace: Path) -> None:
    _enable(workspace, "cyberfw-sample")

    plan = api.plan_pipeline("probe", "example.com")
    outcome = api.run_pipeline("probe", "example.com", save=False, mail=False, takeover=False, intel=False)

    assert plan.ready and [stage.tool for stage in plan.stages] == ["sample"]
    assert outcome.succeeded and [record.tool for record in outcome.result.records] == ["sample"]


def test_a_plugin_tool_not_in_use_says_why_and_what_to_do(workspace: Path) -> None:
    said = "sample is not available: plugin cyberfw-sample 1.0 is disabled — enable it with `cyberfw plugins enable cyberfw-sample`"

    with pytest.raises(RegistryError, match="^sample is not available") as run:
        api.run_tool("sample", target="example.com")
    with pytest.raises(RegistryError, match="^sample is not available") as plan:
        api.plan_pipeline("probe", "example.com")

    assert str(run.value) == str(plan.value) == said


def test_registry_yaml_lays_its_keys_over_a_plugin_s_recipe(workspace: Path) -> None:
    _enable(workspace, "cyberfw-sample")
    with (workspace / "registry.yaml").open("a", encoding="utf-8") as registry:
        registry.write("\nsample:\n  version: v2.0.0\n")

    manager = open_manager(load_settings())
    spec = manager.spec("sample")
    manager.close()

    assert (spec.name, spec.repo, spec.binary, spec.version) == ("sample", "acme/sample", "sample", "v2.0.0")


def test_an_entry_for_a_plugin_not_in_use_leaves_the_registry_working(workspace: Path) -> None:
    # "version:" alone is no recipe: without its plugin it is left out, not an error.
    with (workspace / "registry.yaml").open("a", encoding="utf-8") as registry:
        registry.write("\nsample:\n  version: v2.0.0\n")

    manager = open_manager(load_settings())
    try:
        assert manager.spec("subfinder").repo == "org/subfinder"
        with pytest.raises(RegistryError, match="^sample is not available"):
            manager.spec("sample")
    finally:
        manager.close()


def test_the_lock_keeps_a_disabled_plugin_tool_s_pin(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def offline(self: ToolManager, spec: ToolSpec) -> LockedTool:
        raise CyberfwError("no network in tests")

    monkeypatch.setattr(ToolManager, "_resolve", offline)
    pins = {name: LockedTool(repo=f"acme/{name}", tag="v1", assets={}) for name in ("sample", "gone")}
    write_lock(workspace / "tools.lock", ToolLock(tools=pins))

    manager = open_manager(load_settings())
    manager.update_lock()
    manager.close()

    lock = read_lock(workspace / "tools.lock")
    assert lock is not None and set(lock.tools) == {"sample"}
```

- [ ] **Step 2: Run them to see them fail**

```bash
uv run --quiet python -m pytest tests/unit/test_plugin_tools.py -q -p no:cacheprovider
```

Expected: `7 failed` — the plugin tools are unknown everywhere (`Regex pattern did not match`, …) and the lock drops the disabled plugin's pin (`set() == {'sample'}`).

- [ ] **Step 3: Wire the tools in use through the manager**

Save as `$W/task4_wiring.py`:

```python
"""Task 4: the tool manager carries the tools in use — built-in and plugin — and everything looks them up there.

Usage: python task4_wiring.py <repo root>
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from edit import Source  # noqa: E402

root = Path(sys.argv[1])

# -- the registry: a plugin's recipe under registry.yaml's keys ------------------------
registry = Source(root, "cyberfw/manager/registry.py")
registry.replace("from collections.abc import Iterator\n", "from collections.abc import Collection, Iterator, Mapping\n")
registry.replace(
    'def load_registry(path: Path | str) -> ToolRegistry:\n'
    '    """Parse a registry file into a :class:`ToolRegistry`."""\n',
    "def load_registry(\n"
    "    path: Path | str, *, overlays: Mapping[str, ToolSpec] | None = None, skip: Collection[str] = ()\n"
    ") -> ToolRegistry:\n"
    '    """Parse a registry file into a :class:`ToolRegistry`.\n'
    "\n"
    "    ``overlays`` are the install recipes of the plugin tools in use, by name: an\n"
    "    entry of the same name in the file is laid over its recipe key by key (to pin\n"
    "    a version, or point at a local binary), and a plugin tool the file does not\n"
    "    name keeps its recipe as it is. Entries named in ``skip`` — tools of plugins\n"
    "    not in use, whose entries may be such partial overlays — are left out.\n"
    '    """\n'
    "    overlays = overlays or {}\n",
)
registry.replace(
    "    for name, block in payload.items():\n"
    "        if not isinstance(block, dict):\n",
    "    for name, block in payload.items():\n"
    "        if str(name) in skip:\n"
    "            continue\n"
    "        if not isinstance(block, dict):\n",
)
registry.replace(
    "        try:\n"
    "            tools[name] = ToolSpec(**block, name=str(name))\n",
    "        base = overlays.get(str(name))\n"
    "        fields = {**base.model_dump(), **block} if base is not None else dict(block)\n"
    "        try:\n"
    "            tools[name] = ToolSpec(**{**fields, \"name\": str(name)})\n",
)
registry.replace(
    "            raise RegistryError(f\"invalid registry entry {name!r}: {exc}\") from exc\n"
    "    return ToolRegistry(tools)\n",
    "            raise RegistryError(f\"invalid registry entry {name!r}: {exc}\") from exc\n"
    "    for name, spec in overlays.items():\n"
    "        tools.setdefault(name, spec)\n"
    "    return ToolRegistry(tools)\n",
)
registry.save()

# -- the manager carries the tools in use ------------------------------------------------
manager = Source(root, "cyberfw/manager/__init__.py")
manager.replace(
    "import json\nimport tempfile\nfrom pathlib import Path\n",
    "import json\nimport tempfile\nfrom pathlib import Path\nfrom typing import TYPE_CHECKING\n",
)
manager.replace(
    "from cyberfw.manager.verify import ensure_binary, find_in_path\n",
    "from cyberfw.manager.verify import ensure_binary, find_in_path\n"
    "\n"
    "if TYPE_CHECKING:  # cyberfw.plugin and the tools import this package's registry module\n"
    "    from cyberfw.manager.plugins import PluginSet\n"
    "    from cyberfw.plugin import BaseTool, ToolPlugin\n",
)
manager.replace(
    "        *,\n"
    "        lock_path: Path | None = None,\n"
    "    ) -> None:\n"
    "        self.settings = settings\n"
    "        self.registry = registry\n",
    "        *,\n"
    "        lock_path: Path | None = None,\n"
    "        plugins: PluginSet | None = None,\n"
    "    ) -> None:\n"
    "        self.settings = settings\n"
    "        self.registry = registry\n"
    "        #: The plugin tools in use and every declared one's state; ``None`` without plugins.\n"
    "        self.plugins = plugins\n",
)
manager.replace(
    "    def spec(self, name: str) -> ToolSpec:\n"
    "        return self.registry.require(name)\n",
    "    def spec(self, name: str) -> ToolSpec:\n"
    "        if name not in self.registry:\n"
    "            reason = self.unavailable(name)\n"
    "            if reason is not None:\n"
    "                raise RegistryError(reason)\n"
    "        return self.registry.require(name)\n"
    "\n"
    "    # -- the tools in use ---------------------------------------------------------\n"
    "    @property\n"
    "    def tools(self) -> dict[str, ToolPlugin]:\n"
    '        """Every usable tool\'s description, by name: the built-in ones and the plugins\' in use."""\n'
    "        from cyberfw.tools import BUILTIN  # the tools import this package's registry module\n"
    "\n"
    "        return {**BUILTIN, **(self.plugins.tools if self.plugins is not None else {})}\n"
    "\n"
    "    def unavailable(self, name: str) -> str | None:\n"
    '        """Why a plugin tool cannot be used, as a sentence; ``None`` for any other name."""\n'
    "        return self.plugins.unavailable(name) if self.plugins is not None else None\n"
    "\n"
    "    def adapter_class(self, name: str) -> type[BaseTool]:\n"
    '        """``name``\'s adapter class — for what it knows before a binary exists (prompts,\n'
    '        target validation). :class:`RegistryError` when no usable tool has the name."""\n'
    "        tool = self.tools.get(name)\n"
    "        if tool is None:\n"
    "            raise RegistryError(self.unavailable(name) or f\"no adapter registered for tool {name!r}\")\n"
    "        return tool.adapter\n"
    "\n"
    "    def adapter_for(self, name: str, binary: Path) -> BaseTool:\n"
    '        """``name``\'s adapter on its recipe and installed ``binary``, reading its lines\n'
    '        with the record model its description names."""\n'
    "        adapter = self.adapter_class(name)(self.spec(name), binary)\n"
    "        adapter._record = self.tools[name].record\n"
    "        return adapter\n",
)
manager.replace(
    "from cyberfw.exceptions import CyberfwError, DownloadError, LockError, ToolNotFoundError\n",
    "from cyberfw.exceptions import (\n"
    "    CyberfwError,\n"
    "    DownloadError,\n"
    "    LockError,\n"
    "    RegistryError,\n"
    "    ToolNotFoundError,\n"
    ")\n",
)
manager.replace(
    "        if names is None:\n"
    "            for gone in sorted(set(tools) - set(downloadable)):\n",
    "        if names is None:\n"
    "            # A disabled plugin's tool is not gone: its pin stays for when it is enabled again.\n"
    "            declared = self.plugins.declared() if self.plugins is not None else frozenset()\n"
    "            for gone in sorted(set(tools) - set(downloadable) - declared):\n",
)
manager.save()

# -- a tool's own record model, from its description -------------------------------------
contract = Source(root, "cyberfw/plugin.py")
contract.replace(
    "    #: Prompt for a secondary input (e.g. a wordlist); ``None`` = nothing to ask.\n"
    "    extra_input_prompt: ClassVar[str | None] = None\n",
    "    #: Prompt for a secondary input (e.g. a wordlist); ``None`` = nothing to ask.\n"
    "    extra_input_prompt: ClassVar[str | None] = None\n"
    "\n"
    "    #: The model this tool's lines validate against — set by the tool manager from the\n"
    "    #: tool's description; without one, the model is looked up by the tool's name.\n"
    "    _record: type[ToolRecord] | None = None\n",
)
contract.replace(
    '    def parse_line(self, line: str, lineno: int) -> ToolRecord:\n'
    '        """Validate one JSONL stdout line for this tool."""\n'
    "        return validate_record(self.name, line, lineno)\n",
    '    def parse_line(self, line: str, lineno: int) -> ToolRecord:\n'
    '        """Validate one JSONL stdout line for this tool, with its record model."""\n'
    "        if self._record is not None:\n"
    "            return self._record.from_json(self.name, line, lineno)\n"
    "        return validate_record(self.name, line, lineno)\n",
)
contract.save()

# -- opening the manager: the plugins in use, their recipes under registry.yaml -----------
workspace = Source(root, "cyberfw/core/workspace.py")
workspace.replace(
    "from cyberfw.manager.lock import LOCK_NAME\n",
    "from cyberfw.manager.lock import LOCK_NAME\nfrom cyberfw.manager.plugins import load_plugins\n",
)
workspace.replace(
    "from cyberfw.resources import packaged_data\n",
    "from cyberfw.resources import packaged_data\nfrom cyberfw.tools import BUILTIN\n",
)
workspace.replace(
    'def open_manager(settings: Settings) -> ToolManager:\n'
    '    """A :class:`ToolManager` over the registry in use, with ``tools.lock`` next to it."""\n'
    "    path = registry_path()\n"
    "    return ToolManager(settings, load_registry(path), lock_path=path.with_name(LOCK_NAME))\n",
    'def open_manager(settings: Settings) -> ToolManager:\n'
    '    """A :class:`ToolManager` over the registry in use — with the plugin tools in use,\n'
    "    their recipes under its entries of the same name — and ``tools.lock`` next to it.\"\"\"\n"
    "    path = registry_path()\n"
    "    plugins = load_plugins(settings)\n"
    "    overlays = {name: tool.install for name, tool in plugins.tools.items() if tool.install is not None}\n"
    "    skip = plugins.declared() - set(plugins.tools) - set(BUILTIN)\n"
    "    registry = load_registry(path, overlays=overlays, skip=skip)\n"
    "    return ToolManager(settings, registry, lock_path=path.with_name(LOCK_NAME), plugins=plugins)\n",
)
workspace.save()

# -- every lookup goes through the manager --------------------------------------------------
scan = Source(root, "cyberfw/core/scan.py")
scan.replace("from cyberfw.tools import adapter_class\n", "")
scan.replace(
    "        requirement = adapter_class(node.tool).missing_requirement(tools_dir)\n",
    "        requirement = manager.adapter_class(node.tool).missing_requirement(tools_dir)\n",
)
scan.replace("        manager.spec(node.tool)\n        adapter_class(node.tool)\n", "        manager.spec(node.tool)\n        manager.adapter_class(node.tool)\n")
scan.save()

tool_run = Source(root, "cyberfw/core/tool_run.py")
tool_run.replace("from cyberfw.tools import adapter_class\n", "")
tool_run.replace("        adapter_class(tool).validate_target(target)\n", "        manager.adapter_class(tool).validate_target(target)\n")
tool_run.save()

engine = Source(root, "cyberfw/pipeline/engine.py")
engine.replace(
    "    def build_tool(self, name: str) -> BaseTool:\n"
    "        from cyberfw.tools import adapter_for\n"
    "\n"
    "        spec = self.tool_manager.spec(name)\n",
    "    def build_tool(self, name: str) -> BaseTool:\n"
    "        spec = self.tool_manager.spec(name)\n",
)
engine.replace("        return adapter_for(spec, binary)\n", "        return self.tool_manager.adapter_for(name, binary)\n")
engine.save()

launcher = Source(root, "cyberfw/cli/launcher.py")
launcher.replace("from cyberfw.tools import adapter_class\n", "")
launcher.replace(
    "    adapter = adapter_class(tool)\n",
    "    _settings, manager = _bootstrap()\n"
    "    try:\n"
    "        adapter = manager.adapter_class(tool)\n"
    "    finally:\n"
    "        manager.close()\n",
)
launcher.save()

tools_cmd = Source(root, "cyberfw/cli/tools.py")
tools_cmd.replace(
    "        manager = ToolManager(settings, manager.registry, manager.mapping, lock_path=manager.lock_path)\n",
    "        manager = ToolManager(\n"
    "            settings, manager.registry, manager.mapping, lock_path=manager.lock_path, plugins=manager.plugins\n"
    "        )\n",
    count=2,
)
tools_cmd.save()

# -- the CLI test that registers a new tool does so as a description ----------------------
cli_test = Source(root, "tests/unit/test_cli.py")
cli_test.replace(
    "        from cyberfw.plugin import BaseTool\n        from cyberfw.tools import ADAPTERS\n",
    "        from cyberfw.plugin import BaseTool, ToolPlugin, ToolRecord\n        from cyberfw.tools import BUILTIN\n",
)
cli_test.replace(
    '        monkeypatch.setitem(ADAPTERS, "planetscan", PlanetScan)\n',
    '        monkeypatch.setitem(BUILTIN, "planetscan", ToolPlugin(contract=1, adapter=PlanetScan, record=ToolRecord))\n',
)
cli_test.save()
```

```bash
uv run --quiet python "$W/task4_wiring.py" .
```

Expected: `edited` lines for `cyberfw/manager/registry.py`, `cyberfw/manager/__init__.py`, `cyberfw/plugin.py`, `cyberfw/core/workspace.py`, `cyberfw/core/scan.py`, `cyberfw/core/tool_run.py`, `cyberfw/pipeline/engine.py`, `cyberfw/cli/launcher.py`, `cyberfw/cli/tools.py` and `tests/unit/test_cli.py`.

- [ ] **Step 4: Run the tests to see them pass**

```bash
uv run --quiet python -m pytest tests/unit/test_plugin_tools.py -q -p no:cacheprovider
```

Expected: `7 passed`.

- [ ] **Step 5: The whole suite, lint, types, and the output**

```bash
uv run --quiet python -m pytest -q
uv run --quiet ruff check .
uv run --quiet mypy cyberfw
```

Expected: `1237 passed, 5 skipped, 8 deselected`; `All checks passed!`; `Success: no issues found in 79 source files`.

```bash
cp "$W/test_zz_capture.py" tests/unit/ && COLUMNS=250 CAPTURE_DIR="$W/transcripts/4-tools" uv run --quiet python -m pytest tests/unit/test_zz_capture.py -q -p no:cacheprovider; rm tests/unit/test_zz_capture.py
diff -r "$W/transcripts/0-base" "$W/transcripts/4-tools" && echo identical
```

Expected: `50 passed`, then `identical`. (If the only difference is an `elapsed <dur> (1m…s)` line, the machine was loaded enough for a stage to pass a minute — capture again into an empty directory.)

- [ ] **Step 6: Commit and push**

```bash
git add cyberfw/manager/registry.py cyberfw/manager/__init__.py cyberfw/plugin.py cyberfw/core/workspace.py cyberfw/core/scan.py cyberfw/core/tool_run.py cyberfw/pipeline/engine.py cyberfw/cli/launcher.py cyberfw/cli/tools.py tests/unit/test_cli.py tests/unit/test_plugin_tools.py
git commit -m "Carry the tools in use on the tool manager: plugin tools run, plan and lock like built-in ones"
git push origin main
```
