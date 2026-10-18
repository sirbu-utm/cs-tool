# Core API and CLI split

Date: 2026-10-18
Status: design, pending review
Roadmap: 2.0, item 1a (item 1b — tool adapters as entry-point plugins — follows)

## Goal

`cyberfw/cli.py` (2855 lines, 101 top-level definitions, 13 commands) mixes
argument parsing, Rich rendering, prompts and the orchestration of a run
itself: `pipeline_cmd` alone is 349 lines of pre-flight, session handling, the
engine run, the post-scan steps, triage, the comparison with an earlier run,
report writing and the exit code, interleaved with spinners and questions.

Split it into:

- a **core** that prepares, executes and finalises runs without printing,
  prompting or exiting;
- a small, **stable public API** for the user's own scripts and CI;
- a **CLI package** of focused modules that parses flags, asks questions and
  renders — and runs pipelines through the public API itself.

The behaviour of every command — flags, output, exit codes — stays as it is.

Success: the suite passes after every step with only import paths changed in
the tests; `import cyberfw.api` never loads the CLI; a script can run a
pipeline and get a structured result while nothing is printed.

## Decisions (settled)

- **Consumers:** the user's scripts and CI. The API is synchronous, returns
  results as data, reports progress through optional observer callbacks, and
  never prints, prompts or calls `sys.exit`.
- **Stable surface (semver):** runs and saved runs — `run_pipeline`,
  `plan_pipeline`, `run_tool`, `load_run`, `compare_runs`, `export_sarif`,
  `export_csv` and their result types. `cyberfw.core.*` and `cyberfw.cli.*`
  are internal.
- **Approach:** step by step, behaviour-preserving — (1) the CLI becomes a
  package by moving code, (2) the orchestration moves into the core, (3) the
  API facade goes on top. The suite stays green after each step.

## Layers and the dependency rule

```
cyberfw/api.py      public facade (stable)
cyberfw/core/       orchestration, no UI
cyberfw/cli/        Typer commands, prompts, Rich rendering
existing domain modules: pipeline/, pipelines/, manager/, posture/, report/,
                         threatintel, vt, triage, schedule, config, …
```

- `core` and `api` import domain modules only. They never import
  `cyberfw.cli`, `typer`, the presentation modules (`cyberfw.ui`, `hud`,
  `live_view`, `motion`) or the shared Rich `console`.
- `cli` imports `api`, `core`, the domain modules and the presentation modules.
- Tests enforce it: an AST check over `core/*.py` and `api.py` for forbidden
  imports, and a subprocess check that `import cyberfw.api` leaves
  `cyberfw.cli` and `typer` out of `sys.modules`.

## Step 1 — the CLI package (move only)

`cyberfw/cli.py` becomes `cyberfw/cli/`:

| module | contents |
|--------|----------|
| `app.py` | the Typer `app` object (so command modules can register on it) |
| `__init__.py` | re-exports `app`, imports the command modules so they register |
| `__main__.py` | `app()` — keeps `python -m cyberfw.cli` working |
| `common.py` | `_bootstrap`, registry/lock path resolution, shared options (`VerboseOption`), `_is_interactive`, `_live_fps`, `_after_live`, screen helpers |
| `views.py` | Rich renderers: record table, run summary, findings pane, plan view, status view, tool menu and cards, change list |
| `tools.py` | `init`, `lock`, `doctor`/`status`, `prepare`; install progress, Chromium provisioning, lock table, `_ensure_tools` |
| `scan.py` | `run`, `pipeline`, `vt` and their flag handling |
| `reports.py` | `diff`, `export` |
| `triage.py` | `mute`, `unmute`, `mutes` |
| `schedule.py` | `schedule` |
| `launcher.py` | interactive menu, help card, prompts, Tab-completion wiring |

Rules for this step: code moves verbatim and private helpers keep their
names; only imports change. Import order avoids cycles: `app`, `common` ←
`views` ← command modules ← `launcher`; `__init__` imports the command modules
last. The entry points (`cyberfw`, `cs-tool`, `cstool` → `cyberfw.cli:app`)
are untouched. Tests change `from cyberfw.cli import …` and the
`"cyberfw.cli.…"` monkeypatch targets (about 30 imports, 20 targets) to the new
modules.

## Step 2 — the core

`cyberfw/core/`:

- `workspace.py` — `registry_path()` (current directory → checkout → packaged
  copy, as today), `open_manager(settings) -> ToolManager` with the lock next
  to that registry, `is_packaged(path)`. No logging set-up: the CLI does that.
- `sessions.py` — `session_tag(kind, name)`, `checked_session(name)` (raises
  `ValueError` for anything but a plain directory name), `discard_session(dir,
  created)`.
- `events.py` — the observer:

  ```python
  class RunObserver:            # every method is a no-op by default
      def on_stage(self, event: StageEvent) -> None: ...
      def on_record(self, record: ToolRecord) -> None: ...
      def on_output(self, line: str, stream: str) -> None: ...   # "stdout" | "stderr"
      def on_step(self, event: StepEvent) -> None: ...
      def on_note(self, note: Note) -> None: ...

  @dataclass(frozen=True)
  class StepEvent:
      kind: Literal["start", "advance", "done"]
      step: str                          # "tls" | "mail" | "takeover" | "intel" | "vt"
      total: int | None = None           # units of work, when known (takeover hosts, VT lookups)
      summary: StepSummary | None = None # on "done": that step's own result object

  @dataclass(frozen=True)
  class Note:
      level: Literal["info", "warn"]
      text: str
  ```

  `StepSummary` is the union of the steps' result objects (`TlsSummary`,
  `MailSummary`, `TakeoverSummary`, `IntelSummary`, `VtSummary`), each holding
  the counts and verdicts the CLI prints today.

- `runs.py` — the orchestration, moved out of `cli.py`:
  - `prepare_pipeline(...) -> PreparedPipeline` — build the node list, check
    every tool is registered and has an adapter, pre-flight (`_preflight`,
    `_resolve_gowitness`, `_tool_state`).
  - `execute_pipeline(...)` — the engine run wired to the observer.
  - Post-scan steps, each appending records as today and returning a summary
    instead of printing one: `check_tls`, `check_mail`, `check_takeover`,
    `rate_cves`, `enrich_vt`. A failing step becomes a warning `Note`; it never
    fails the scan.
  - `finalize(...)` — triage, run info, comparison with an earlier run and
    report writing (`_apply_triage`, `_run_info`, `_compare_with_earlier`,
    `_write_reports`). The alert count and exit code (`_pipeline_exit_code`)
    become methods of the API's `RunOutcome`.
  - `run_tool_once(...)` — the logic of `run_cmd`.

Every line these helpers print today either becomes a returned summary that
`cli/views.py` renders with the same wording, or a `Note`.

## Step 3 — the public API (`cyberfw/api.py`)

```python
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
) -> RunOutcome

def plan_pipeline(name, target=None, *, settings=None, ffuf=False, gowitness=None, max_httpx=0) -> Plan

def run_tool(
    tool, *, target=None, inputs=(), wordlist=None, settings=None,
    severity="", tags="", rate_limit=None, parse=True,
    session=None, save=False, observer=None,
) -> RunOutcome

def load_run(ref: str | Path, *, settings: Settings | None = None) -> SavedRun   # session id, its directory or report.json
def compare_runs(old: SavedRun, new: SavedRun) -> RunDiff
def export_sarif(run: SavedRun) -> dict[str, Any]
def export_csv(run: SavedRun) -> str
```

- `settings=None` loads settings exactly as the CLI does. The scan controls
  (`severity`, `tags`, `rate_limit`, `exclude`) override them for this call
  only.
- VirusTotal enrichment happens only when `vt_key` is passed. The API never
  looks for a key on its own and never asks for one; the CLI keeps its prompt
  and passes the result.
- `save` decides whether the run's reports are kept. A callable is asked after
  the scan and before reports are written — the CLI passes its "Save the
  report?" question. When not saved, a session directory this call created is
  removed, as today.
- Result types:
  - `RunOutcome` — `result` (`PipelineResult`: nodes, records, excluded
    hosts, timing), `run` (`RunInfo`), `session_id`, `session_dir`, `reports`
    (`{"json": Path, "html": Path}` or empty), `changes` (`RunDiff | None`),
    `notes`; `succeeded`, `alert_hits(severity="low")` and
    `exit_code(alert_severity=None)` (1 for a failed run, 3 for new findings
    at or above `alert_severity` when given, else 0 — today's rules).
  - `Plan` — `name`, `target`, `stages` (index, tool, stage, consumes, tool
    state, per-stage options), `blocking` (stage, tool, reason), `warnings`,
    `ready`.
  - `SavedRun` — `path` (its `report.json`) and `payload`.
- Errors are typed: `RegistryError` (unknown pipeline or tool, or a YAML
  pipeline naming one), `ValueError` (a target the tool does not take, a
  non-plain session name, an unknown alert severity), a new
  `PreflightError(CyberfwError)` carrying `blocking` when stages cannot run and
  `force_start` is false, `ToolNotFoundError` (`run_tool` with an uninstalled
  tool), `FileNotFoundError` / `ValueError` from `load_run`. The CLI maps them
  to today's messages and exit codes (2 for usage and pre-flight, 1 for
  runtime failures).
- The CLI's `pipeline`, `run`, `pipeline --plan`, `diff` and `export` go
  through this API, so the facade is exercised by every existing CLI test.
  Install, lock, triage and schedule stay on the core and manager directly.

## Testing

- After each step: full suite, `ruff`, `mypy --strict`. The existing CLI tests
  are the characterisation tests; they change only import paths.
- New API tests, offline with the fake tool binaries the CLI tests already use:
  - `run_pipeline` returns nodes, records and report paths; the observer gets
    stage, record and step events; stdout and stderr stay empty (`capsys`);
    `exit_code` gives 1 for a failed stage and 3 for new findings with
    `alert_severity`; `save=False` and a `save` callable returning False leave
    no new session directory.
  - `plan_pipeline` lists stages, blocking stages and `ready`.
  - `run_tool` returns records; `save=False` writes nothing.
  - `load_run` → `compare_runs` → `export_sarif` / `export_csv` on saved runs.
  - The dependency-rule checks above.
- README gets a short "Python API" section with an example; CHANGELOG notes
  the API and the package split.

## Compatibility

- Entry points and `python -m cyberfw.cli` keep working.
- No change to settings, `registry.yaml`, `tools.lock`, pipelines or report
  formats.

## Out of scope

- Tool adapters as entry-point plugins (item 1b).
- An async API, cancellation, or event streams beyond the observer callbacks.
- Moving the presentation modules (`hud`, `live_view`, `motion`, `ui`) into
  `cli/`.
- New CLI features or flag changes.
