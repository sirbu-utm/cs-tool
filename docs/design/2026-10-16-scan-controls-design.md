# Scan controls: nuclei severity/tags, scope excludes, rate-limit

Date: 2026-10-16
Status: design, pending review

## Goal

Make a scan more targeted and more considerate: run nuclei only for the
severities/tags you care about, keep agreed out-of-scope hosts untouched, and
cap request rate. All three are optional and off by default (today's behaviour
is unchanged when no control is set).

## Decisions (settled)

- Controls live in `Settings` (so they work via `CYBERFW_*`, `config.local.yaml`
  and CLI flags, like `concurrency`/`parse`), and CLI flags override settings.
- `--exclude` is glob flags + the `exclude` setting; no separate scope file in
  v1. Excludes filter only **discovered** hosts — the explicit seed is kept.
- `--severity` / `--tags` / `--rate-limit` go on both `pipeline` and `run`
  (for the single tools that support them); `--exclude` is `pipeline`-only.

## Settings (new fields)

- `severity: str = ""` — comma list for nuclei `-severity` (e.g. `critical,high`).
- `tags: str = ""` — comma list for nuclei `-tags` (e.g. `cve,exposure`).
- `rate_limit: int | None = None` (ge=1) — max requests/sec, mapped to each
  tool's own flag.
- `exclude: list[str] = []` — fnmatch globs of hostnames to skip.

All optional; empty/None means "no control", exactly as now.

## How controls reach the tools

A small value object carries the per-tool knobs to every stage:

```python
# cyberfw/tools/base.py
@dataclass(frozen=True)
class ScanControls:
    rate_limit: int | None = None
    severity: str = ""
    tags: str = ""
```

`ToolContext` gains `controls: ScanControls = field(default_factory=ScanControls)`.
The engine fills it from settings (`PipelineEngine._controls()`) and passes it
through every `ToolContext` it builds (`_run_node`, `_dispatch`'s run_ctx,
`_fan_out`). Each adapter reads what it understands in `build_cmd`; the rest
ignore it:

- **nuclei:** `-severity <list>`, `-tags <list>`, `-rate-limit <n>`.
- **httpx:** `-rate-limit <n>`.
- **naabu:** `-rate <n>`.
- **ffuf:** `-rate <n>`.
- subfinder / rustscan / gowitness / gitleaks: ignore (no applicable flag).

A control left empty/None adds no flag, so commands are byte-for-byte the same
as today when nothing is set (the existing adapter tests stay valid).

## Scope excludes

`in_scope(target, excludes)` — a discovered target is out of scope when
`fnmatch(hostname_of(target), pattern)` matches any `--exclude` pattern (case-
insensitive, `*` wildcard — the same shape as triage targets).

Applied in `PipelineEngine.run`, where discovered targets are threaded to the
next stage (`inputs = [r.target for r in step_records]`): excluded targets are
dropped from what downstream stages receive, so they are never scanned. The
discovery record itself is kept (subfinder still reports the host); only the
**downstream scanning** of it is skipped. The seed is never filtered.

Excluded hostnames are collected on `PipelineResult.excluded: list[str]`
(deduped, in order); `pipeline_cmd` prints `scope: N host(s) excluded` when
non-empty, and the count rides into the run summary. (A single `run` has one
explicit target and no discovery, so `--exclude` is not offered there.)

## CLI

- `pipeline`: `--severity`, `--tags`, `--rate-limit` (int, min 1),
  `--exclude` (repeatable glob).
- `run`: `--severity`, `--tags`, `--rate-limit`.
- Each provided flag overrides the setting for that run
  (`settings.model_copy(update=...)`, only for flags actually passed — an
  unset flag leaves the setting/env/YAML value in place). Help text names which
  tools each control reaches.

## Module touch-list

- `cyberfw/config.py`: four new `Settings` fields.
- `cyberfw/tools/base.py`: `ScanControls`; `ToolContext.controls`.
- `cyberfw/tools/{nuclei,httpx_tool,naabu,ffuf}.py`: read `ctx.controls`.
- `cyberfw/pipeline/engine.py`: `_controls()`; pass controls into every
  `ToolContext`; scope filter in `run`; `PipelineResult.excluded`.
- `cyberfw/cli.py`: flags on `pipeline_cmd` / `run_cmd`; settings override;
  print the excluded-count line.

## Testing (TDD)

- **Settings:** the four fields default to off; `CYBERFW_RATE_LIMIT` /
  `CYBERFW_SEVERITY` etc. are read; `rate_limit` rejects < 1.
- **Adapters (build_cmd with controls):** nuclei adds `-severity`/`-tags`/
  `-rate-limit` when set and nothing when unset; httpx/naabu/ffuf add their
  rate flag; a tool with no applicable control is unchanged. (Mutation check:
  an empty control must add no argument.)
- **Scope:** `in_scope` matches on hostname with globs; the engine drops an
  excluded discovered host from downstream inputs while keeping its discovery
  record, records it in `PipelineResult.excluded`, and never filters the seed;
  an end-to-end `pipeline --exclude "*.dev.example.com"` run over fake tools
  shows the excluded host in discovery but not scanned downstream, exit 0 with
  the `scope: …` line.
- **CLI:** each flag overrides the setting; `--rate-limit 0` is a usage error;
  `run --severity high` reaches nuclei.
- Full suite, `ruff`, `mypy --strict`. README + CHANGELOG updated.

## Out of scope (v1)

- A scope *file* / allow-list (only exclude globs + the setting).
- Per-tool distinct rate limits (one `--rate-limit` maps to each tool's flag).
- Applying excludes to a single `run`, or to the seed.
- nuclei template paths / `-exclude-templates` and other nuclei knobs beyond
  severity/tags.
