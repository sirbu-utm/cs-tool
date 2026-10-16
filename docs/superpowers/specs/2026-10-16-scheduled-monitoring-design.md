# Scheduled monitoring: `schedule` + `--alert`

Date: 2026-10-16
Status: design, pending review

## Goal

Turn cyberfw from a one-shot scanner into something that watches a target
over time and tells you — locally — when something new shows up, without any
new long-running process and without sending anything to the outside world.

Two independent, composable pieces:

- `cyberfw pipeline … --alert` — the scan signals "new findings" through its
  exit code and a log line.
- `cyberfw schedule …` — generates (and, with `--install`, installs) an
  OS-scheduler entry that runs such a scan on a recurring basis.

## Decisions (settled)

- **Runner:** the OS scheduler (cron on Linux/macOS, Task Scheduler on
  Windows). No daemon, no bot dependency. Survives reboots.
- **Alert channel:** local only — a nonzero exit code and a log line. Nothing
  is sent to Telegram, a webhook, email, etc. (Those can be a later feature.)
- **Install depth:** `schedule` *generates* the entry by default and prints
  it; `--install` applies it. `--install`/`--remove` are the only code paths
  that touch system state.
- **Default severity threshold:** `low` (any real finding). **No `schedule
  list` in v1.** `--alert` lives on `pipeline` only, not `run`.

## Part A — `cyberfw pipeline … --alert`

### Options (new, on `pipeline_cmd`)

- `--alert / --no-alert` (default off). When on, the run's exit code reflects
  whether new findings appeared.
- `--alert-severity <low|medium|high|critical>` (default `low`). The lowest
  severity that counts as alert-worthy. (`info`/unknown findings never alert —
  they are noise for monitoring — so the threshold is one of the REAL levels.)

### Behaviour

The scan runs exactly as today. It already computes `changes: RunDiff | None`
(the comparison against the newest earlier *saved* run of the same seed +
pipeline, unless `--no-baseline`). After the summary panel:

- If `--alert` and `changes` is not `None` and the number of **newly added
  findings at or above the threshold** is > 0:
  - print one line: `ALERT: N new finding(s) ≥ <severity> since <session-id>`
    (themed `err`), and
  - exit with code **3**.
- Otherwise `--alert` changes nothing (exit 0, or 1 if a stage failed — see
  exit codes).

Edge cases:

- **First scan of a target** (no baseline found) → `changes is None` → nothing
  is "new" → exit 0. Alerts are about *change*, so the first run never alerts.
- **`--no-baseline` with `--alert`** → contradictory (no baseline to compare).
  Treat as a usage error: exit 2 with a one-line explanation, before scanning.
- **A stage failed** (`result.succeeded()` is false) → that already exits 1.
  Run-failure (1) takes precedence over alert (3): a broken scan is reported
  as broken, not as "nothing new". So: compute the alert, but if the run
  failed exit 1; else if alert fired exit 3; else exit 0.
- Alerting compares against the last **saved** run, so a watched scan must
  save its report (the default). `--no-report` + `--alert` still works for the
  current run but leaves no baseline for the next one; no special handling.

### Threshold logic (in `report/diff.py`, where the diff is tested)

Add to `RunDiff`:

```python
def new_findings_at_least(self, level: str) -> int:
    """Newly added findings whose severity is `level` or worse.

    `level` is one of REAL (critical/high/medium/low). Unknown/info never
    count. Mirrors `new_findings` (which is the `low` case)."""
```

Implementation counts `changes` where `area == "finding"`, `status ==
"added"`, and the severity ranks at or above `level` using the existing
`REAL` ordering (`critical` < `high` < `medium` < `low`). `new_findings`
stays as the `low` shorthand.

## Part B — `cyberfw schedule`

### Signature

```
cyberfw schedule <pipeline> -t/--target <target>
    [--every daily|weekly|hourly]      # default daily
    [--at HH:MM]                       # default 09:00; ignored for hourly
    [--cron "<m h dom mon dow>"]       # raw cron, overrides --every/--at (POSIX only)
    [--ffuf] [--gowitness] [--wordlist …] [--no-mail] [--no-intel] [--no-vt]
    [--alert-severity <level>]         # passed through to the scan
    [--install]                        # apply the entry instead of only printing
    [--remove]                         # delete the installed entry of the same identity
```

The pipeline/target and scan flags are the same ones `pipeline` takes; the
generated command is `cyberfw pipeline <name> -t <target> --alert
[--alert-severity …] [flags]`.

### What it generates

The invocation embeds the current workspace so the scheduled run finds the
same registry/tools/reports:

- program: the installed `cyberfw` if resolvable (`shutil.which`), else
  `"<python> -m cyberfw"` (`sys.executable`);
- environment: `CYBERFW_ROOT_DIR=<cwd>` so it uses this workspace from
  wherever the scheduler runs it;
- output: appended to `<logs_dir>/schedule.log`.

Per OS (from `manager.mapping` / `os.name`):

- **POSIX (Linux, macOS):** a crontab line
  `` <m> <h> <dom> <mon> <dow> cd <root> && CYBERFW_ROOT_DIR=<root> <cmd> >> <log> 2>&1 ``
  (macOS uses cron too; launchd is out of scope.)
- **Windows:** a `schtasks /Create` command
  `schtasks /Create /SC DAILY /ST 09:00 /TN "<task-name>" /TR "<cmd>" /F`
  with `/SC WEEKLY /D MON` for weekly and `/SC HOURLY` for hourly.

`--cron` is POSIX-only (Task Scheduler has no equivalent string); on Windows
it is a usage error.

### Task identity

A stable name/tag derived from pipeline + target, e.g.
`cyberfw-<pipeline>-<sanitised-target>`. On cron it is carried as a trailing
`# <tag>` comment on the line; on Windows it is the `/TN` task name. This lets
`--install` replace an existing entry (cron: drop any line with the same tag,
then append; `schtasks … /F` overwrites) and `--remove` delete it (cron:
filter the tag line out of `crontab -l` and pipe back; `schtasks /Delete /TN
<name> /F`).

### Install / remove

- Default (no `--install`): print the entry and a one-line how-to; touch
  nothing.
- `--install`: apply it (cron: `crontab -l` → edit → `crontab -`; Windows: run
  the `schtasks` command), then print what was installed.
- `--remove`: delete the entry of that identity; report whether one was there.

## Module layout

- **`cyberfw/schedule.py`** (new): pure generation + a thin system shim.
  - `Schedule` dataclass (pipeline, target, cadence, time, extra scan args).
  - `cron_line(schedule, *, command, tag, log) -> str`
  - `schtasks_command(schedule, *, command, tag, log) -> list[str]`
  - `cron_expr(every, at) -> str` (daily/weekly/hourly + HH:MM → 5-field)
  - `scan_command(schedule, *, program, root) -> str` (the inner cyberfw call)
  - `install(entry)` / `remove(tag)` — call `crontab`/`schtasks`; isolated so
    tests mock the subprocess boundary. Everything above is pure strings.
- **`cyberfw/report/diff.py`**: add `RunDiff.new_findings_at_least`.
- **`cyberfw/cli.py`**: `--alert` / `--alert-severity` on `pipeline_cmd`; the
  alert decision + exit-code logic at the end of the run; a new
  `@app.command("schedule")` that wires options to `cyberfw/schedule.py` and
  prints or installs.
- **`registry.yaml` / adapters:** unchanged.

## Exit codes (pipeline)

| code | meaning |
|------|---------|
| 0 | ran; nothing new above the threshold (or `--alert` off) |
| 1 | a stage failed (unchanged; takes precedence over 3) |
| 2 | usage error — e.g. `--alert` with `--no-baseline`, `--cron` on Windows |
| 3 | `--alert`: new findings at or above the threshold |

## Testing (TDD)

- **diff.py:** `new_findings_at_least` — a hand-built `RunDiff` with added
  findings across severities; assert counts for each threshold; info/unknown
  never count; equals `new_findings` at `low`.
- **pipeline `--alert`:** drive `runner.invoke` with fake tools (as the suite
  already does) over two saved runs where the second adds a `high` finding:
  assert exit code 3 and the `ALERT:` line; a run with nothing new → exit 0;
  `--alert-severity critical` when only a `high` appeared → exit 0; first scan
  → exit 0; `--alert` + `--no-baseline` → exit 2; a failed stage + new finding
  → exit 1 (failure wins).
- **schedule generation (pure):** `cron_expr` for daily/weekly/hourly + `--at`;
  `cron_line` carries the tag comment, the workspace `cd`/env and the log
  redirect; `schtasks_command` maps cadence to `/SC` and quotes `/TR`; `--cron`
  overrides; `--cron` on Windows → usage error; target sanitised in the tag.
- **schedule install/remove:** mock the `crontab`/`schtasks` boundary; assert
  replace-by-tag (no duplicate lines), remove filters the tag line, and the
  default (no `--install`) runs no subprocess and only prints.
- Full suite, `ruff`, `mypy --strict`. README + CHANGELOG updated.

## Out of scope (v1)

- `schedule list`; reading back all installed entries.
- `--alert` on `run`.
- External alert channels (Telegram / webhook / email).
- A cyberfw daemon / `watch` process.
- macOS launchd (cron is used there).
