# Export a saved run to SARIF and CSV

Date: 2026-10-17
Status: design, pending review

## Goal

Get a run's findings out of cyberfw's own JSON/HTML into the two formats other
tools expect: **SARIF** (so GitHub code scanning / a CI gate can ingest the
vulnerabilities) and **CSV** (so a run can be triaged in a spreadsheet). Read
from a *saved* `report.json`, so any past run re-exports without re-scanning.

## Decisions (settled)

- One standalone command, `cyberfw export <run> --sarif|--csv [-o FILE]`; no
  scan-time `--sarif/--csv` flags in v1.
- SARIF carries only the findings (problems); CSV is a flat table of every
  record.
- Default output is stdout (pipe-friendly); `-o FILE` writes a file instead.

## Command

```
cyberfw export <run> (--sarif | --csv) [-o/--output FILE]
```

- `<run>`: a session id, its directory, or a path to `report.json` — resolved
  with the existing `rundiff.resolve_report` / `load_report` (same as `diff`).
- Exactly one of `--sarif` / `--csv` is required; neither or both is a usage
  error (exit 2).
- No `-o` → write the document to stdout with a plain `print` (not the themed
  console, so JSON/CSV is emitted verbatim). `-o FILE` → write the file and
  print a one-line confirmation to the console.
- Unreadable / missing run → exit 2 with the loader's message (as `diff`).

## SARIF (`cyberfw/report/sarif.py`, `to_sarif(payload: dict) -> dict`)

SARIF 2.1.0. Only **findings** become results — a saved record is a finding
when its `kind` is `vuln` (nuclei and the posture checks — TLS, mail, takeover —
all store `kind: "vuln"`) or `secret` (gitleaks). Hosts, ports, HTTP probes,
screenshots and scan summaries are not problems and are left out.

Shape:

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [{
    "tool": {"driver": {
      "name": "cyberfw",
      "version": "<run.cyberfw_version or package version>",
      "informationUri": "https://github.com/sirbu-utm/cs-tool",
      "rules": [{"id": "<ruleId>", "name": "<finding name>"}]   // deduped by id
    }},
    "results": [{
      "ruleId": "<id>",
      "level": "error|warning|note",
      "message": {"text": "<finding name>[ — description]"},
      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "<where>"}}}]
    }]
  }]
}
```

Per-record mapping from the saved dict:

- **vuln** (`kind == "vuln"`): `ruleId` = `template_id` (or `"unknown"`);
  `level` from `info.severity` — `critical`/`high` → `error`, `medium` →
  `warning`, `low`/`info`/`unknown`/absent → `note`; message = `info.name`
  (falling back to the id), plus `info.description` after an em dash when
  present; `uri` = `matched_at` or `target`.
- **secret** (`kind == "secret"`): `ruleId` = `rule_id` (or `"secret"`);
  `level` = `error` (a leaked secret is actionable); message = `description`
  (falling back to `rule_id`); `uri` = `target` (the file path).

`rules` is the set of `{id, name}` seen in the results, deduped by id, first
name wins. A muted finding is still exported (muting is cyberfw's own triage,
not a SARIF concept) — out of scope to filter here.

## CSV (`cyberfw/report/csv_report.py`, `to_csv(payload: dict) -> str`)

Every record, one row, written with the stdlib `csv` module (CRLF, quoting as
needed). Columns:

| column | value |
|--------|-------|
| `tool` | `tool` |
| `kind` | `kind` |
| `severity` | `info.severity` if present, else `severity`, else `""` |
| `target` | `target` |
| `detail` | first non-empty of `info.name`, `description`, `title`, else `""` |
| `muted` | `true`/`false` from `bool(muted)` |

Tool-agnostic via `.get`, so a new record type needs no change here.

## Module touch-list

- `cyberfw/report/sarif.py` (new): `to_sarif`.
- `cyberfw/report/csv_report.py` (new): `to_csv`.
- `cyberfw/cli.py`: the `export` command (resolve + load the report, convert,
  write to stdout or `-o`).
- `report/__init__.py`: export the two helpers if the package re-exports.

## Testing (TDD)

- **SARIF:** a hand-built payload with a critical nuclei vuln, a medium posture
  vuln, a gitleaks secret and a non-finding host record →
  `to_sarif` yields 3 results (host excluded), levels `error`/`warning`/
  `error`, the right `ruleId`s and `uri`s, `version`/`$schema` present, `rules`
  deduped; the document round-trips through `json.loads`.
- **CSV:** a payload with mixed records → a header plus one row per record
  (all records), `severity` filled for the vuln, `muted` reflecting the flag;
  parsed back with `csv.DictReader`.
- **CLI:** `export <session> --sarif` on a saved report prints JSON that
  `json.loads` accepts; `--csv` prints parseable CSV; `-o FILE` writes the file
  and says so; neither/both of `--sarif`/`--csv` → exit 2; an unknown run →
  exit 2.
- Full suite, `ruff`, `mypy --strict`. README + CHANGELOG updated.

## Out of scope (v1)

- Scan-time `pipeline --sarif/--csv` flags.
- Filtering muted findings out of SARIF, or SARIF `partialFingerprints` /
  rule `helpText` / full `ruleIndex` wiring.
- Other formats (JUnit, HTML already exists).
