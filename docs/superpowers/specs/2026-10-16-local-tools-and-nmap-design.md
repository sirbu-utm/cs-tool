# Local tools (`source: local`) + an nmap service-detection stage

Date: 2026-10-16
Status: design, pending review

## Goal

Let the registry orchestrate a tool the framework does **not** download — one
already on the machine (`nmap`, `masscan`, a user's own script) — and use that
to add the missing piece after port discovery: nmap `-sV` service/version
detection on the ports rustscan/naabu found.

Two parts; the first is the generic mechanism, the second its first user.

## Decisions (settled)

- `source: local` is a general registry feature; nmap is the first local tool.
- The nmap stage is added to the shipped `pipelines/ports-to-vuln.yaml` (a
  `services` stage reading naabu's open ports), so it works and demonstrates
  itself out of the box.
- nmap stays the user's to install (apt/brew/winget); the framework never
  downloads it — it only reports whether it is on PATH.

## Part 1 — `source: local` in the registry

### Schema (`ToolSpec`)

- `source: str = "github"` — `"github"` | `"local"`; any other value is a
  registry error.
- `repo` becomes optional (default `""`). Validation: a `github` tool still
  requires `owner/name`; a `local` tool ignores it.
- `asset_patterns` default `[]` (already a list) — unused for local.
- `path: str | None = None` — an explicit binary path for a local tool;
  without it the binary is found on PATH by `binary` (or the tool name).
- `is_local` property → `source == "local"`.

### Manager (`ToolManager`)

- `binary_path(name)`: for a local tool, resolve `spec.path` (if set and
  executable) else `shutil.which(spec.binary or name)`; raise
  `ToolNotFoundError` naming the tool and that it must be installed/on PATH.
  github tools keep `ensure_binary` as today.
- `is_installed(name)`: for a local tool, true iff `binary_path` resolves (no
  install record, no version — it is not something we installed).
- `install(name)`: a local tool is never downloaded — `ToolManager.install`
  on one raises `CyberfwError("nmap is a local tool — install it with your
  package manager (apt/brew/winget)")`. The callers that install in bulk
  (`install_all`, the launcher's auto-install) **filter local tools out** so
  they never hit that; `cyberfw init nmap` likewise skips it with the same
  one-line note and keeps exit 0.

### State / presentation

- `_tool_state`: a local tool is `ready` (binary resolves) or `not installed`
  (does not); `blocked` cannot occur (nothing on disk to be unreadable).
- The inventory's `source` column shows `local` for a local tool (its
  `_ToolRow.repo` is `spec.repo or "local"`).
- `_preflight` already keys off `_tool_state`, so a pipeline stage whose tool
  is a local tool that is not on PATH blocks the run with the usual message
  ("nmap … not installed"), overridable with `--force-start`.
- `status` lists nmap in the tools table like any tool; the existing rustscan
  `check_deps: [nmap]` soft-warning is left as-is (it is about rustscan's own
  version detection and is harmless alongside the new entry).

## Part 2 — nmap service detection

### Schema (`pipeline/schemas.py`)

`NmapResult(ToolRecord)` with `host`, `port: int`, `service`, `product`,
`version`. After validation: `target = f"{host}:{port}"`, `kind = "service"`,
and the detail reads like `ssh — OpenSSH 8.9`. nmap is **buffered** (it emits
one XML document, not JSONL), so there is no `VALIDATORS` entry; the adapter
builds records in `parse_output`.

### Adapter (`tools/nmap.py`, registered in `tools/__init__.py`)

- `per_target = True`, `buffered = True`.
- Consumes `host:port` targets — exactly what naabu passes downstream
  (`NaabuResult.target == "host:port"`). The engine's fan-out hands each target
  to `build_cmd` one at a time.
- `build_cmd(ctx)`: split `ctx.target` into host (`hostname_of`) and port; emit
  `nmap -sV -Pn -p <port> <host> -oX -` (XML to stdout; `-Pn` because the port
  is already known open). A bare host (no `:port`, e.g. a seed) → `nmap -sV -Pn
  <host> -oX -` (nmap's default ports).
- `parse_output(xml)`: parse with stdlib `xml.etree.ElementTree`; for each
  `host`/`port` with a `service`, emit one `NmapResult` (address or hostname,
  portid, service name, product, version). Malformed XML → no records (never a
  crash), consistent with other adapters.
- `validate_target`: accept host/URL (default).

### Registry + pipeline

- `registry.yaml`:
  ```yaml
  nmap:
    source: local
    binary: nmap
  ```
  plus a `TOOL_GUIDES["nmap"]` entry (title "Service detection", a one-line
  description, example `nmap -sV -Pn example.com`) for the capability column
  and the tool card.
- `pipelines/ports-to-vuln.yaml`: add
  ```yaml
    - tool: nmap
      stage: services
      input_from: ports
  ```
  so nmap `-sV` runs on naabu's open ports, alongside the httpx probe.

## Ripple to handle

- nmap becomes the 9th shipped tool. The CLI unit tests use their own 4-tool
  fake registry, so they are unaffected; tests that load the real
  `registry.yaml` (installer arm64, pipeline-file validation) must still pass —
  pipeline-file validation requires every stage tool to be registered **and**
  have an adapter, which nmap now satisfies. Any test that assumes a tool count
  or "all github" will be updated.
- One nmap process per `host:port` (via fan-out) — simple and correct; grouping
  a host's ports into one invocation is out of scope.

## Testing (TDD)

- **ToolSpec:** a `local` entry validates without `repo`; `is_local`; default
  `source` is github; a bad `source` is a registry error; `path` is carried.
- **ToolManager:** with `shutil.which` stubbed, a local tool is
  installed/ready and `binary_path` resolves; not on PATH → not installed and
  `binary_path` raises; `install_all` skips local; explicit `install("nmap")`
  gives the package-manager message.
- **CLI:** `status` shows nmap ready / not installed by PATH; `init nmap`
  skips with the note; `_preflight` blocks a pipeline needing nmap when it is
  not on PATH.
- **NmapResult + parse_output:** feed a canned nmap `-oX` document → assert the
  host, port, service, product/version, `target == host:port`, `kind ==
  "service"`; malformed XML → `[]`.
- **NmapTool.build_cmd:** `host:port` → `-sV -Pn -p <port> <host> -oX -`; a URL
  seed → host stripped; a bare host → no `-p`.
- **Pipeline:** `ports-to-vuln.yaml` carries the nmap `services` stage and the
  existing file-validation test still passes.
- **Integration (opt-in, `-m integration`):** real `nmap -sV` against
  localhost — skipped in the default run/CI.
- Full suite, `ruff`, `mypy --strict`. README + CHANGELOG updated.

## Out of scope (v1)

- NSE / `-sC` scripts, OS detection, UDP.
- Grouping a host's ports into a single nmap invocation.
- Auto-installing nmap; launchd/systemd anything.
- A generic "any local tool" wizard — a local tool is added by editing
  `registry.yaml` (plus an adapter when its output is novel), same as a github
  tool.
