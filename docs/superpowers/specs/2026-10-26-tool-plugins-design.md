# Tool adapters as plugins

Date: 2026-10-26 (revised the same day: manifest plugins, isolation)
Status: design, pending review — Step 1 done (`8e537a6`, `c319289`)
Roadmap: 2.0, item 1b (follows 1a, the core / API / CLI split)

## Goal

The nine tools cyberfw orchestrates are wired into cyberfw itself, in four
places: the `ADAPTERS` map (`cyberfw/tools/__init__.py`), the record models in
`MODELS` (`cyberfw/pipeline/schemas.py`), an install recipe in `registry.yaml`,
and the engine's `adapter_for`. Adding a tool means changing cyberfw.

Let anyone publish a tool for cyberfw as their own Python package — on PyPI or
anywhere else — installed next to cyberfw and usable everywhere a built-in tool
is: `cyberfw run`, YAML pipelines, `lock` / `init`, the reports and the Python
API. The package talks to cyberfw through one small, documented, versioned
contract, and cyberfw runs its code only after the user has enabled it.

Success:

- A plugin package installed next to cyberfw is listed but stays off. After
  `cyberfw plugins enable <package>` its tool shows in `cyberfw tools`,
  `cyberfw lock` pins its binary, `cyberfw run <tool>` and a YAML pipeline use
  it, and its findings reach `report.json`, the HTML report, SARIF and the run
  comparison.
- A package that is disabled is never imported.
- A manifest plugin runs no Python of its own inside cyberfw, and an update
  that makes its package ship code does not load until the user allows code.
- A broken, incompatible or conflicting plugin never breaks cyberfw: it is
  listed with its reason, and every other tool keeps working.
- Without plugins, every command prints what it prints today, apart from the
  three additions named under Compatibility.

## Decisions (settled)

- **Authors:** anyone, publishing public packages. The contract is strict,
  documented and versioned on its own.
- **What a plugin brings:** the adapter (how to build the command, how to read
  the output), the record model, and the install recipe for its binary — so
  `pip install cyberfw-foo` and `cyberfw lock` / `init` are enough, without
  editing `registry.yaml`. Not in scope: pipelines, report sections, replacing
  built-in tools.
- **Loading:** only packages the user enabled. A package that is installed but
  not enabled is listed from its metadata and its code never runs.
- **Names:** a built-in name always wins; a plugin tool that claims one does
  not load. Two packages that declare the same tool name both lose it until
  one is disabled.
- **Shape:** one entry point per tool in the group `cyberfw.tools`; the entry
  point's name is the tool's name and its value points at a `ToolPlugin`
  description. The built-in tools are described by the same objects, so there
  is one code path for every tool.
- **Two kinds of plugin.** A *manifest* plugin is data: a YAML file that
  describes the command and how the tool's JSON output becomes records. It
  runs no Python inside cyberfw and is the default way to add a tool. A *code*
  plugin is a `ToolPlugin` as above, for a tool a manifest cannot describe
  (one document instead of JSON Lines, parsing of its own). Its Python runs
  inside cyberfw with cyberfw's rights, so enabling one takes an explicit
  `--allow-code`.
- **Isolation:** cyberfw does not sandbox plugin code or tool processes (see
  Out of scope for why). What it does instead: every tool process gets a
  scrubbed environment — never cyberfw's secrets (landed before Step 2); a
  manifest plugin runs no Python in cyberfw; a package's kind is verified from
  the files it installed, not taken from what it claims.

## The contract: `cyberfw.plugin`

A plugin package declares its tools in its `pyproject.toml`:

```toml
[project.entry-points."cyberfw.tools"]
foo = "cyberfw_foo:PLUGIN"
```

and describes each one:

```python
from cyberfw.plugin import BaseTool, Finding, ToolContext, ToolPlugin, ToolSpec


class FooFinding(Finding):
    @classmethod
    def from_json(cls, tool: str, text: str, lineno: int) -> FooFinding:
        ...  # validate one JSONL line of foo's output


class FooTool(BaseTool):
    def build_cmd(self, ctx: ToolContext) -> list[str]:
        return [str(self.binary), "-json", *self.rate_args(ctx), "-u", ctx.target or ""]


PLUGIN = ToolPlugin(
    contract=1,
    adapter=FooTool,
    record=FooFinding,
    install=ToolSpec(repo="acme/foo", asset_patterns=["foo_*_linux_amd64.zip", "foo_*_windows_amd64.zip"]),
)
```

`cyberfw.plugin` is the whole stable surface for plugin authors, versioned by
its contract number (below), separate from `cyberfw.api` (which is for scripts
that run scans):

| Name | What it is |
|---|---|
| `CONTRACT` | the contract version this cyberfw writes for (`1`) |
| `SUPPORTED_CONTRACTS` | the versions this cyberfw loads (`{1}`) |
| `ToolPlugin` | frozen dataclass: `contract: int`, `adapter: type[BaseTool]`, `record: type[ToolRecord]`, `install: ToolSpec \| None` — required for a plugin; only the built-in tools leave it `None`, their recipe being their `registry.yaml` entry |
| `BaseTool` | the adapter base, with today's hooks: `build_cmd`, `parse_line`, `parse_output`, `prepare_inputs`, `input_flag`, `per_target`, `buffered`, `target_prompt`, `extra_input_prompt`, `validate_target`, `missing_requirement` |
| `BaseTool` helpers | `rate_args`, `static_flags`, `unique` — today's `_rate_args`, `_static_flags`, `_u`, made public so plugins do not copy them |
| `ToolContext`, `ScanControls` | what a stage runs with (unchanged) |
| `ToolRecord` | the base of every record (unchanged) |
| `Finding` | the base for a finding, in nuclei's shape (`template_id`, `matched_at`, `info` with `name` / `severity` / `description` / `remediation`, `muted`) |
| `ToolSpec` | the install recipe — the same model as an entry in `registry.yaml` |

Records and reports:

- The reports, SARIF, the run comparison and triage read records by `kind`, not
  by tool name. A finding is a record of `kind == "vuln"` in nuclei's shape;
  today's `PostureFinding` (the TLS and mail checks) is exactly that. `Finding`
  is that shape as a base class, and `PostureFinding` becomes a subclass of it.
  A plugin's findings subclass `Finding` and then land in the HTML findings
  section, SARIF, the comparison and `cyberfw mute` like nuclei's.
- Any other record is a `ToolRecord` with a `kind` from the documented set
  (`host`, `port`, `http`, `fuzz`, `vuln`, `secret`, `screenshot`, `scan`,
  `reputation`) or its own. Its `target` feeds the next stage; it is kept in
  `report.json` and the CSV export.

Versioning:

- The contract version is an integer, independent of cyberfw's version.
- Adding something optional — a `BaseTool` hook with a default, a
  `ToolContext` field with a default — keeps the version. Removing, renaming or
  changing the meaning of anything in the table bumps it, and cyberfw keeps
  loading the previous version for a while (`SUPPORTED_CONTRACTS`).
- A plugin written for a version this cyberfw does not load stays off, with the
  reason: `cyberfw-foo 0.3 is written for plugin contract 2; this cyberfw loads
  1 — update cyberfw`.
- Everything else (`cyberfw.tools.*`, `cyberfw.pipeline.*`, `cyberfw.manager.*`
  …) stays internal. A plugin that imports it does so at its own risk.

The built-in adapters import everything they use from `cyberfw.plugin` too, so
nine real tools exercise the contract every day. Each built-in module defines
its `ToolPlugin`; their install recipes stay in `registry.yaml`, as today.

## Manifest plugins

Most tools print JSON Lines and take a target, a host list and maybe a rate
limit; describing one needs no code. A manifest plugin package declares its
tools in a group of their own, each pointing at the package that holds the
manifest:

```toml
[project.entry-points."cyberfw.manifests"]
foo = "cyberfw_foo"
```

and ships `cyberfw_foo/foo.yaml` (the tool's name, `.yaml`), with no Python
file in the package:

```yaml
contract: 1
install:                         # the same keys as an entry in registry.yaml
  repo: acme/foo
  asset_patterns: ["foo_*_linux_amd64.zip", "foo_*_windows_amd64.zip"]
  env: [FOO_API_KEY]             # extra environment variables the tool is given
command: ["-json", "-silent"]    # always, right after the binary
target: ["-u", "{target}"]       # a stage with one target
list: ["-l", "{input_file}"]     # a stage given a host list (the engine writes the file)
rate: ["-rate-limit", "{rate}"]  # only when a rate limit is set
per_target: false                # true: one process per upstream target
inputs: any                      # any | host — host reduces URLs to bare hostnames first
target_prompt: "Target URL"      # what the launcher asks for
record:
  kind: vuln                     # host, port, http, … — or vuln for findings
  target: matched-at             # the field that is the record's target (dotted path)
  finding:                       # kind vuln only: where Finding's fields come from
    template_id: template-id
    name: info.name
    severity: info.severity
    description: info.description
```

- **The manifest is checked like a record:** a pydantic model; an unknown key,
  a missing required key, an unknown placeholder or a `finding` block on a
  record that is not a `vuln` makes the tool `broken`, with the key named.
- **Placeholders:** `{target}`, `{input_file}`, `{rate}`, `{output_dir}` (the
  session directory, for a tool that writes files). Only these.
- **Output** is JSON Lines; a line that is not a JSON object is skipped as
  unparsed, as for a built-in tool. A record keeps every field of its line,
  so `report.json` and the CSV export carry the tool's own data; `target` and
  `kind` are as mapped, and a `vuln` record is a `Finding` with the mapped
  fields.
- **It compiles into a `ToolPlugin`**: a generic adapter configured by the
  manifest, a generic record model, and `install` as the `ToolSpec`. Everything
  after loading — the registry, the lock, the engine, the reports — is the
  same as for a code plugin.
- **Located without running anything:** the entry point's value is a top-level
  package name; `importlib.util.find_spec` finds a top-level package without
  executing it, and cyberfw reads the YAML file next to it.
- **The kind is verified:** a package is a manifest package only when the
  files its installation recorded (`RECORD`) hold no Python — no `.py`, `.pyc`,
  `.pth`, `.so` or `.pyd` file — and it declares no `cyberfw.tools` entry
  point. Anything else, or a package whose files cannot be listed, is a code
  package.
- **What a manifest cannot describe** — a whole-document output, a command that
  depends on the input in other ways, parsing beyond a field mapping — is what
  code plugins are for.

## Discovery and enabling

- **Discovery reads metadata only:** `importlib.metadata.entry_points` for the
  groups `cyberfw.tools` and `cyberfw.manifests` gives each tool's name, what
  it points at, and the name and version of the package that declares it.
  Nothing is imported.
- **A tool name** is lowercase letters, digits, `-` and `_`, starting with a
  letter or digit (`^[a-z0-9][a-z0-9_-]*$`; every built-in name fits). The
  names of the built-in tools and of the records cyberfw makes itself
  (`tlscheck`, `mailcheck`, `takeover`, `virustotal`) are reserved.
- **What is enabled is a package**, not a tool: trust goes to the package, and
  enabling it enables every tool it declares. The list lives in `plugins.yaml`
  — a new setting, `plugins_file`, resolved like `triage_file` (in the
  workspace, else in the user data directory) — and only the `plugins`
  commands write it:

  ```yaml
  # managed by `cyberfw plugins enable/disable`
  enabled:
    - cyberfw-foo        # a manifest package
    - cyberfw-bar
  allow_code:
    - cyberfw-bar        # a code package: its Python runs inside cyberfw
  ```

  Package names are compared normalised (PEP 503: case-insensitive, `-`, `_`
  and `.` alike). The file can be committed with the workspace, so CI enables
  exactly what the user enabled. Upgrading an enabled package keeps it
  enabled; `cyberfw plugins` shows the version installed now. A package that
  is enabled but not in `allow_code` loads only while it is a manifest
  package: if a release starts shipping code, it stays off until the user
  allows code.
- **Loading** happens once per process for a given `plugins.yaml`, on the
  first lookup of the tool set (the `plugins` commands reload it). A manifest
  tool is accepted when its YAML file is found and its manifest is valid. A
  code tool — only from a package in `allow_code` — is accepted when its entry
  point imports, the attribute is a `ToolPlugin`, its `contract` is in
  `SUPPORTED_CONTRACTS`, `adapter` subclasses `BaseTool`, `record` subclasses
  `ToolRecord`, and `install` is a valid `ToolSpec` (re-validated with the
  tool's name injected) — a plugin without one is `broken`.

Every discovered tool is in exactly one state:

| State | When | Code imported |
|---|---|---|
| `disabled` | installed, not enabled (the default) | no |
| `enabled` | enabled and accepted | a code package's, yes; a manifest package's, never |
| `code-not-allowed` | enabled, but its package ships code and is not in `allow_code` | no |
| `conflict` | its name is a built-in or reserved name, or two packages declare it (both are in conflict) | no |
| `incompatible` | enabled, written for a contract this cyberfw does not load | yes |
| `broken` | enabled, but the import failed, the attribute is not a `ToolPlugin`, a check above failed, or its name is invalid | when it got as far as importing |
| `missing` | named in `plugins.yaml`, but no installed package has that name | no |

Conflicts are found from metadata and are per tool: the rest of the package's
tools still load.

**A plugin never breaks cyberfw.** A problem while loading puts only that
plugin's tools in their state: it shows in `cyberfw plugins` and as one warning
per problem per process on the `cyberfw` logger (silent in scripts, which get a
`NullHandler`). Built-in tools and other plugins keep working. Using the tool
itself is the only thing that fails, with the reason: `foo is not available:
plugin cyberfw-foo is disabled — run cyberfw plugins enable cyberfw-foo`.

## Registry, lock, install and the engine

- **The effective tool set** is the built-in tools, with their recipes from
  `registry.yaml` as today, plus the enabled plugin tools with their `install`
  recipe. An entry in `registry.yaml` named like a plugin tool overlays that
  recipe key by key — the keys it sets replace the plugin's, the rest come
  from the plugin — so a user can pin a version or point at a local binary in
  one line:

  ```yaml
  foo:
    version: v0.3.1        # or: source: local + path: C:\tools\foo.exe
  ```

  An entry for a plugin tool whose package is not enabled gives that tool a
  recipe but no adapter: using it fails with the hint above.
- **One place computes the set**, from the settings, and the tool manager
  carries it: adapter lookup, record models, YAML pipeline validation, the
  launcher, shell completion and the API all read it from there, so the CLI
  and a script see the same tools.
- **`tools.lock`** stays one file next to the registry in use. A plugin tool is
  locked like a built-in: `cyberfw lock` resolves its release and records the
  SHA-256 for every platform, `cyberfw init` installs exactly what is pinned,
  and installing a tool that is not locked yet locks it, as today. One change:
  `cyberfw lock` still drops the entries of tools that are gone, but a tool of
  an installed plugin package is not gone while it is disabled — its entry
  stays, so disabling and re-enabling a plugin never silently re-pins its
  binary. An entry goes once the tool is in neither `registry.yaml` nor any
  installed plugin package.
- **`init`, `status`, `tools`** install and list the enabled plugin tools with
  the built-in ones, with a column for where each tool comes from: `built-in`
  or `cyberfw-foo 0.3`.
- **The engine** builds the adapter from the tool set. `BaseTool.parse_line`
  validates with the record model of the tool's `ToolPlugin`; the `MODELS` map
  is built from the same set.
- **YAML pipelines** may name a plugin tool. Their validation before the run
  (an unknown tool is exit 2) checks the effective set and, for a tool of a
  plugin that is not enabled, gives the hint. `recon-to-vuln` does not depend
  on plugins.
- **The environment of a tool process** — built-in or plugin — is a fixed set
  of variables a program needs to run (the search path, the home, temporary
  and Windows system directories, proxy and certificate settings, locale) plus
  the names its recipe lists under `env:`. cyberfw's own secrets (the GitHub
  token, the VirusTotal key) and anything else in the user's environment are
  never passed unless a recipe names them, and `cyberfw plugins` shows each
  plugin tool's `env:`, so a plugin asking for a secret is visible before it
  is enabled.
- **Soft dependencies** (`check_deps`) and `missing_requirement` work for
  plugin tools as for built-ins. The special cases (gowitness's Chromium, the
  nmap hints) stay internal to the built-in tools.
- **Saved runs** keep their records as data, so a run made with a plugin tool
  still loads, compares and exports after the plugin is disabled or removed.

## CLI and API

- `cyberfw plugins` — a table: package, version, kind (`manifest` / `code`),
  tool, the extra variables it is given (`env:`), state, reason. With no
  plugins installed it says how to add one
  (`uv tool install cyberfw --with cyberfw-foo`, or `pip install cyberfw-foo`
  in cyberfw's environment).
- `cyberfw plugins enable <package>` — writes it to `plugins.yaml`, loads it at
  once and prints the state of each of its tools. Exit 0 when every tool is
  enabled; 1 when one is broken, incompatible or in conflict — the package
  stays enabled, so a fixed release works without enabling it again; 2 when no
  installed package by that name declares cyberfw tools (the message lists the
  ones that do). Enabling it again says `already enabled`, exit 0. No
  confirmation prompt: the command the user typed is the consent.
- A code package needs `cyberfw plugins enable <package> --allow-code`, which
  also writes it to `allow_code`. Without the flag the command refuses with
  exit 2 and says why: the package's Python would run inside cyberfw, with
  access to everything cyberfw can reach. `disable` removes a package from
  both lists.
- `cyberfw plugins disable <package>` — idempotent; it also removes a `missing`
  package from the file.
- `status` and `tools` get the origin column; `status` a line
  `plugins: 1 enabled, 2 disabled`. The launcher and shell completion offer the
  enabled plugin tools. `--help` lists one new command, `plugins`.
- Running a tool of a plugin that is not enabled or not working
  (`cyberfw run foo`, a pipeline stage) exits as an unknown tool does today,
  with the reason and the hint.
- `cyberfw.api.list_plugins(settings=None) -> list[PluginInfo]` — the same
  table as data (`package`, `version`, `tool`, `state`, `reason`); `PluginInfo`
  joins `cyberfw.api.__all__`. Enabling and disabling stay with the CLI and the
  file: running someone else's code is the user's decision, and CI commits
  `plugins.yaml`.
- Running an unavailable tool through the API raises `RegistryError` with the
  reason, as an unknown tool does today.
- `report.json` records where each plugin tool came from: a new, optional
  `tool_plugins` map in the `run` block (`{"foo": "cyberfw-foo 0.3"}`), next to
  `tool_versions`. Reports without it read as before.

## Errors

- Loading problems never raise: they are the states above.
- A plugin adapter that raises in `build_cmd`, or whose process fails, fails
  its stage like a built-in tool; the other stages go on, and the message names
  the package: `foo (cyberfw-foo 0.3): …`.
- An exception in a plugin record's `from_json` counts as a parse error of that
  line, exactly as for a built-in tool.
- A new `PluginError(CyberfwError)` covers what only the `plugins` commands
  hit: an unknown package, a `plugins.yaml` that cannot be read or written.

## Testing

- **Plugin packages for tests are real distributions:** small packages with
  their own `*.dist-info` (metadata and `entry_points.txt`) in a test
  directory put on `sys.path`, which `importlib.metadata` finds like installed
  ones. The set: a working manifest package `cyberfw-sample` (a tool with
  findings and a fake binary like the other fake tools), a working code
  package, one that fails on import, one with `contract=99`, one whose
  attribute is not a `ToolPlugin`, one that claims `nuclei`, two that declare
  the same name, a manifest package with an invalid manifest, and one whose
  manifest package also ships a `.py` file.
- **Manifests describe real tools:** subfinder, httpx, naabu and nuclei written
  as manifests build the same commands and the same records as their code
  adapters, on the outputs the adapter tests already use.
- **The kinds hold:** a code package is refused without `--allow-code`; a
  manifest package that starts shipping a `.py` file is `code-not-allowed`
  and is not imported.
- **The environment:** a fake tool that prints its environment sees the fixed
  set and its recipe's `env:` names — never a secret set for the test, such as
  `CYBERFW_GITHUB_TOKEN` or `VT_API_KEY`.
- **The whole path:** disabled by default → `plugins enable` → listed in
  `cyberfw tools` → `run sample` and a YAML pipeline with it → its findings in
  `report.json`, the HTML report, SARIF and the comparison → `cyberfw lock`
  pins its binary (with the fake GitHub client the lock tests use) → after
  `disable` its lock entry stays.
- **Never imported:** a disabled package's module fails the test on import;
  listing plugins, running other tools and `init` never touch it.
- **The contract is pinned:** a test compares `cyberfw.plugin.__all__` and the
  signatures of `BaseTool`'s public members with a recorded list, so a change
  to the contract fails until someone decides whether the version moves.
- **Layering:** the built-in adapters import only from `cyberfw.plugin`, and
  `cyberfw.plugin` loads neither the CLI, typer nor Rich — the AST and
  subprocess checks the core already has.
- **Output:** the transcript harness shows no difference after the first step,
  and after the others only the three additions under Compatibility, updated
  in the step that adds them.
- **Optional, marked integration:** build `cyberfw-sample` as a real wheel,
  install it next to cyberfw in a temporary environment and run
  `cyberfw plugins`.

## Steps

Each step is its own plan; the suite, ruff and mypy `--strict` are green after
each.

1. **The contract, without plugins** — done (`8e537a6`, `c319289`).
   `cyberfw/plugin.py` with `ToolPlugin`, `Finding` and the public helpers; the
   nine built-in tools described as `ToolPlugin`s, with `ADAPTERS` and
   `MODELS` built from them.
   Landed between Steps 1 and 2, on its own: **the scrubbed environment** for
   tool processes, with `env:` in the recipe (`ToolSpec`) — an optional field,
   so the contract stays at version 1.
2. **The manifest adapter.** The manifest model, the generic adapter and record
   model, and the compilation into a `ToolPlugin` — without discovery yet:
   tested by writing subfinder, httpx, naabu and nuclei as manifests.
3. **Discovery and states.** Metadata discovery for both groups, the kind
   check, `plugins.yaml` with `allow_code`, the states, the effective tool set
   carried by the manager, the `registry.yaml` overlay, the lock entries kept
   for disabled plugins, and `api.list_plugins`.
4. **The CLI.** The `plugins` commands with `--allow-code` and the kind and
   `env:` columns, the origin column and the `status` line, the launcher and
   completion, the hints in `run` and pipelines, and `tool_plugins` in
   `report.json`.
5. **Docs.** A README section "Плагины" — for users (install, enable, what a
   code plugin can reach) and for authors (manifests first, then the
   contract and its version, with examples) — and the CHANGELOG. The examples
   are `cyberfw-sample` and the code package the tests run, so they cannot go
   stale.

## Compatibility

- Without plugins, everything works as before, except three additions to the
  output: the origin column in `status` and `tools`, the plugins line in
  `status`, and the `plugins` command in `--help`.
- One deliberate change for everyone: tool processes no longer inherit the
  whole environment. A tool that needs a variable outside the fixed set (an
  API key of its own, say `PDCP_API_KEY` for nuclei's cloud upload) gets it
  once its `registry.yaml` entry lists it under `env:`; the CHANGELOG says so.
- `registry.yaml` and `tools.lock` keep their formats; `report.json` gains one
  optional field.
- The renames inside `cyberfw.tools.*` break no one outside: those modules were
  never public.
- Plugin contract 1 starts with cyberfw 2.0.
- Discovery uses `importlib.metadata.entry_points(group=...)`, available since
  Python 3.10 — the version the project requires.

## Out of scope

- Pipelines, report sections or post-scan checks shipped by plugins.
- Replacing a built-in tool with a plugin.
- Enabling or disabling plugins through the API.
- A plugin index or search, signing or verifying plugin packages (trust is the
  user's `enable`), and a lock file shipped by the plugin.
- Sandboxing plugin code or tool processes. Installing a package already
  trusts it — pip may run its build code, and a wheel's `.pth` file runs at
  every interpreter start — and the larger surface is the binary, which a
  sandbox around the adapter would not touch. WebAssembly would force plugins
  out of Python and still leave the binary outside; separate adapter
  processes (gRPC) isolate memory but not files or network without an OS
  sandbox; containers need Docker, and raw-socket scans (naabu) need the host
  network. An opt-in, best-effort OS sandbox for tool processes (bubblewrap /
  Landlock on Linux, Job Objects on Windows) can come later as its own item.
