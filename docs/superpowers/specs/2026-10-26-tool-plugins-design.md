# Tool adapters as plugins

Date: 2026-10-26
Status: design, pending review
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

## Discovery and enabling

- **Discovery reads metadata only:** `importlib.metadata.entry_points(group=
  "cyberfw.tools")` gives each tool's name, its `module:attribute`, and the
  name and version of the package that declares it. Nothing is imported.
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
    - cyberfw-foo
  ```

  Package names are compared normalised (PEP 503: case-insensitive, `-`, `_`
  and `.` alike). The file can be committed with the workspace, so CI enables
  exactly what the user enabled. Upgrading an enabled package keeps it
  enabled; `cyberfw plugins` shows the version installed now.
- **Loading** happens once per process for a given `plugins.yaml`, on the
  first lookup of the tool set (the `plugins` commands reload it), and imports
  only the enabled packages' entry points. A tool is accepted when its entry
  point imports, the attribute is a `ToolPlugin`, its `contract` is in
  `SUPPORTED_CONTRACTS`, `adapter` subclasses `BaseTool`, `record` subclasses
  `ToolRecord`, and `install` is a valid `ToolSpec` (re-validated with the
  tool's name injected) — a plugin without one is `broken`.

Every discovered tool is in exactly one state:

| State | When | Code imported |
|---|---|---|
| `disabled` | installed, not enabled (the default) | no |
| `enabled` | enabled and accepted | yes |
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
- **Soft dependencies** (`check_deps`) and `missing_requirement` work for
  plugin tools as for built-ins. The special cases (gowitness's Chromium, the
  nmap hints) stay internal to the built-in tools.
- **Saved runs** keep their records as data, so a run made with a plugin tool
  still loads, compares and exports after the plugin is disabled or removed.

## CLI and API

- `cyberfw plugins` — a table: package, version, tool, state, reason. With no
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
  ones. The set: a working `cyberfw-sample` (a tool with findings and a fake
  binary like the other fake tools), one that fails on import, one with
  `contract=99`, one whose attribute is not a `ToolPlugin`, one that claims
  `nuclei`, and two that declare the same name.
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

1. **The contract, without plugins.** `cyberfw/plugin.py` with `ToolPlugin`,
   `Finding` and the public helpers; the nine built-in tools described as
   `ToolPlugin`s, with `ADAPTERS` and `MODELS` built from them. No behaviour
   changes: the transcript harness shows no difference.
2. **Discovery and states.** Metadata discovery, `plugins.yaml`, the states, the
   effective tool set carried by the manager, the `registry.yaml` overlay, the
   lock entries kept for disabled plugins, and `api.list_plugins`.
3. **The CLI.** The `plugins` commands, the origin column and the `status`
   line, the launcher and completion, the hints in `run` and pipelines, and
   `tool_plugins` in `report.json`.
4. **Docs.** A README section "Плагины" — for users (install and enable) and for
   authors (the contract, its version, the example) — and the CHANGELOG. The
   example for authors is `cyberfw-sample` itself, the package the tests run,
   so it cannot go stale.

## Compatibility

- Without plugins, everything works as before, except three additions to the
  output: the origin column in `status` and `tools`, the plugins line in
  `status`, and the `plugins` command in `--help`.
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
  user's `enable`), a lock file shipped by the plugin, and sandboxing plugin
  code.
