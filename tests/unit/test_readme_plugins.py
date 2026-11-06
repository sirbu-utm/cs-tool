"""The README's «Плагины» section runs: its packages are installed and used, so its examples cannot go stale."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, get_args

import pytest
import yaml
from typer.testing import Result

from cyberfw import api, plugin
from cyberfw.cli import app
from cyberfw.config import load_settings
from cyberfw.core.workspace import open_manager
from cyberfw.manager import plugins
from cyberfw.manager.discovery import CODE_GROUP, MANIFEST_GROUP
from cyberfw.plugin import BaseTool, ScanControls, ToolContext, ToolPlugin
from cyberfw.tools.manifest import OWN_PLACEHOLDER, FindingSpec, Manifest, RecordSpec

from . import test_cli as base
from ._dists import install

README = Path(__file__).resolve().parents[2] / "README.md"
USING = "### Подключить плагин"
TRUST = "### Чему доверяешь, включая плагин"
MANIFEST = "### Написать плагин-манифест"
CODE = "### Написать плагин с кодом"
CONTRACT = "### Контракт и его версия"


def _section(heading: str) -> str:
    """The README under ``heading``, down to the next heading of its level or above.
    A ``#`` line inside a code block is a comment, not a heading."""
    level = len(heading) - len(heading.lstrip("#"))
    found, fenced, lines = False, False, []
    for line in README.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
        elif not fenced and re.match(r"#{1,6} ", line):
            if found and len(line) - len(line.lstrip("#")) <= level:
                break
            if line == heading:
                found = True
                continue
        if found:
            lines.append(line)
    assert found, f"the README has no {heading!r}"
    return "\n".join(lines) + "\n"


def _blocks(heading: str, language: str) -> list[str]:
    return re.findall(rf"^ *```{language}\n(.*?)^ *```$", _section(heading), flags=re.M | re.S)


def _package(heading: str, group: str) -> tuple[str, str, dict[str, str]]:
    """The name, version and entry points a section's ``pyproject.toml`` declares."""
    (pyproject,) = _blocks(heading, "toml")
    name = re.search(r'^name = "(.+)"$', pyproject, flags=re.M)
    version = re.search(r'^version = "(.+)"$', pyproject, flags=re.M)
    assert name is not None and version is not None
    entries = pyproject.split(f'[project.entry-points."{group}"]\n')[1].split("\n[")[0]
    return name.group(1), version.group(1), dict(re.findall(r'^(\S+) = "(.+)"$', entries, flags=re.M))


def _tool_prints(workspace: Path, tool: str, stdout: str) -> None:
    """A fake binary: it notes its arguments next to itself and prints ``stdout``."""
    binary = workspace / "tools_bin" / tool
    binary.write_text(
        f'#!/usr/bin/env bash\necho "$*" > "$(dirname "$0")/{tool}.argv"\nprintf \'%s\\n\' \'{stdout}\'\n',
        encoding="utf-8",
        newline="\n",
    )
    binary.chmod(0o755)


def _argv(workspace: Path, tool: str) -> str:
    return (workspace / "tools_bin" / f"{tool}.argv").read_text(encoding="utf-8").strip()


@pytest.fixture(autouse=True)
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, site: Path) -> Path:
    """The CLI tests' workspace, with the README's two packages installed, none enabled,
    and fake binaries that print what the README says their tools print."""
    base._write_fake_binaries(tmp_path / "tools_bin")
    base._write_registry(tmp_path)

    name, version, entries = _package(MANIFEST, MANIFEST_GROUP)
    assert entries == {"sample": "cyberfw_sample"}
    (manifest,) = _blocks(MANIFEST, "yaml")
    install(site, name, version=version, manifests=entries, files={"cyberfw_sample/sample.yaml": manifest})
    (lines,) = _blocks(MANIFEST, "json")
    _tool_prints(tmp_path, "sample", lines.strip())

    name, version, entries = _package(CODE, CODE_GROUP)
    assert entries == {"bar": "cyberfw_bar:PLUGIN"}
    (source,) = _blocks(CODE, "python")
    install(site, name, version=version, tools=entries, files={"cyberfw_bar/__init__.py": source})
    (document,) = _blocks(CODE, "json")
    _tool_prints(tmp_path, "bar", json.dumps(json.loads(document)))

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(plugins, "_LOADED", {})
    monkeypatch.setattr(plugins, "_WARNED", set())
    return tmp_path


def _cli(*args: str) -> Result:
    return base.runner.invoke(app, list(args))


def _text(text: str) -> str:
    """Rich's line folding and padding undone."""
    return " ".join(text.split())


def _report(workspace: Path, session: str) -> dict[str, Any]:
    report: dict[str, Any] = json.loads((workspace / "reports" / session / "report.json").read_text(encoding="utf-8"))
    return report


def _findings(report: dict[str, Any]) -> list[tuple[str, str, str, str, str]]:
    return [
        (r["tool"], r["target"], r["template_id"], r["info"]["name"], r["info"]["severity"])
        for r in report["records"]
        if r["kind"] == "vuln"
    ]


# -- using a plugin ----------------------------------------------------------------------------
def test_the_listing_in_the_readme_is_what_cyberfw_plugins_prints() -> None:
    (listing,) = _blocks(USING, "text")

    result = _cli("plugins")

    assert result.exit_code == 0, result.stdout
    assert _text(result.stdout) == _text(listing)


def test_the_plugins_yaml_in_the_readme_is_what_enabling_both_packages_writes(workspace: Path) -> None:
    documented = _blocks(USING, "yaml")[0]

    assert _cli("plugins", "enable", "cyberfw-sample").exit_code == 0
    assert _cli("plugins", "enable", "cyberfw-bar", "--allow-code").exit_code == 0

    assert (workspace / "plugins.yaml").read_text(encoding="utf-8") == documented


def test_the_pipeline_in_the_readme_runs_both_plugins_on_a_previous_stages_hosts(workspace: Path) -> None:
    documented = _blocks(USING, "yaml")[1]
    (workspace / "pipelines").mkdir()
    (workspace / "pipelines" / "probe.yaml").write_text(documented, encoding="utf-8")
    assert _cli("plugins", "enable", "cyberfw-sample").exit_code == 0
    assert _cli("plugins", "enable", "cyberfw-bar", "--allow-code").exit_code == 0

    result = _cli("pipeline", "probe", "-t", "example.com", "--session", "p1", "--no-mail", "--no-takeover", "--no-intel", "--no-vt")

    assert result.exit_code == 0, result.stdout
    assert "-json -silent -l " in _argv(workspace, "sample")
    assert "--report json --list " in _argv(workspace, "bar")
    report = _report(workspace, "p1")
    assert {tool for tool, *_ in _findings(report)} == {"sample", "bar"}
    assert report["run"]["tool_plugins"] == {"sample": "cyberfw-sample 1.0", "bar": "cyberfw-bar 0.3"}


def test_the_registry_entry_in_the_readme_overlays_the_plugins_recipe_key_by_key(workspace: Path) -> None:
    documented = _blocks(USING, "yaml")[2]
    with (workspace / "registry.yaml").open("a", encoding="utf-8") as registry:
        registry.write("\n" + documented)
    assert _cli("plugins", "enable", "cyberfw-sample").exit_code == 0

    manager = open_manager(load_settings())
    try:
        spec = manager.spec("sample")
    finally:
        manager.close()

    assert spec.version == "v1.4.2"
    assert spec.repo == "acme/sample"


def test_the_readme_names_every_state_a_plugin_can_be_in() -> None:
    section = _section(USING)

    assert [state for state in get_args(plugins.State) if f"`{state}`" not in section] == []


def test_the_readme_names_the_names_a_plugin_cannot_take() -> None:
    section = _section(USING)

    assert [name for name in plugins.RESERVED if f"`{name}`" not in section] == []


def test_the_python_api_section_names_what_lists_the_plugins() -> None:
    assert "list_plugins" in _section("## Python API")
    assert "list_plugins" in api.__all__


# -- what a plugin can reach -------------------------------------------------------------------
def test_a_code_package_is_refused_without_the_flag_the_readme_gives() -> None:
    (commands,) = _blocks(TRUST, "bash")
    assert commands.strip() == "cyberfw plugins enable cyberfw-bar --allow-code"

    refused = _cli("plugins", "enable", "cyberfw-bar")

    assert refused.exit_code == 2
    assert "--allow-code" in _text(refused.stdout)
    assert _cli(*commands.split()[1:]).exit_code == 0


# -- writing a manifest ------------------------------------------------------------------------
def test_the_manifest_in_the_readme_builds_the_command_and_the_finding_it_describes(workspace: Path) -> None:
    assert _cli("plugins", "enable", "cyberfw-sample").exit_code == 0

    result = _cli("run", "sample", "-t", "https://example.com", "--rate-limit", "5", "--save", "--session", "s1")

    assert result.exit_code == 0, result.stdout
    assert _argv(workspace, "sample") == "-json -silent -rate-limit 5 -u https://example.com"
    report = _report(workspace, "s1")
    assert _findings(report) == [("sample", "https://example.com/admin", "open-admin", "Open admin panel", "high")]
    assert report["run"]["tool_plugins"] == {"sample": "cyberfw-sample 1.0"}
    sarif = json.loads(_cli("export", "s1", "--sarif").stdout)
    assert [finding["ruleId"] for finding in sarif["runs"][0]["results"]] == ["open-admin"]


def test_the_readme_names_every_key_of_a_manifest() -> None:
    section = _section(MANIFEST)
    keys = [field.alias or name for name, field in Manifest.model_fields.items()]
    keys += [*RecordSpec.model_fields, *FindingSpec.model_fields]

    assert [key for key in keys if f"`{key}`" not in section and f"`record.{key}`" not in section] == []


def test_the_readme_names_every_placeholder_of_a_manifest() -> None:
    section = _section(MANIFEST)
    placeholders = [own for own in OWN_PLACEHOLDER.values() if own] + ["output_dir"]

    assert [name for name in placeholders if f"{{{name}}}" not in section] == []


# -- writing code ------------------------------------------------------------------------------
def test_the_code_plugin_in_the_readme_reads_its_tools_one_document(workspace: Path) -> None:
    assert _cli("plugins", "enable", "cyberfw-bar", "--allow-code").exit_code == 0

    result = _cli("run", "bar", "-t", "https://example.com", "--rate-limit", "5", "--save", "--session", "b1")

    assert result.exit_code == 0, result.stdout
    assert _argv(workspace, "bar") == "--report json --rate 5 https://example.com"
    report = _report(workspace, "b1")
    assert _findings(report) == [("bar", "https://example.com/", "weak-tls", "Weak TLS", "medium")]
    assert report["run"]["tool_plugins"] == {"bar": "cyberfw-bar 0.3"}


def test_the_code_plugin_in_the_readme_fails_its_stage_on_a_report_it_cannot_read(workspace: Path) -> None:
    assert _cli("plugins", "enable", "cyberfw-bar", "--allow-code").exit_code == 0
    _tool_prints(workspace, "bar", "not a report")

    result = _cli("run", "bar", "-t", "https://example.com", "--no-save")

    assert result.exit_code == 1
    assert "[bar] unexpected report" in _text(result.stdout)


# -- the contract ------------------------------------------------------------------------------
def test_the_readme_names_everything_in_the_contract() -> None:
    section = _section(CONTRACT)
    names = [*plugin.__all__, *(name for name in vars(BaseTool) if not name.startswith("_"))]
    names += [*ToolContext.__dataclass_fields__, *ScanControls.__dataclass_fields__, *ToolPlugin.__dataclass_fields__]

    assert [name for name in names if f"`{name}`" not in section] == []


def test_the_readmes_examples_are_written_for_the_contract_this_cyberfw_writes_for() -> None:
    (manifest,) = _blocks(MANIFEST, "yaml")
    (source,) = _blocks(CODE, "python")

    assert yaml.safe_load(manifest)["contract"] == plugin.CONTRACT
    assert f"contract={plugin.CONTRACT}," in source
    assert f"`CONTRACT` | версия контракта, под которую написан этот cyberfw (`{plugin.CONTRACT}`)" in _section(CONTRACT)
