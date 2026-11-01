"""Enabling and disabling plugin packages: ``plugins.yaml``, the states right after, and the commands."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from typer.testing import Result

from cyberfw.cli import app, launcher
from cyberfw.config import load_settings
from cyberfw.core import plugins as enabling
from cyberfw.core.workspace import open_manager
from cyberfw.exceptions import PluginError
from cyberfw.manager import plugins

from . import test_cli as base
from ._dists import install
from .test_plugin_tools import BAR, SAMPLE

#: A manifest the loader refuses: no install recipe.
BROKEN = "contract: 1\ntarget: ['-u', '{target}']\nrecord: {kind: http, target: url}\n"


@pytest.fixture(autouse=True)
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, site: Path) -> Path:
    """The CLI tests' workspace of fake tools and two plugin packages installed, none
    enabled: ``cyberfw-sample`` (a manifest) and ``cyberfw-bar`` (code)."""
    base._write_fake_binaries(tmp_path / "tools_bin")
    base._write_registry(tmp_path)
    base.TestBaselineComparison._tool_prints(tmp_path, "sample", {"url": "https://sample.example.com/", "status_code": 200})
    install(site, "cyberfw-sample", manifests={"sample": "cyberfw_sample"}, files={"cyberfw_sample/sample.yaml": SAMPLE})
    install(site, "cyberfw-bar", tools={"bar": "cyberfw_bar:PLUGIN"}, files={"cyberfw_bar/__init__.py": BAR})
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(plugins, "_LOADED", {})
    monkeypatch.setattr(plugins, "_WARNED", set())
    return tmp_path


def _file(workspace: Path) -> plugins.PluginsFile:
    return plugins.read_plugins_file(workspace / "plugins.yaml")


# -- enabling and disabling ----------------------------------------------------------------
def test_enabling_a_manifest_package_writes_plugins_yaml_and_loads_it_at_once(workspace: Path) -> None:
    result = enabling.enable_plugin(load_settings(), "cyberfw-sample")

    assert (result.package, result.already, result.working) == ("cyberfw-sample", False, True)
    assert [(info.tool, info.state) for info in result.tools] == [("sample", "enabled")]
    assert _file(workspace) == plugins.PluginsFile(enabled=frozenset({"cyberfw-sample"}))


def test_a_package_is_found_however_its_name_is_spelled(workspace: Path) -> None:
    assert enabling.enable_plugin(load_settings(), "CyberFW_Sample").package == "cyberfw-sample"
    assert _file(workspace).enabled == {"cyberfw-sample"}


def test_enabling_it_again_changes_nothing(workspace: Path) -> None:
    enabling.enable_plugin(load_settings(), "cyberfw-sample")
    before = (workspace / "plugins.yaml").read_bytes()

    again = enabling.enable_plugin(load_settings(), "cyberfw-sample")

    assert again.already and again.working
    assert (workspace / "plugins.yaml").read_bytes() == before


def test_a_code_package_is_enabled_only_when_its_code_is_allowed(workspace: Path) -> None:
    with pytest.raises(enabling.CodeNotAllowed, match="Python that would run inside cyberfw.*--allow-code"):
        enabling.enable_plugin(load_settings(), "cyberfw-bar")
    assert not (workspace / "plugins.yaml").exists()

    result = enabling.enable_plugin(load_settings(), "cyberfw-bar", allow_code=True)

    assert [(info.tool, info.state) for info in result.tools] == [("bar", "enabled")]
    assert _file(workspace) == plugins.PluginsFile(
        enabled=frozenset({"cyberfw-bar"}), allow_code=frozenset({"cyberfw-bar"})
    )


def test_allowing_code_for_a_manifest_package_allows_none(workspace: Path) -> None:
    # Were it written to allow_code, a release that starts shipping Python would load it.
    enabling.enable_plugin(load_settings(), "cyberfw-sample", allow_code=True)

    assert _file(workspace).allow_code == frozenset()


def test_an_unknown_package_names_those_that_declare_tools(workspace: Path) -> None:
    with pytest.raises(enabling.UnknownPackage, match=r"'cyberfw-nope'.*those that do: cyberfw-bar, cyberfw-sample"):
        enabling.enable_plugin(load_settings(), "cyberfw-nope")
    assert not (workspace / "plugins.yaml").exists()


def test_a_broken_package_stays_enabled_so_a_fixed_release_needs_nothing_more(workspace: Path, site: Path) -> None:
    install(site, "cyberfw-broken", manifests={"broken": "cyberfw_broken"}, files={"cyberfw_broken/broken.yaml": BROKEN})

    result = enabling.enable_plugin(load_settings(), "cyberfw-broken")

    assert not result.working and [info.state for info in result.tools] == ["broken"]
    assert _file(workspace).enabled == {"cyberfw-broken"}


def test_disabling_takes_a_package_off_both_lists_and_says_whether_it_was_there(workspace: Path) -> None:
    enabling.enable_plugin(load_settings(), "cyberfw-bar", allow_code=True)

    assert enabling.disable_plugin(load_settings(), "cyberfw-bar") is True
    assert _file(workspace) == plugins.PluginsFile()
    assert enabling.disable_plugin(load_settings(), "cyberfw-bar") is False


def test_disabling_a_package_that_is_gone_removes_it_from_the_file(workspace: Path) -> None:
    (workspace / "plugins.yaml").write_text("enabled: [cyberfw-gone, cyberfw-sample]\n", encoding="utf-8")

    assert enabling.disable_plugin(load_settings(), "cyberfw-gone") is True
    assert _file(workspace).enabled == {"cyberfw-sample"}


def test_a_plugins_yaml_that_cannot_be_read_is_left_as_it_is(workspace: Path) -> None:
    (workspace / "plugins.yaml").write_text("enabled: [unclosed\n", encoding="utf-8")

    with pytest.raises(PluginError, match="not valid YAML"):
        enabling.enable_plugin(load_settings(), "cyberfw-sample")
    with pytest.raises(PluginError, match="not valid YAML"):
        enabling.disable_plugin(load_settings(), "cyberfw-sample")
    assert (workspace / "plugins.yaml").read_text(encoding="utf-8") == "enabled: [unclosed\n"


def test_plugins_yaml_is_written_whole_and_reads_back(tmp_path: Path) -> None:
    where = tmp_path / "elsewhere"
    where.mkdir()
    path = where / "plugins.yaml"
    chosen = plugins.PluginsFile(enabled=frozenset({"cyberfw-foo", "123"}), allow_code=frozenset({"123"}))

    plugins.write_plugins_file(path, chosen)

    assert path.read_text(encoding="utf-8").startswith("# managed by `cyberfw plugins enable/disable`\n")
    assert yaml.safe_load(path.read_text(encoding="utf-8")) == {"enabled": ["123", "cyberfw-foo"], "allow_code": ["123"]}
    assert plugins.read_plugins_file(path) == chosen
    assert [p.name for p in where.iterdir()] == ["plugins.yaml"]  # no temp file left behind


def test_a_plugins_yaml_that_cannot_be_written_is_a_plugin_error(tmp_path: Path) -> None:
    with pytest.raises(PluginError, match="cannot be written"):
        plugins.write_plugins_file(tmp_path / "missing-dir" / "plugins.yaml", plugins.PluginsFile())


# -- the plugins command ---------------------------------------------------------------------
#: A manifest tool whose recipe asks for a variable of its own.
KEYED = (
    "contract: 1\n"
    "install: {repo: acme/keyed, asset_patterns: [], binary: keyed, env: [KEYED_TOKEN]}\n"
    "target: ['-u', '{target}']\n"
    "list: ['-l', '{input_file}']\n"
    "record: {kind: http, target: url}\n"
)


def _plugins(*args: str) -> Result:
    return base.runner.invoke(app, ["plugins", *args])


def _text(result: Result) -> str:
    """The output with Rich's line folding and padding undone."""
    return " ".join(result.stdout.split())


def _squashed(result: Result) -> str:
    """The output without any whitespace: a table cell folds mid-word on a narrow console."""
    return "".join(result.stdout.split())


def test_plugins_lists_each_tool_with_its_package_kind_env_state_and_reason(site: Path) -> None:
    install(site, "cyberfw-keyed", manifests={"keyed": "cyberfw_keyed"}, files={"cyberfw_keyed/keyed.yaml": KEYED})

    result = _plugins()

    assert result.exit_code == 0, result.stdout
    rows = {line.split()[0]: line.split() for line in result.stdout.splitlines() if line.startswith("cyberfw-")}
    assert rows["cyberfw-sample"][:6] == ["cyberfw-sample", "1.0", "manifest", "sample", "—", "disabled"]
    assert rows["cyberfw-bar"][:6] == ["cyberfw-bar", "1.0", "code", "bar", "—", "disabled"]
    # A disabled manifest's env: is read from its YAML — reading runs nothing.
    assert rows["cyberfw-keyed"][:6] == ["cyberfw-keyed", "1.0", "manifest", "keyed", "KEYED_TOKEN", "disabled"]
    assert "enableitwith`cyberfwpluginsenablecyberfw-sample`" in _squashed(result)


def test_with_no_plugin_installed_plugins_says_how_to_add_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(plugins, "discover", lambda: [])

    result = _plugins()

    assert result.exit_code == 0
    assert "`uv tool install cyberfw --with cyberfw-foo`, or `pip install cyberfw-foo`" in _text(result)


def test_enable_loads_the_package_and_shows_its_tools(workspace: Path) -> None:
    result = _plugins("enable", "cyberfw-sample")

    assert result.exit_code == 0, result.stdout
    assert _text(result).startswith("Enabled cyberfw-sample. kind tool env state reason manifest sample — enabled")
    assert _file(workspace).enabled == {"cyberfw-sample"}


def test_enabling_again_says_already_enabled_and_exits_0() -> None:
    _plugins("enable", "cyberfw-sample")

    result = _plugins("enable", "cyberfw-sample")

    assert result.exit_code == 0
    assert _text(result).startswith("cyberfw-sample: already enabled")


def test_a_code_package_without_allow_code_exits_2_and_says_what_it_would_reach(workspace: Path) -> None:
    refused = _plugins("enable", "cyberfw-bar")
    allowed = _plugins("enable", "cyberfw-bar", "--allow-code")

    assert refused.exit_code == 2
    assert "ships Python that would run inside cyberfw, with access to everything cyberfw can reach" in _text(refused)
    assert "`cyberfw plugins enable cyberfw-bar --allow-code`" in _text(refused)
    assert allowed.exit_code == 0, allowed.stdout
    assert _file(workspace).allow_code == {"cyberfw-bar"}


def test_an_unknown_package_exits_2_and_names_those_that_declare_tools() -> None:
    result = _plugins("enable", "cyberfw-nope")

    assert result.exit_code == 2
    assert "those that do: cyberfw-bar, cyberfw-sample" in _text(result)


def test_a_broken_package_exits_1_and_stays_enabled(workspace: Path, site: Path) -> None:
    install(site, "cyberfw-broken", manifests={"broken": "cyberfw_broken"}, files={"cyberfw_broken/broken.yaml": BROKEN})

    result = _plugins("enable", "cyberfw-broken")

    assert result.exit_code == 1
    assert " broken " in _text(result)
    assert _file(workspace).enabled == {"cyberfw-broken"}


def test_disable_says_what_it_did_and_can_be_repeated(workspace: Path) -> None:
    _plugins("enable", "cyberfw-sample")

    first, again = _plugins("disable", "cyberfw-sample"), _plugins("disable", "cyberfw-sample")

    assert (first.exit_code, _text(first)) == (0, "Disabled cyberfw-sample.")
    assert (again.exit_code, _text(again)) == (0, "cyberfw-sample was not enabled.")
    assert _file(workspace) == plugins.PluginsFile()


def test_a_plugins_yaml_that_cannot_be_read_exits_2(workspace: Path) -> None:
    (workspace / "plugins.yaml").write_text("enabled: [unclosed\n", encoding="utf-8")

    for command in (("enable", "cyberfw-sample"), ("disable", "cyberfw-sample")):
        result = _plugins(*command)
        assert result.exit_code == 2
        assert "not valid YAML" in _text(result)


def test_help_lists_one_new_command_plugins_with_enable_and_disable_under_it() -> None:
    top = base.runner.invoke(app, ["--help"])
    own = _plugins("--help")

    listed = [line.strip("│| ").split()[0] for line in top.stdout.splitlines() if line.strip("│| ")[:1].isalpha()]
    assert listed.count("plugins") == 1
    assert {"enable", "disable"} <= set(_text(own).split())


# -- where a tool comes from: status and the launcher ----------------------------------------
def _row(result: Result, tool: str) -> str:
    """The inventory row of ``tool`` without the panel's borders, whitespace squeezed."""
    (line,) = [line for line in result.stdout.splitlines() if line.strip("║│| ").split()[:1] == [tool]]
    return " ".join(line.strip("║│| ").split())


def test_status_says_where_each_tool_comes_from_and_counts_the_plugins() -> None:
    _plugins("enable", "cyberfw-sample")

    result = base.runner.invoke(app, ["status"])

    assert result.exit_code == 0, result.stdout
    assert _row(result, "sample").endswith("cyberfw-sample 1.0")
    assert _row(result, "subfinder").endswith("built-in")
    assert "plugins 1 enabled, 1 disabled" in _text(result)


def test_with_no_plugin_installed_status_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(plugins, "discover", lambda: [])

    result = base.runner.invoke(app, ["status"])

    assert "plugins none installed" in _text(result)


def test_the_launcher_offers_an_enabled_plugin_tool_and_no_other() -> None:
    def offered() -> list[str]:
        manager = open_manager(load_settings())
        try:
            return [option.name for option in launcher._menu_options(manager.registry.names())]
        finally:
            manager.close()

    before = offered()
    _plugins("enable", "cyberfw-sample")
    after = offered()

    assert "sample" not in before and "bar" not in before
    assert "sample" in after and "bar" not in after
