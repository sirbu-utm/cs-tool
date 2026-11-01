"""Enabling and disabling plugin packages: ``plugins.yaml``, the states right after, and the commands."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from cyberfw.config import load_settings
from cyberfw.core import plugins as enabling
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
