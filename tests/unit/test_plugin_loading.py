"""Which plugin tools are in use: plugins.yaml, every state a tool can be in, and loading."""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
import yaml

from cyberfw import api
from cyberfw.config import Settings
from cyberfw.exceptions import PluginError
from cyberfw.manager import plugins
from cyberfw.manager.plugins import PluginInfo, load_plugins, read_plugins_file

from ._dists import install

SAMPLE = """\
contract: 1
install: {repo: acme/sample, asset_patterns: [], binary: sample, env: [SAMPLE_KEY]}
target: ["-u", "{target}"]
list: ["-l", "{input_file}"]
record: {kind: http, target: url}
"""

CODE = """\
from cyberfw.plugin import BaseTool, ToolContext, ToolPlugin, ToolRecord, ToolSpec


class BarTool(BaseTool):
    def build_cmd(self, ctx: ToolContext) -> list[str]:
        return [str(self.binary), "-u", ctx.target or ""]


PLUGIN = ToolPlugin(contract={contract}, adapter=BarTool, record=ToolRecord, install={install})
"""


@pytest.fixture(autouse=True)
def _fresh(monkeypatch: pytest.MonkeyPatch) -> None:
    # Loading is cached and its warnings deduplicated per process: each test starts clean.
    monkeypatch.setattr(plugins, "_LOADED", {})
    monkeypatch.setattr(plugins, "_WARNED", set())


@pytest.fixture
def warned(caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[], list[str]]]:
    """The warnings logged on the cyberfw logger — which stops propagating once the
    CLI has set logging up, so it is made to reach caplog for the test."""
    monkeypatch.setattr(logging.getLogger("cyberfw"), "propagate", True)
    caplog.set_level(logging.WARNING, logger="cyberfw")
    yield lambda: [record.getMessage() for record in caplog.records if record.levelno >= logging.WARNING]


def _sample(site: Path, *, package: str = "cyberfw-sample", tool: str = "sample", manifest: str = SAMPLE, **files: str) -> None:
    install(site, package, manifests={tool: "cyberfw_sample"}, files={f"cyberfw_sample/{tool}.yaml": manifest, **files})


def _bar(site: Path, *, contract: int = 1, install_spec: str = 'ToolSpec(repo="acme/bar", env=["BAR_KEY"])', body: str | None = None) -> None:
    source = body if body is not None else CODE.format(contract=contract, install=install_spec)
    install(site, "cyberfw-bar", tools={"bar": "cyberfw_bar:PLUGIN"}, files={"cyberfw_bar/__init__.py": source})


def _settings(tmp_path: Path, enabled: tuple[str, ...] = (), allow_code: tuple[str, ...] = ()) -> Settings:
    (tmp_path / "plugins.yaml").write_text(
        yaml.safe_dump({"enabled": list(enabled), "allow_code": list(allow_code)}), encoding="utf-8"
    )
    return Settings(root_dir=tmp_path)


def _info(settings: Settings, tool: str) -> PluginInfo:
    (info,) = [info for info in load_plugins(settings).infos if (info.tool or info.package) == tool]
    return info


def test_an_installed_package_stays_off_until_enabled(site: Path, tmp_path: Path) -> None:
    _sample(site)
    _bar(site)
    settings = _settings(tmp_path)

    assert (_info(settings, "sample").state, _info(settings, "sample").env) == ("disabled", ("SAMPLE_KEY",))
    assert _info(settings, "bar").state == "disabled"
    assert load_plugins(settings).tools == {} and "cyberfw_bar" not in sys.modules


def test_an_enabled_manifest_package_loads_its_tools(site: Path, tmp_path: Path) -> None:
    _sample(site)
    settings = _settings(tmp_path, enabled=("cyberfw-sample",))

    loaded = load_plugins(settings)

    assert _info(settings, "sample") == PluginInfo(
        package="cyberfw-sample", version="1.0", kind="manifest", tool="sample", state="enabled", env=("SAMPLE_KEY",)
    )
    assert loaded.tools["sample"].install is not None and loaded.tools["sample"].install.name == "sample"
    assert loaded.origin("sample") == "cyberfw-sample 1.0"


def test_a_code_package_runs_only_when_allowed_to(site: Path, tmp_path: Path) -> None:
    _bar(site)

    refused = _info(_settings(tmp_path, enabled=("cyberfw-bar",)), "bar")
    assert refused.state == "code-not-allowed" and "--allow-code" in refused.reason
    assert "cyberfw_bar" not in sys.modules

    allowed = load_plugins(_settings(tmp_path, enabled=("cyberfw-bar",), allow_code=("cyberfw-bar",)))
    assert _info(_settings(tmp_path, enabled=("cyberfw-bar",), allow_code=("cyberfw-bar",)), "bar").state == "enabled"
    assert allowed.tools["bar"].adapter.__name__ == "BarTool"
    assert allowed.tools["bar"].install is not None and allowed.tools["bar"].install.name == "bar"


def test_a_manifest_package_that_starts_shipping_python_is_not_loaded(site: Path, tmp_path: Path) -> None:
    # A release that adds Python is a code package now: enabled as data, it stays off.
    _sample(site, **{"cyberfw_sample/__init__.py": "raise RuntimeError('cyberfw_sample was imported')\n"})

    info = _info(_settings(tmp_path, enabled=("cyberfw-sample",)), "sample")

    assert (info.kind, info.state) == ("code", "code-not-allowed")
    assert "cyberfw_sample" not in sys.modules


@pytest.mark.parametrize(
    ("bar", "state", "reason"),
    [
        ({"contract": 99}, "incompatible", "written for plugin contract 99; this cyberfw loads 1 — update cyberfw"),
        ({"body": "PLUGIN = 42\n"}, "broken", "cyberfw_bar:PLUGIN is a int, not a ToolPlugin"),
        ({"body": "raise RuntimeError('no luck')\n"}, "broken", "RuntimeError: no luck"),
        ({"install_spec": "None"}, "broken", "it brings no install recipe"),
    ],
    ids=["another contract", "not a ToolPlugin", "fails to import", "no recipe"],
)
def test_a_code_plugin_that_cannot_be_used_says_why(
    site: Path, tmp_path: Path, bar: dict[str, object], state: str, reason: str
) -> None:
    _bar(site, **bar)  # type: ignore[arg-type]

    info = _info(_settings(tmp_path, enabled=("cyberfw-bar",), allow_code=("cyberfw-bar",)), "bar")

    assert info.state == state and reason in info.reason


@pytest.mark.parametrize(
    ("manifest", "state", "reason"),
    [
        (SAMPLE.replace('target: ["-u"', 'comand: [x]\ntarget: ["-u"'), "broken", "comand: unknown key"),
        (SAMPLE.replace("contract: 1", "contract: 2"), "incompatible", "written for plugin contract 2"),
    ],
)
def test_a_manifest_that_cannot_be_used_says_why(site: Path, tmp_path: Path, manifest: str, state: str, reason: str) -> None:
    _sample(site, manifest=manifest)

    info = _info(_settings(tmp_path, enabled=("cyberfw-sample",)), "sample")

    assert info.state == state and reason in info.reason


@pytest.mark.parametrize(
    ("tool", "reason"),
    [("nuclei", "nuclei is a built-in tool"), ("virustotal", "virustotal names records cyberfw makes itself")],
)
def test_a_plugin_cannot_take_a_name_cyberfw_uses(site: Path, tmp_path: Path, tool: str, reason: str) -> None:
    _sample(site, tool=tool)

    info = _info(_settings(tmp_path, enabled=("cyberfw-sample",)), tool)

    assert (info.state, info.reason) == ("conflict", reason)
    assert tool not in load_plugins(_settings(tmp_path, enabled=("cyberfw-sample",))).tools


def test_two_packages_declaring_one_name_both_lose_it(site: Path, tmp_path: Path) -> None:
    _sample(site, package="cyberfw-one", tool="dup")
    install(site, "cyberfw-two", manifests={"dup": "cyberfw_two"}, files={"cyberfw_two/dup.yaml": SAMPLE})

    loaded = load_plugins(_settings(tmp_path, enabled=("cyberfw-one", "cyberfw-two")))

    assert {(info.package, info.state) for info in loaded.infos if info.tool == "dup"} == {
        ("cyberfw-one", "conflict"), ("cyberfw-two", "conflict"),
    }
    assert "dup" not in loaded.tools


def test_a_tool_name_that_is_not_one_is_broken(site: Path, tmp_path: Path) -> None:
    _sample(site, tool="Bad")

    info = _info(_settings(tmp_path, enabled=("cyberfw-sample",)), "Bad")

    assert info.state == "broken" and "is not a tool name" in info.reason


def test_an_enabled_package_that_is_not_installed_is_missing(tmp_path: Path, warned: Callable[[], list[str]]) -> None:
    info = _info(_settings(tmp_path, enabled=("cyberfw-gone",)), "cyberfw-gone")

    assert (info.state, info.tool, info.reason) == ("missing", "", "not installed, or it declares no cyberfw tool")
    assert warned() == ["plugin cyberfw-gone: missing — not installed, or it declares no cyberfw tool"]


def test_package_names_in_plugins_yaml_are_compared_normalised(site: Path, tmp_path: Path) -> None:
    _sample(site)

    assert _info(_settings(tmp_path, enabled=("CyberFW_Sample",)), "sample").state == "enabled"


def test_an_unreadable_plugins_yaml_enables_nothing_and_says_so(
    site: Path, tmp_path: Path, warned: Callable[[], list[str]]
) -> None:
    _sample(site)
    (tmp_path / "plugins.yaml").write_text("enabled: [cyberfw-sample\n", encoding="utf-8")

    info = _info(Settings(root_dir=tmp_path), "sample")

    assert info.state == "disabled"
    assert len(warned()) == 1 and "not valid YAML" in warned()[0] and "no plugin is enabled until it is fixed" in warned()[0]


def test_a_problem_is_warned_about_once_per_process(site: Path, tmp_path: Path, warned: Callable[[], list[str]]) -> None:
    _bar(site, contract=99)
    load_plugins(_settings(tmp_path, enabled=("cyberfw-bar",), allow_code=("cyberfw-bar",)))
    (tmp_path / "plugins.yaml").write_text("# reordered\nallow_code: [cyberfw-bar]\nenabled: [cyberfw-bar]\n", encoding="utf-8")
    load_plugins(Settings(root_dir=tmp_path))

    assert warned() == [
        "plugin cyberfw-bar (bar): incompatible — written for plugin contract 99; this cyberfw loads 1 — update cyberfw"
    ]


def test_a_package_nobody_enabled_stays_quiet(site: Path, tmp_path: Path, warned: Callable[[], list[str]]) -> None:
    _sample(site, tool="nuclei")

    assert _info(_settings(tmp_path), "nuclei").state == "conflict"
    assert warned() == []


@pytest.mark.parametrize(
    ("text", "said"),
    [("enabled: cyberfw-x\n", "enabled: a list of package names"), ("enable: [x]\n", "expected the keys enabled and allow_code")],
)
def test_a_plugins_yaml_that_is_not_one_is_named(tmp_path: Path, text: str, said: str) -> None:
    (tmp_path / "plugins.yaml").write_text(text, encoding="utf-8")

    with pytest.raises(PluginError, match=said):
        read_plugins_file(tmp_path / "plugins.yaml")


def test_a_tool_that_is_not_available_says_why_and_what_to_do(site: Path, tmp_path: Path) -> None:
    _sample(site)

    loaded = load_plugins(_settings(tmp_path))

    assert loaded.unavailable("sample") == (
        "sample is not available: plugin cyberfw-sample 1.0 is disabled — enable it with `cyberfw plugins enable cyberfw-sample`"
    )
    assert loaded.unavailable("nuclei") is None and loaded.declared() >= {"sample"}


def test_the_api_lists_the_plugins(site: Path, tmp_path: Path) -> None:
    _sample(site)
    settings = _settings(tmp_path, enabled=("cyberfw-sample",))

    assert api.list_plugins(settings) == load_plugins(settings).infos
