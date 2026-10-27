"""Plugin tools in use, wherever cyberfw looks a tool up: a run, a pipeline, the registry, the lock."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from cyberfw import api
from cyberfw.config import load_settings
from cyberfw.core.workspace import open_manager
from cyberfw.exceptions import CyberfwError, RegistryError
from cyberfw.manager import ToolManager, plugins
from cyberfw.manager.lock import LockedTool, ToolLock, read_lock, write_lock
from cyberfw.manager.registry import ToolSpec

from . import test_cli as base
from ._dists import install

SAMPLE = """\
contract: 1
install: {repo: acme/sample, asset_patterns: [], binary: sample}
target: ["-u", "{target}"]
list: ["-l", "{input_file}"]
record: {kind: http, target: url}
"""

BAR = """\
from cyberfw.plugin import BaseTool, ToolContext, ToolPlugin, ToolRecord, ToolSpec


class BarRecord(ToolRecord):
    url: str = ""

    @classmethod
    def from_json(cls, tool, text, lineno):
        record = super().from_json(tool, text, lineno)
        record.target, record.kind = record.url, "http"
        return record


class BarTool(BaseTool):
    def build_cmd(self, ctx: ToolContext) -> list[str]:
        return [str(self.binary), "-u", ctx.target or ""]


PLUGIN = ToolPlugin(
    contract=1, adapter=BarTool, record=BarRecord, install=ToolSpec(repo="acme/bar", asset_patterns=[], binary="bar")
)
"""

PROBE = "description: One stage, a plugin's tool\nnodes:\n  - tool: sample\n    stage: live\n"


@pytest.fixture(autouse=True)
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, site: Path) -> Path:
    """The CLI tests' workspace of fake tools, two plugin packages installed (none
    enabled), their fake binaries, and a YAML pipeline that names a plugin's tool."""
    base._write_fake_binaries(tmp_path / "tools_bin")
    base._write_registry(tmp_path)
    for tool in ("sample", "bar"):
        base.TestBaselineComparison._tool_prints(tmp_path, tool, {"url": f"https://{tool}.example.com/", "status_code": 200})
    (tmp_path / "pipelines").mkdir()
    (tmp_path / "pipelines" / "probe.yaml").write_text(PROBE, encoding="utf-8")
    install(site, "cyberfw-sample", manifests={"sample": "cyberfw_sample"}, files={"cyberfw_sample/sample.yaml": SAMPLE})
    install(site, "cyberfw-bar", tools={"bar": "cyberfw_bar:PLUGIN"}, files={"cyberfw_bar/__init__.py": BAR})
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(plugins, "_LOADED", {})
    monkeypatch.setattr(plugins, "_WARNED", set())
    return tmp_path


def _enable(workspace: Path, *packages: str, allow_code: tuple[str, ...] = ()) -> None:
    (workspace / "plugins.yaml").write_text(
        yaml.safe_dump({"enabled": list(packages), "allow_code": list(allow_code)}), encoding="utf-8"
    )


def test_an_enabled_manifest_tool_runs_like_a_built_in_one(workspace: Path) -> None:
    _enable(workspace, "cyberfw-sample")

    outcome = api.run_tool("sample", target="https://sample.example.com")

    assert outcome.succeeded
    assert [(record.tool, record.target, record.kind) for record in outcome.result.records] == [
        ("sample", "https://sample.example.com/", "http"),
    ]


def test_a_code_plugin_reads_its_lines_with_its_own_record_model(workspace: Path) -> None:
    # Its adapter keeps BaseTool's parse_line: the model comes from its description.
    _enable(workspace, "cyberfw-bar", allow_code=("cyberfw-bar",))

    (record,) = api.run_tool("bar", target="bar.example.com").result.records

    assert (type(record).__name__, record.target, record.kind) == ("BarRecord", "https://bar.example.com/", "http")


def test_a_yaml_pipeline_may_name_a_plugin_tool(workspace: Path) -> None:
    _enable(workspace, "cyberfw-sample")

    plan = api.plan_pipeline("probe", "example.com")
    outcome = api.run_pipeline("probe", "example.com", save=False, mail=False, takeover=False, intel=False)

    assert plan.ready and [stage.tool for stage in plan.stages] == ["sample"]
    assert outcome.succeeded and [record.tool for record in outcome.result.records] == ["sample"]


def test_a_plugin_tool_not_in_use_says_why_and_what_to_do(workspace: Path) -> None:
    said = "sample is not available: plugin cyberfw-sample 1.0 is disabled — enable it with `cyberfw plugins enable cyberfw-sample`"

    with pytest.raises(RegistryError, match="^sample is not available") as run:
        api.run_tool("sample", target="example.com")
    with pytest.raises(RegistryError, match="^sample is not available") as plan:
        api.plan_pipeline("probe", "example.com")

    assert str(run.value) == str(plan.value) == said


def test_registry_yaml_lays_its_keys_over_a_plugin_s_recipe(workspace: Path) -> None:
    _enable(workspace, "cyberfw-sample")
    with (workspace / "registry.yaml").open("a", encoding="utf-8") as registry:
        registry.write("\nsample:\n  version: v2.0.0\n")

    manager = open_manager(load_settings())
    spec = manager.spec("sample")
    manager.close()

    assert (spec.name, spec.repo, spec.binary, spec.version) == ("sample", "acme/sample", "sample", "v2.0.0")


def test_an_entry_for_a_plugin_not_in_use_leaves_the_registry_working(workspace: Path) -> None:
    # "version:" alone is no recipe: without its plugin it is left out, not an error.
    with (workspace / "registry.yaml").open("a", encoding="utf-8") as registry:
        registry.write("\nsample:\n  version: v2.0.0\n")

    manager = open_manager(load_settings())
    try:
        assert manager.spec("subfinder").repo == "org/subfinder"
        with pytest.raises(RegistryError, match="^sample is not available"):
            manager.spec("sample")
    finally:
        manager.close()


def test_the_lock_keeps_a_disabled_plugin_tool_s_pin(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def offline(self: ToolManager, spec: ToolSpec) -> LockedTool:
        raise CyberfwError("no network in tests")

    monkeypatch.setattr(ToolManager, "_resolve", offline)
    pins = {name: LockedTool(repo=f"acme/{name}", tag="v1", assets={}) for name in ("sample", "gone")}
    write_lock(workspace / "tools.lock", ToolLock(tools=pins))

    manager = open_manager(load_settings())
    manager.update_lock()
    manager.close()

    lock = read_lock(workspace / "tools.lock")
    assert lock is not None and set(lock.tools) == {"sample"}
