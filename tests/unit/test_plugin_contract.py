"""cyberfw.plugin: the contract tool adapters are written against — what it holds, and that it holds still."""

from __future__ import annotations

import ast
import dataclasses
import inspect
import os
import subprocess
import sys
from pathlib import Path

import pytest

import cyberfw
from cyberfw import plugin
from cyberfw.manager.registry import load_registry
from cyberfw.pipeline.schemas import PostureFinding
from cyberfw.tools import ADAPTERS, BUILTIN, MODELS

PACKAGE = Path(cyberfw.__file__).resolve().parent

#: What contract 1 promises plugin authors. A test failing against this is a change
#: to every plugin's ground: decide whether ``plugin.CONTRACT`` moves (the module
#: docstring says when it must) before recording the new surface here.
CONTRACT_1: dict[str, object] = {
    "__all__": [
        "CONTRACT",
        "SUPPORTED_CONTRACTS",
        "BaseTool",
        "Finding",
        "ParseError",
        "ScanControls",
        "ToolContext",
        "ToolPlugin",
        "ToolRecord",
        "ToolSpec"
    ],
    "CONTRACT": 1,
    "SUPPORTED_CONTRACTS": [
        1
    ],
    "BaseTool": {
        "fields": [],
        "members": {
            "__init__": "def(self, spec: 'ToolSpec', binary: 'Path') -> 'None'",
            "buffered": "False",
            "build_cmd": "def(self, ctx: 'ToolContext') -> 'list[str]'",
            "extra_input_prompt": "None",
            "input_flag": "property",
            "missing_requirement": "classmethod(cls, tools_dir: 'Path | None' = None) -> 'str | None'",
            "name": "property",
            "parse_line": "def(self, line: 'str', lineno: 'int') -> 'ToolRecord'",
            "parse_output": "def(self, text: 'str') -> 'list[ToolRecord]'",
            "per_target": "False",
            "prepare_inputs": "def(self, inputs: 'list[str]') -> 'list[str]'",
            "rate_args": "def(self, ctx: 'ToolContext', flag: 'str' = '-rate-limit') -> 'list[str]'",
            "static_flags": "def(self) -> 'list[str]'",
            "target_prompt": "'Target (domain, URL or host)'",
            "unique": "staticmethod(inputs: 'list[str]') -> 'list[str]'",
            "validate_target": "classmethod(cls, target: 'str') -> 'None'"
        }
    },
    "ToolContext": {
        "fields": [
            "target: str | None",
            "inputs: list[str]",
            "input_file: Path | None",
            "extra_input: str | None",
            "output_dir: Path | None",
            "controls: ScanControls"
        ],
        "members": {
            "__init__": "def(self, target: 'str | None' = None, inputs: 'list[str]' = <factory>, input_file: 'Path | None' = None, extra_input: 'str | None' = None, output_dir: 'Path | None' = None, controls: 'ScanControls' = <factory>) -> None",
            "extra_input": "None",
            "input_file": "None",
            "output_dir": "None",
            "target": "None"
        }
    },
    "ScanControls": {
        "fields": [
            "rate_limit: int | None",
            "severity: str",
            "tags: str"
        ],
        "members": {
            "__init__": "def(self, rate_limit: 'int | None' = None, severity: 'str' = '', tags: 'str' = '') -> None",
            "rate_limit": "None",
            "severity": "''",
            "tags": "''"
        }
    },
    "ToolPlugin": {
        "fields": [
            "contract: int",
            "adapter: type[BaseTool]",
            "record: type[ToolRecord]",
            "install: ToolSpec | None"
        ],
        "members": {
            "__init__": "def(self, contract: 'int', adapter: 'type[BaseTool]', record: 'type[ToolRecord]', install: 'ToolSpec | None' = None) -> None",
            "install": "None"
        }
    },
    "ToolRecord": {
        "fields": [
            "tool",
            "line_number",
            "raw",
            "target",
            "kind"
        ],
        "members": {
            "as_dict": "def(self) -> 'dict[str, Any]'",
            "from_json": "classmethod(cls, tool: 'str', text: 'str', lineno: 'int') -> 'ToolRecord'"
        }
    },
    "Finding": {
        "fields": [
            "tool",
            "line_number",
            "raw",
            "target",
            "kind",
            "template_id",
            "matched_at",
            "info",
            "muted"
        ],
        "members": {
            "name": "property",
            "severity": "property"
        }
    },
    "ToolSpec": {
        "fields": [
            "name",
            "source",
            "repo",
            "asset_patterns",
            "archive",
            "binary",
            "path",
            "version",
            "check_deps",
            "interactive_input"
        ],
        "members": {
            "is_local": "property",
            "pinned_version": "property",
            "repo_name": "property",
            "repo_owner": "property"
        }
    }
}


def _members(cls: type) -> dict[str, str]:
    """``cls``'s own public members and ``__init__``: a method's signature, a property, or a value."""
    out: dict[str, str] = {}
    for name, member in sorted(vars(cls).items()):
        if (name.startswith("_") and name != "__init__") or name.startswith("model_"):
            continue
        if isinstance(member, property):
            out[name] = "property"
        elif isinstance(member, classmethod):
            out[name] = f"classmethod{inspect.signature(member.__func__)}"
        elif isinstance(member, staticmethod):
            out[name] = f"staticmethod{inspect.signature(member.__func__)}"
        elif inspect.isfunction(member):
            out[name] = f"def{inspect.signature(member)}"
        else:
            out[name] = repr(member)
    return out


def _fields(cls: type) -> list[str]:
    """A dataclass's fields with their types, a pydantic model's field names; none for a plain class."""
    if dataclasses.is_dataclass(cls):
        return [f"{item.name}: {item.type}" for item in dataclasses.fields(cls)]
    return list(getattr(cls, "model_fields", {}))


def _surface() -> dict[str, object]:
    types = ("BaseTool", "ToolContext", "ScanControls", "ToolPlugin", "ToolRecord", "Finding", "ToolSpec")
    return {
        "__all__": list(plugin.__all__),
        "CONTRACT": plugin.CONTRACT,
        "SUPPORTED_CONTRACTS": sorted(plugin.SUPPORTED_CONTRACTS),
        **{name: {"fields": _fields(getattr(plugin, name)), "members": _members(getattr(plugin, name))} for name in types},
    }


def test_the_contract_is_what_version_1_promises() -> None:
    assert _surface() == CONTRACT_1


def test_the_built_in_tools_take_the_contract_from_cyberfw_plugin() -> None:
    # The nine built-in tools use exactly what a plugin gets — never a way around it.
    offenders = []
    for path in sorted((PACKAGE / "tools").glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("cyberfw"):
                taken = {alias.name for alias in node.names} & set(plugin.__all__)
                if taken and node.module != "cyberfw.plugin":
                    offenders.append(f"{path.name}: {', '.join(sorted(taken))} from {node.module}")

    assert offenders == []


@pytest.mark.parametrize("first", ["cyberfw.plugin", "cyberfw.tools", "cyberfw.pipeline.engine", "cyberfw.pipeline.schemas"])
def test_the_contract_imports_in_any_order(first: str) -> None:
    # A plugin's first line is `from cyberfw.plugin import ...`; cyberfw's own code reaches
    # the same types through its tools, its engine and its record models.
    code = (
        f"import importlib; importlib.import_module({first!r})\n"
        "import cyberfw.plugin, cyberfw.tools\n"
        "from cyberfw.pipeline.schemas import validate_record\n"
        "print(cyberfw.tools.adapter_class('nuclei').__name__, type(validate_record('subfinder', '{}', 1)).__name__)\n"
    )
    run = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONUTF8": "1"},
        timeout=120,
    )

    assert run.returncode == 0, run.stderr
    assert run.stdout.split() == ["NucleiTool", "SubfinderResult"]


def test_a_finding_is_a_vuln_shaped_like_nuclei_s() -> None:
    finding = plugin.Finding(tool="foo", template_id="foo-weak-cipher", info={"name": "Weak cipher"})

    assert (finding.kind, finding.name, finding.severity) == ("vuln", "Weak cipher", "unknown")


def test_cyberfw_s_own_findings_are_findings_and_saved_as_before() -> None:
    # Saved runs hold posture findings; their shape on disk must not move.
    found = PostureFinding.make(
        "tlscheck", "tls-expired", "https://a.example.com",
        name="Expired", severity="high", description="d", remediation="r",
    )

    assert isinstance(found, plugin.Finding)
    assert list(found.as_dict()) == [
        "tool", "line_number", "raw", "target", "kind", "template_id", "matched_at", "info", "muted",
    ]
    assert (found.kind, found.name, found.severity) == ("vuln", "Expired", "high")


class Echo(plugin.BaseTool):
    def build_cmd(self, ctx: plugin.ToolContext) -> list[str]:
        return [str(self.binary), *self.static_flags(), *self.rate_args(ctx, "-rate")]


def test_a_tool_written_against_the_contract_builds_its_command_with_its_helpers() -> None:
    spec = plugin.ToolSpec(name="echo", source="local", interactive_input={"-json": "", "-c": "5"})
    tool = Echo(spec, Path("echo"))

    assert tool.build_cmd(plugin.ToolContext(controls=plugin.ScanControls(rate_limit=20))) == [
        "echo", "-json", "-c", "5", "-rate", "20",
    ]
    assert tool.build_cmd(plugin.ToolContext()) == ["echo", "-json", "-c", "5"]
    assert plugin.BaseTool.unique(["a", "b", "a"]) == ["a", "b"]


def test_every_built_in_tool_is_described_the_way_a_plugin_describes_its_own() -> None:
    registry = load_registry(PACKAGE.parent / "registry.yaml")

    assert sorted(BUILTIN) == registry.names()
    for name, tool in BUILTIN.items():
        assert isinstance(tool, plugin.ToolPlugin) and tool.contract == plugin.CONTRACT, name
        assert issubclass(tool.adapter, plugin.BaseTool) and issubclass(tool.record, plugin.ToolRecord), name
        assert tool.install is None, f"{name}'s recipe is its registry.yaml entry"
    assert ADAPTERS == {name: tool.adapter for name, tool in BUILTIN.items()}


def test_records_validate_against_the_model_each_tool_s_description_names() -> None:
    assert {name: model.__name__ for name, model in MODELS.items()} == {
        "subfinder": "SubfinderResult",
        "naabu": "NaabuResult",
        "nmap": "NmapResult",
        "rustscan": "RustscanResult",
        "httpx": "HttpxResult",
        "ffuf": "FfufResult",
        "nuclei": "NucleiResult",
        "gitleaks": "GitleaksResult",
        "gowitness": "GowitnessResult",
        "virustotal": "VirusTotalResult",
    }
    assert all(MODELS[name] is tool.record for name, tool in BUILTIN.items())
