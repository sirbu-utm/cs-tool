"""Manifest tools run like built-in ones — the same commands, the same records — and
nothing a tool prints can change what its record is."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from cyberfw.cli.views import _record_table
from cyberfw.live_view import TopologyView
from cyberfw.pipeline.engine import Node, NodeResult, PipelineResult
from cyberfw.plugin import (
    BaseTool,
    Finding,
    ParseError,
    ScanControls,
    ToolContext,
    ToolPlugin,
    ToolRecord,
    ToolSpec,
)
from cyberfw.report.csv_report import to_csv
from cyberfw.report.diff import compare
from cyberfw.report.html_report import generate_html_report
from cyberfw.report.json_report import report_payload
from cyberfw.report.sarif import to_sarif
from cyberfw.tools import adapter_for
from cyberfw.tools.manifest import parse_manifest
from cyberfw.tools.manifest_tool import ManifestTool, compile_manifest

from .test_engine import _make_engine, _stub_binary, _StubTool
from .test_manifest_format import MANIFESTS

BINARY = Path("tools_bin") / "tool"

#: What each tool prints, as the adapter and schema tests already have it.
LINES = {
    "subfinder": '{"host": "sub.example.com", "source": "crt.sh"}',
    "httpx": '{"url": "https://sub.example.com/", "status_code": 200, "title": "Home"}',
    "naabu": '{"host": "1.2.3.4", "port": 443, "protocol": "tcp"}',
    "nuclei": (
        '{"template-id": "xss", "matched-at": "https://sub.example.com/", '
        '"info": {"name": "XSS check", "severity": "medium"}}'
    ),
}

CONTEXTS = {
    "a target": ToolContext(target="https://Sub.Example.com:8443/login"),
    "a host list": ToolContext(inputs=["a.example.com", "b.example.com"], input_file=Path("stage.input")),
    "every control": ToolContext(
        target="example.com", controls=ScanControls(rate_limit=50, severity="critical,high", tags="cve")
    ),
}


def _compiled(name: str) -> ToolPlugin:
    return compile_manifest(name, parse_manifest(MANIFESTS[name], where=f"{name}.yaml"))


def _both(name: str) -> tuple[BaseTool, BaseTool]:
    """The tool's code adapter and its manifest's, on one recipe that has a static flag."""
    spec = ToolSpec(name=name, repo=f"org/{name}", asset_patterns=[], interactive_input={"-stats": ""})
    return adapter_for(spec, BINARY), _compiled(name).adapter(spec, BINARY)


def _view(record: ToolRecord) -> dict[str, object]:
    """What the rest of cyberfw reads of a record: whose line it is, its target and
    kind — and a finding's own fields."""
    fields = record.as_dict()
    return {key: fields.get(key) for key in ("tool", "line_number", "raw", "target", "kind", "template_id", "matched_at", "info")}


@pytest.mark.parametrize("context", sorted(CONTEXTS))
@pytest.mark.parametrize("name", sorted(MANIFESTS))
def test_a_manifest_builds_the_command_its_tool_s_adapter_builds(name: str, context: str) -> None:
    code, manifest = _both(name)

    assert manifest.build_cmd(CONTEXTS[context]) == code.build_cmd(CONTEXTS[context])


@pytest.mark.parametrize("name", sorted(MANIFESTS))
def test_a_manifest_reads_a_line_as_its_tool_s_adapter_does(name: str) -> None:
    code, manifest = _both(name)

    assert _view(manifest.parse_line(LINES[name], 3)) == _view(code.parse_line(LINES[name], 3))


@pytest.mark.parametrize("name", sorted(MANIFESTS))
def test_a_manifest_tool_tells_the_engine_and_the_launcher_what_its_adapter_does(name: str) -> None:
    code, manifest = _both(name)

    assert (manifest.input_flag, manifest.per_target, type(manifest).target_prompt) == (
        code.input_flag, code.per_target, type(code).target_prompt,
    )


def test_a_host_only_manifest_reduces_upstream_urls_as_naabu_s_adapter_does() -> None:
    code, manifest = _both("naabu")
    upstream = ["https://a.example.com/", "http://b.example.com:8080/x", "c.example.com"]

    assert manifest.prepare_inputs(upstream) == code.prepare_inputs(upstream) == ["a.example.com", "b.example.com", "c.example.com"]


def test_a_compiled_manifest_is_a_plugin_like_any_other() -> None:
    nuclei = _compiled("nuclei")

    assert nuclei.contract == 1 and nuclei.install is not None
    assert (nuclei.install.name, nuclei.install.repo, nuclei.install.env) == ("nuclei", "projectdiscovery/nuclei", ["PDCP_API_KEY"])
    assert issubclass(nuclei.adapter, ManifestTool) and issubclass(nuclei.record, Finding)
    assert not issubclass(_compiled("httpx").record, Finding)


def test_a_finding_from_a_manifest_reads_like_nuclei_s() -> None:
    finding = _compiled("nuclei").record.from_json("nuclei", LINES["nuclei"], 1)

    assert isinstance(finding, Finding)
    assert (finding.kind, finding.name, finding.severity) == ("vuln", "XSS check", "medium")


def test_a_record_keeps_every_field_of_its_line() -> None:
    host = _compiled("subfinder").record.from_json("subfinder", LINES["subfinder"], 1).as_dict()
    finding = _compiled("nuclei").record.from_json("nuclei", LINES["nuclei"], 1).as_dict()

    assert host["source"] == "crt.sh"
    assert (finding["template-id"], finding["matched-at"]) == ("xss", "https://sub.example.com/")


def test_a_line_cannot_change_what_its_record_is() -> None:
    line = json.dumps({
        "template-id": "x", "matched-at": "https://a.example.com/", "info": {"name": "N", "severity": "high"},
        "kind": "Pod", "target": "elsewhere", "tool": "other", "raw": "forged", "line_number": 99,
        "template_id": "forged", "muted": {"reason": "false positive"},
    })

    record = _compiled("nuclei").record.from_json("nuclei", line, 4)

    assert (record.tool, record.line_number, record.raw, record.target, record.kind) == (
        "nuclei", 4, line, "https://a.example.com/", "vuln",
    )
    assert (record.as_dict()["template_id"], record.as_dict()["muted"], record.as_dict()["info"]) == (
        "x", None, {"name": "N", "severity": "high"},
    )


@pytest.mark.parametrize("line", ["not json", "[1, 2]", "42"])
def test_a_line_that_is_not_a_json_object_is_skipped_as_unparsed(line: str) -> None:
    with pytest.raises(ParseError):
        _compiled("httpx").record.from_json("httpx", line, 1)


def test_a_mapped_value_renders_as_text_and_a_missing_one_as_nothing() -> None:
    naabu = _compiled("naabu").record
    nuclei = _compiled("nuclei").record

    assert naabu.from_json("naabu", '{"host": "10.0.0.1", "port": 8443}', 1).target == "10.0.0.1:8443"
    assert naabu.from_json("naabu", '{"host": "10.0.0.1"}', 1).target == "10.0.0.1:"
    finding = nuclei.from_json("nuclei", '{"matched-at": "https://a.example.com/", "info": {"severity": "low"}}', 1)
    assert (finding.as_dict()["template_id"], finding.as_dict()["info"]) == ("", {"severity": "low"})


def test_output_dir_is_the_session_directory_or_else_the_current_one(tmp_path: Path) -> None:
    text = MANIFESTS["httpx"].replace('command: ["-silent", "-json", "-tls-grab"]', 'command: ["-o", "{output_dir}/httpx.json"]')
    tool = compile_manifest("httpx", parse_manifest(text, where="httpx.yaml")).adapter(ToolSpec(name="httpx", repo="o/h"), BINARY)

    assert tool.build_cmd(ToolContext(target="x", output_dir=tmp_path))[1:3] == ["-o", f"{tmp_path}/httpx.json"]
    assert tool.build_cmd(ToolContext(target="x"))[1:3] == ["-o", "./httpx.json"]


async def test_a_manifest_tool_takes_the_seed_and_a_previous_stage_s_hosts(tmp_path: Path) -> None:
    # A real pipeline: the seed reaches it as its target, an earlier stage's hosts
    # through the list file the engine writes — reduced to bare hosts first.
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import json, sys\n"
        "flag, value = sys.argv[1], sys.argv[2]\n"
        "hosts = [value] if flag == '-u' else open(value, encoding='utf-8').read().split()\n"
        "for host in hosts:\n"
        "    print(json.dumps({'url': f'https://{host}/', 'status_code': 200}))\n",
        encoding="utf-8",
    )
    manifest = parse_manifest(
        "contract: 1\n"
        "install: {source: local}\n"
        f"command: [{json.dumps(probe.as_posix())}]\n"
        'target: ["-u", "{target}"]\n'
        'list: ["-l", "{input_file}"]\n'
        "inputs: host\n"
        "record: {kind: http, target: url}\n",
        where="probe.yaml",
    )
    plugin = compile_manifest("probe", manifest)
    assert plugin.install is not None
    registry_path = tmp_path / "registry.yaml"
    registry_path.write_text("subfinder:\n  repo: org/subfinder\n  asset_patterns: []\n", encoding="utf-8")
    engine = _make_engine(tmp_path, registry_path)
    tools = {
        "subfinder": _StubTool(engine.tool_manager.spec("subfinder"), _stub_binary(tmp_path)),
        "probe": plugin.adapter(plugin.install, Path(sys.executable)),
    }
    engine.build_tool = lambda name: tools[name]  # type: ignore[method-assign]

    alone = await engine.run([Node(tool="probe", stage="live")], seed="https://seed.example.com/login")
    after = await engine.run(
        [Node(tool="subfinder", stage="subdomains"), Node(tool="probe", stage="live")], seed="sub.example.com"
    )

    assert alone.succeeded() and after.succeeded()
    assert [(record.target, record.kind) for record in alone.records] == [("https://seed.example.com/", "http")]
    assert [record.target for record in after.records if record.tool == "probe"] == ["https://sub.example.com/"]


def _odd(kind: str, target: str, line: str) -> ToolRecord:
    """A record of a manifest tool of ``kind``, made from ``line`` as it is."""
    manifest = parse_manifest(
        "contract: 1\n"
        "install: {source: local}\n"
        'target: ["-u", "{target}"]\n'
        'list: ["-l", "{input_file}"]\n'
        f"record: {{kind: {kind}, target: {target}}}\n",
        where="odd.yaml",
    )
    return compile_manifest("odd", manifest).record.from_json("odd", line, 1)


#: Lines holding what no built-in tool's typed schema would let through.
ODD_LINES = [
    ("http", "url", '{"url": "https://a.example.com/", "status_code": "N/A", "info": "probed"}'),
    ("http", "url", '{"url": "https://b.example.com/", "status_code": [301, 200]}'),
    ("reputation", "host", '{"host": "a.example.com", "malicious": "yes", "suspicious": [1], "harmless": {"n": 1}}'),
    ("host", "host", '{"host": "c.example.com", "info": "resolved via 1.1.1.1"}'),
    ("secret", "file", '{"file": "a.env", "rule_id": "aws", "info": "line 3"}'),
    ("screenshot", "url", '{"url": "https://a.example.com/", "filename": "a.png", "status_code": "OK"}'),
    ("scan", "host", '{"host": "d.example.com", "ports_list": 8080}'),
]


def test_reports_read_a_manifest_record_whatever_its_fields_hold(tmp_path: Path) -> None:
    # A built-in tool's schema types its fields; a manifest record keeps what the tool
    # printed. One odd line must cost no report, export, comparison or view.
    records = [_odd(kind, target, line) for kind, target, line in ODD_LINES]
    result = PipelineResult(nodes=[NodeResult(node=Node(tool="odd", stage="odd"), count=len(records))], records=records)
    payload = report_payload(result)
    view = TopologyView([Node(tool="odd", stage="odd")], seed="a.example.com", animate=False)

    for record in records:
        view.on_record(record)
    assert generate_html_report(result, tmp_path / "report.html").is_file()
    assert to_csv(payload).count("\n") == len(records) + 1
    assert to_sarif(payload)["version"] == "2.1.0"
    assert compare(payload, payload).new_findings_at_least("low") == 0
    assert _record_table(records) is not None


def test_a_line_cannot_set_what_cyberfw_records_about_it_later() -> None:
    # Triage marks a finding muted, threat intel rates it, the context store names its
    # stage. A tool's own keys of those names must not pre-empt them, whatever its kind:
    # a secret printed with "muted": true would otherwise be hidden from triage and the diff.
    secret = _odd("secret", "file", '{"file": "a.env", "rule_id": "aws", "muted": true, "intel": {"kev": true}, "stage": "x"}')
    finding = _compiled("nuclei").record.from_json(
        "nuclei", '{"template-id": "x", "matched-at": "https://a.example.com/", "intel": {"kev": true}}', 1
    )

    assert {"muted", "intel", "stage"}.isdisjoint(secret.as_dict())
    assert "intel" not in finding.as_dict() and finding.as_dict()["muted"] is None
