"""The manifest format: what a manifest plugin writes instead of Python, and how it is checked."""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from cyberfw.exceptions import ContractError, ManifestError
from cyberfw.tools.manifest import FindingSpec, Manifest, RecordSpec, parse_manifest

from .test_plugin_contract import _fields

#: Four built-in tools written as manifests — what a plugin author would write for them.
MANIFESTS = {
    "subfinder": """
contract: 1
install: {repo: projectdiscovery/subfinder, asset_patterns: ["subfinder_*_linux_amd64.zip"]}
command: ["-silent", "-json"]
target: ["-d", "{target}"]
list: ["-dL", "{input_file}"]
inputs: host
record: {kind: host, target: host}
""",
    "httpx": """
contract: 1
install: {repo: projectdiscovery/httpx, asset_patterns: ["httpx_*_linux_amd64.zip"]}
command: ["-silent", "-json", "-tls-grab"]
target: ["-u", "{target}"]
list: ["-l", "{input_file}"]
rate: ["-rate-limit", "{rate}"]
record: {kind: http, target: url}
""",
    "naabu": """
contract: 1
install: {repo: projectdiscovery/naabu, asset_patterns: ["naabu_*_linux_amd64.zip"]}
command: ["-silent", "-json"]
target: ["-host", "{target}"]
list: ["-iL", "{input_file}"]
rate: ["-rate", "{rate}"]
inputs: host
target_prompt: "Target host, IP or URL"
record: {kind: port, target: "{host}:{port}"}
""",
    "nuclei": """
contract: 1
install: {repo: projectdiscovery/nuclei, asset_patterns: ["nuclei_*_linux_amd64.zip"], env: [PDCP_API_KEY]}
command: ["-silent", "-jsonl"]
target: ["-u", "{target}"]
list: ["-l", "{input_file}"]
severity: ["-severity", "{severity}"]
tags: ["-tags", "{tags}"]
rate: ["-rate-limit", "{rate}"]
record:
  kind: vuln
  target: matched-at
  finding:
    template_id: template-id
    name: info.name
    severity: info.severity
    description: info.description
    remediation: info.remediation
""",
}

#: What contract 1's manifest format promises authors: its keys, their types and
#: defaults. A change here changes what manifests may say — decide whether the
#: contract moves (see cyberfw/plugin.py) before recording it.
FORMAT_1: dict[str, list[str]] = {
    "Manifest": [
        "contract: <class 'int'> = <required>",
        "install: <class 'cyberfw.manager.registry.ToolSpec'> = <required>",
        "command: list[str] = <factory list>",
        "target: list[str] = <required>",
        "host_list: list[str] = <factory list> (alias 'list')",
        "severity: list[str] = <factory list>",
        "tags: list[str] = <factory list>",
        "rate: list[str] = <factory list>",
        "per_target: <class 'bool'> = False",
        "inputs: typing.Literal['any', 'host'] = 'any'",
        "target_prompt: <class 'str'> = 'Target (domain, URL or host)'",
        "record: <class 'cyberfw.tools.manifest.RecordSpec'> = <required>"
    ],
    "RecordSpec": [
        "kind: <class 'str'> = <required>",
        "target: <class 'str'> = <required>",
        "finding: cyberfw.tools.manifest.FindingSpec | None = None"
    ],
    "FindingSpec": [
        "template_id: <class 'str'> = ''",
        "matched_at: <class 'str'> = ''",
        "name: <class 'str'> = ''",
        "severity: <class 'str'> = ''",
        "description: <class 'str'> = ''",
        "remediation: <class 'str'> = ''"
    ]
}


def _nuclei(**changes: Any) -> dict[str, Any]:
    """nuclei's manifest as data, with ``changes`` applied (``None`` drops a key)."""
    data: dict[str, Any] = yaml.safe_load(MANIFESTS["nuclei"])
    for key, value in changes.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    return data


def _check(data: dict[str, Any]) -> Manifest:
    return parse_manifest(yaml.safe_dump(data), where="nuclei.yaml")


@pytest.mark.parametrize("name", sorted(MANIFESTS))
def test_the_built_in_tools_can_be_written_as_manifests(name: str) -> None:
    manifest = parse_manifest(MANIFESTS[name], where=f"{name}.yaml")

    assert manifest.contract == 1 and manifest.target and manifest.host_list


def test_a_manifest_reads_as_written() -> None:
    manifest = parse_manifest(MANIFESTS["nuclei"], where="nuclei.yaml")

    assert manifest.install.repo == "projectdiscovery/nuclei" and manifest.install.env == ["PDCP_API_KEY"]
    assert (manifest.host_list, manifest.severity, manifest.inputs) == (["-l", "{input_file}"], ["-severity", "{severity}"], "any")
    assert manifest.record.finding is not None and manifest.record.finding.name == "info.name"


@pytest.mark.parametrize(
    ("data", "said"),
    [
        (_nuclei(comand=["-x"]), "comand: unknown key"),
        (_nuclei(install={"repo": "a/b", "sha256": "00"}), "install: unknown key 'sha256'"),
        (_nuclei(install={"repo": "a/b", "name": "other"}), "install: name: the tool's name is its entry point's"),
        (_nuclei(record=None), "record: Field required"),
        (_nuclei(target=None), "target: Field required"),
        (_nuclei(record={"kind": "host", "target": "host", "finding": {"name": "x"}}), "finding: only a vuln record is a finding"),
        (_nuclei(record={"kind": "vuln", "target": "matched-at"}), "finding: required for kind vuln"),
        (_nuclei(record={"kind": "Vuln!", "target": "x", "finding": {}}), "record.kind: String should match pattern"),
        (_nuclei(target=["-u", "{host}"]), "target: unknown placeholder {host} — it may use {output_dir}, {target}"),
        (_nuclei(target=["-u"]), "target: must pass {target}"),
        (_nuclei(rate=["-rate-limit", "{target}"]), "rate: unknown placeholder {target}"),
        (_nuclei(command=["-o", "{rate}"]), "command: unknown placeholder {rate} — it may use {output_dir}"),
        (_nuclei(per_target=True), "list: a per_target tool runs once per host and never takes a list"),
        (_nuclei(list=None), "list: required unless per_target is true"),
        (_nuclei(inputs="url"), "inputs: Input should be 'any' or 'host'"),
    ],
)
def test_a_mistake_in_a_manifest_is_named(data: dict[str, Any], said: str) -> None:
    with pytest.raises(ManifestError, match="^nuclei.yaml: ") as caught:
        _check(data)

    assert said in str(caught.value)


@pytest.mark.parametrize(
    ("text", "said"),
    [
        ("contract: [1", "not valid YAML"),
        ("- contract: 1\n", "a manifest is a mapping of keys"),
        ("install: {repo: a/b}\n", "contract: required"),
        ("contract: yes\n", "contract: required"),
    ],
)
def test_a_manifest_that_is_not_one_is_named(text: str, said: str) -> None:
    with pytest.raises(ManifestError, match=said):
        parse_manifest(text, where="foo.yaml")


def test_a_manifest_for_a_newer_contract_is_incompatible_not_broken() -> None:
    # Contract 2 may add keys contract 1 does not know: the version is read first.
    newer = _nuclei(contract=2, retries=3)

    with pytest.raises(ContractError, match="nuclei.yaml: written for plugin contract 2; this cyberfw loads 1"):
        _check(newer)


def test_a_per_target_tool_needs_no_list() -> None:
    manifest = _check(_nuclei(per_target=True, list=None))

    assert manifest.per_target and manifest.host_list == []


def test_the_manifest_format_is_what_contract_1_promises() -> None:
    assert {model.__name__: _fields(model) for model in (Manifest, RecordSpec, FindingSpec)} == FORMAT_1
