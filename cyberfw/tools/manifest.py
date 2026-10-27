"""The manifest format: a tool described as data instead of Python.

A manifest plugin ships one YAML file per tool — how to run it, and how each JSON
line it prints becomes a record — and cyberfw runs it with a generic adapter
(:mod:`cyberfw.tools.manifest_tool`), so no Python of the plugin's own ever runs
inside cyberfw. Contract 1's format::

    contract: 1
    install:                          # the same keys as an entry in registry.yaml
      repo: acme/foo
      asset_patterns: ["foo_*_linux_amd64.zip", "foo_*_windows_amd64.zip"]
      env: [FOO_API_KEY]              # extra environment variables the tool is given
    command: ["-json", "-silent"]     # always, right after the binary
    target: ["-u", "{target}"]        # a stage with one target
    list: ["-l", "{input_file}"]      # a stage given hosts (the engine writes the file)
    severity: ["-severity", "{severity}"]  # only with a severity filter set;
    tags: ["-tags", "{tags}"]              # likewise a tags filter,
    rate: ["-rate-limit", "{rate}"]        # and a rate limit
    per_target: false                 # true: one process per host, instead of a list
    inputs: any                       # any | host — host reduces URLs to bare hostnames
    target_prompt: "Target URL"       # what the launcher asks for
    record:
      kind: vuln                      # host, port, http, … — or vuln for findings
      target: matched-at              # a field path, or a template: "{host}:{port}"
      finding:                        # kind vuln only: where the finding's fields come from
        template_id: template-id
        name: info.name
        severity: info.severity
        description: info.description

The command is the binary, ``command``, the recipe's static flags, then
``severity``, ``tags`` and ``rate`` when set, then ``target`` or ``list``. Each
argument list uses its own placeholder and may use ``{output_dir}`` (the
session directory; the current one for a run without a session). A tool runs
either once per host (``per_target``) or on a ``list`` of them.
"""

from __future__ import annotations

import re
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from cyberfw.exceptions import ContractError, ManifestError
from cyberfw.plugin import SUPPORTED_CONTRACTS, BaseTool, ToolSpec

__all__ = ["FindingSpec", "Manifest", "RecordSpec", "parse_manifest"]

#: A ``{name}`` in an argument or a record template.
PLACEHOLDER = re.compile(r"\{([^{}]*)\}")

#: The placeholder each argument list fills — and must pass; ``command`` passes none.
OWN_PLACEHOLDER = {
    "command": None,
    "target": "target",
    "list": "input_file",
    "severity": "severity",
    "tags": "tags",
    "rate": "rate",
}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FindingSpec(_Strict):
    """Where a finding's own fields come from — each a field path of the line or a
    template of them; ``matched_at`` defaults to the record's target."""

    template_id: str = ""
    matched_at: str = ""
    name: str = ""
    severity: str = ""
    description: str = ""
    remediation: str = ""


class RecordSpec(_Strict):
    """How a line becomes a record: its kind, its target, and for a finding the rest."""

    kind: str = Field(pattern=r"^[a-z][a-z0-9_-]*$")
    #: A field path (``matched-at``, ``info.name``) or a template of them (``{host}:{port}``).
    target: str = Field(min_length=1)
    finding: FindingSpec | None = None

    @model_validator(mode="after")
    def _a_finding_is_a_vuln(self) -> RecordSpec:
        if self.kind == "vuln" and self.finding is None:
            raise ValueError("finding: required for kind vuln — where the finding's name and severity come from")
        if self.kind != "vuln" and self.finding is not None:
            raise ValueError(f"finding: only a vuln record is a finding, this one is {self.kind!r}")
        return self


class Manifest(_Strict):
    """One tool, as its manifest describes it (see the module docstring)."""

    contract: int
    install: ToolSpec
    command: list[str] = Field(default_factory=list)
    target: list[str] = Field(min_length=1)
    host_list: list[str] = Field(default_factory=list, alias="list")
    severity: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    rate: list[str] = Field(default_factory=list)
    per_target: bool = False
    inputs: Literal["any", "host"] = "any"
    target_prompt: str = BaseTool.target_prompt
    record: RecordSpec

    @field_validator("install", mode="before")
    @classmethod
    def _only_recipe_keys(cls, value: Any) -> Any:
        # registry.yaml tolerates unknown keys; a manifest must not hide a typo.
        if isinstance(value, dict):
            if "name" in value:
                raise ValueError("name: the tool's name is its entry point's, not the recipe's")
            unknown = sorted(set(value) - set(ToolSpec.model_fields))
            if unknown:
                raise ValueError(f"unknown key {unknown[0]!r}")
        return value

    @model_validator(mode="after")
    def _arguments_pass_their_own_placeholder(self) -> Manifest:
        for key, own in OWN_PLACEHOLDER.items():
            args: list[str] = self.host_list if key == "list" else getattr(self, key)
            used = {name for arg in args for name in PLACEHOLDER.findall(arg)}
            allowed = {"output_dir"} | ({own} if own else set())
            unknown = sorted(used - allowed)
            if unknown:
                names = ", ".join(f"{{{name}}}" for name in sorted(allowed))
                raise ValueError(f"{key}: unknown placeholder {{{unknown[0]}}} — it may use {names}")
            if args and own and own not in used:
                raise ValueError(f"{key}: must pass {{{own}}}")
        if self.per_target and self.host_list:
            raise ValueError("list: a per_target tool runs once per host and never takes a list")
        if not self.per_target and not self.host_list:
            raise ValueError("list: required unless per_target is true — how the tool takes a previous stage's hosts")
        return self


def parse_manifest(text: str, *, where: str) -> Manifest:
    """Check a manifest's YAML; ``where`` names it in messages.

    Raises :class:`ContractError` for a contract this cyberfw does not load —
    checked first, so a newer manifest's new keys never read as mistakes — and
    :class:`ManifestError` for anything else wrong, naming the key.
    """
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ManifestError(f"{where}: not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError(f"{where}: a manifest is a mapping of keys")
    contract = data.get("contract")
    if isinstance(contract, bool) or not isinstance(contract, int):
        raise ManifestError(f"{where}: contract: required — the plugin contract version it is written for, a number")
    if contract not in SUPPORTED_CONTRACTS:
        loads = ", ".join(str(version) for version in sorted(SUPPORTED_CONTRACTS))
        raise ContractError(f"{where}: written for plugin contract {contract}; this cyberfw loads {loads}")
    try:
        return Manifest.model_validate(data)
    except ValidationError as exc:
        raise ManifestError(f"{where}: {_explain(exc)}") from exc


def _explain(exc: ValidationError) -> str:
    """pydantic's errors as ``key: what is wrong``, one after another."""
    parts: list[str] = []
    for error in exc.errors():
        where = ".".join(str(part) for part in error["loc"])
        message = "unknown key" if error["type"] == "extra_forbidden" else error["msg"].removeprefix("Value error, ")
        parts.append(f"{where}: {message}" if where else message)
    return "; ".join(parts)
