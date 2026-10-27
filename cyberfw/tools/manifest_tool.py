"""Running a manifest tool: one generic adapter and record model, made into each tool's own.

:func:`compile_manifest` turns a checked :class:`~cyberfw.tools.manifest.Manifest`
into a :class:`~cyberfw.plugin.ToolPlugin` — a subclass of :class:`ManifestTool`
and one of :class:`ManifestRecord` (or :class:`ManifestFinding`) that carry the
manifest — so from then on the registry, the lock, the engine and the reports
treat the tool like any other.

A record keeps every field of the line it comes from, so ``report.json`` and the
CSV export carry the tool's own data. Its own fields — ``tool``, ``line_number``,
``raw``, ``target``, ``kind``, and a finding's ``template_id``, ``matched_at``,
``info`` and ``muted`` — are cyberfw's: they come from the manifest's mapping,
never from a key of the line that happens to share the name.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar, cast

from pydantic import ConfigDict, ValidationError, create_model

from cyberfw.plugin import (
    BaseTool,
    Finding,
    ParseError,
    ToolContext,
    ToolPlugin,
    ToolRecord,
    ToolSpec,
)
from cyberfw.tools.manifest import PLACEHOLDER, Manifest, RecordSpec
from cyberfw.tools.targets import hostname_of

__all__ = ["ManifestFinding", "ManifestRecord", "ManifestTool", "compile_manifest"]


def _value(data: dict[str, Any], path: str) -> Any:
    """The value at a dotted field path of the line (``info.name``), or ``None``."""
    value: Any = data
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _render(spec: str, data: dict[str, Any]) -> str:
    """A field path's value as text — or, for a template, each ``{path}`` filled in;
    a field the line does not have is empty."""
    if "{" not in spec:
        value = _value(data, spec)
        return "" if value is None else str(value)
    return PLACEHOLDER.sub(lambda match: _render(match[1], data), spec)


def _mapped(mapping: RecordSpec, data: dict[str, Any]) -> dict[str, Any]:
    """The record's own fields, as the manifest maps them from the line."""
    target = _render(mapping.target, data)
    fields: dict[str, Any] = {"target": target, "kind": mapping.kind}
    finding = mapping.finding
    if finding is not None:
        info = {
            key: _render(path, data)
            for key, path in (
                ("name", finding.name),
                ("severity", finding.severity),
                ("description", finding.description),
                ("remediation", finding.remediation),
            )
            if path
        }
        fields["template_id"] = _render(finding.template_id, data) if finding.template_id else ""
        fields["matched_at"] = _render(finding.matched_at, data) if finding.matched_at else target
        fields["info"] = {key: value for key, value in info.items() if value}
    return fields


def _from_line(cls: type[ManifestRecord] | type[ManifestFinding], tool: str, text: str, lineno: int) -> ToolRecord:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError(f"[{tool}:{lineno}] invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError(f"[{tool}:{lineno}] expected a JSON object")
    theirs = {key: value for key, value in data.items() if key not in cls.model_fields}
    try:
        return cls(**theirs, **_mapped(cls.mapping, data), tool=tool, line_number=lineno, raw=text)
    except ValidationError as exc:
        raise ParseError(f"[{tool}:{lineno}] {exc}") from exc


class ManifestRecord(ToolRecord):
    """A manifest tool's record: every field of its line, ``target`` and ``kind`` as mapped."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)
    #: The manifest's ``record`` block — set on each tool's own subclass.
    mapping: ClassVar[RecordSpec]

    @classmethod
    def from_json(cls, tool: str, text: str, lineno: int) -> ToolRecord:
        return _from_line(cls, tool, text, lineno)


class ManifestFinding(Finding):
    """A manifest tool's finding: a :class:`ManifestRecord` that is a :class:`Finding`."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)
    #: The manifest's ``record`` block — set on each tool's own subclass.
    mapping: ClassVar[RecordSpec]

    @classmethod
    def from_json(cls, tool: str, text: str, lineno: int) -> ToolRecord:
        return _from_line(cls, tool, text, lineno)


def _fill(args: list[str], values: dict[str, str]) -> list[str]:
    return [PLACEHOLDER.sub(lambda match: values[match[1]], arg) for arg in args]


class ManifestTool(BaseTool):
    """The adapter of a manifest tool — each tool gets its own subclass, made by
    :func:`compile_manifest`, that carries its manifest and record model."""

    manifest: ClassVar[Manifest]
    record: ClassVar[type[ToolRecord]]

    @property
    def input_flag(self) -> str | None:
        return self.manifest.host_list[0] if self.manifest.host_list else None

    def prepare_inputs(self, inputs: list[str]) -> list[str]:
        return [hostname_of(item) for item in inputs] if self.manifest.inputs == "host" else inputs

    def build_cmd(self, ctx: ToolContext) -> list[str]:
        manifest, controls = self.manifest, ctx.controls
        values = {"output_dir": str(ctx.output_dir) if ctx.output_dir is not None else "."}
        cmd = [str(self.binary), *_fill(manifest.command, values), *self.static_flags()]
        rate = str(controls.rate_limit) if controls.rate_limit else ""
        for args, name, value in (
            (manifest.severity, "severity", controls.severity),
            (manifest.tags, "tags", controls.tags),
            (manifest.rate, "rate", rate),
        ):
            if args and value:
                cmd += _fill(args, {**values, name: value})
        if ctx.target:
            target = hostname_of(ctx.target) if manifest.inputs == "host" else ctx.target
            cmd += _fill(manifest.target, {**values, "target": target})
        elif ctx.input_file is not None and manifest.host_list:
            cmd += _fill(manifest.host_list, {**values, "input_file": str(ctx.input_file)})
        return cmd

    def parse_line(self, line: str, lineno: int) -> ToolRecord:
        return self.record.from_json(self.name, line, lineno)


def compile_manifest(name: str, manifest: Manifest) -> ToolPlugin:
    """The :class:`ToolPlugin` of the manifest tool ``name``: an adapter and a record
    model made for it, and its install recipe with its name filled in."""
    base: type[ManifestRecord] | type[ManifestFinding] = (
        ManifestFinding if manifest.record.finding is not None else ManifestRecord
    )
    record = cast("type[ManifestRecord] | type[ManifestFinding]", create_model(f"{base.__name__}_{name}", __base__=base, __module__=__name__))
    record.mapping = manifest.record
    adapter = type(
        f"ManifestTool_{name}",
        (ManifestTool,),
        {
            "__module__": __name__,
            "manifest": manifest,
            "record": record,
            "per_target": manifest.per_target,
            "target_prompt": manifest.target_prompt,
        },
    )
    install = ToolSpec.model_validate({**manifest.install.model_dump(), "name": name})
    return ToolPlugin(contract=manifest.contract, adapter=adapter, record=record, install=install)
