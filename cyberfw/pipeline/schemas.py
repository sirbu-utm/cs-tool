"""Pydantic models validating each tool's JSON Lines output.

Every tool model subclasses :class:`ToolRecord`, which carries the pipeline's
normalised cross-tool view plus the typed fields a specific utility emits.
``validate_record(tool, raw, lineno)`` dispatches on the tool name and either
returns a validated record or raises :class:`ParseError` (a malformed line is
skipped by the executor without aborting the stage).
"""

from __future__ import annotations

import json
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, Field

from cyberfw.exceptions import ParseError

__all__ = [
    "ToolRecord",
    "SubfinderResult",
    "NaabuResult",
    "HttpxResult",
    "FfufResult",
    "NucleiResult",
    "GitleaksResult",
    "GowitnessResult",
    "RustscanResult",
    "validate_record",
]


class ToolRecord(BaseModel):
    """Base of every validated record; carries the pipeline-normalised view.

    .. attribute:: tool
       The registry name that produced this record.

    .. attribute:: line_number
       Its 1-based index within the tool's stdout stream.

    .. attribute:: raw
       The original unparsed line (kept for provenance / diffing).

    .. attribute:: target
       The normalised object the finding relates to (host, URL or file path).

    .. attribute:: kind
       One of ``host | port | http | fuzz | vuln | secret | screenshot | scan``.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    tool: str
    line_number: int = -1
    raw: str = Field(default="", repr=False)
    target: str = ""
    kind: str = "finding"

    @classmethod
    def from_json(cls, tool: str, text: str, lineno: int) -> ToolRecord:
        """Validate one raw JSONL line into this model, raising ``ParseError``."""
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseError(f"[{tool}:{lineno}] invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ParseError(f"[{tool}:{lineno}] expected a JSON object")
        return cls(tool=tool, line_number=lineno, raw=text, **data)

    def as_dict(self) -> dict[str, Any]:
        """Render for the JSONL context store and reports."""
        return self.model_dump(mode="json")


# -- Subfinder -----------------------------------------------------------------
class SubfinderResult(ToolRecord):
    """Passive subdomain discovery: ``{"host", "source", "input"}``."""

    host: str = Field(default="", validation_alias="host")
    source: str = ""

    @classmethod
    def from_json(cls, tool: str, text: str, lineno: int) -> SubfinderResult:
        rec = cast("SubfinderResult", super().from_json(tool, text, lineno))
        rec.target = rec.model_dump().get("host", "")
        rec.kind = "host"
        return rec


# -- Naabu ---------------------------------------------------------------------
class NaabuResult(ToolRecord):
    """Fast port scan: ``{"host", "port", "protocol", "tls"}``."""

    host: str = ""
    port: int = 0
    protocol: str = "tcp"
    tls: bool = False

    @classmethod
    def from_json(cls, tool: str, text: str, lineno: int) -> NaabuResult:
        rec = cast("NaabuResult", super().from_json(tool, text, lineno))
        rec.target = f"{rec.host}:{rec.port}"
        rec.kind = "port"
        return rec


# -- Httpx ---------------------------------------------------------------------
class HttpxResult(ToolRecord):
    """HTTP probing / tech detection: ``{"url", "status_code", ...}``."""

    url: str = ""
    status_code: int = 0
    title: str = ""
    tech: list[str] = Field(default_factory=list)
    webserver: str = ""
    content_length: int = 0

    @classmethod
    def from_json(cls, tool: str, text: str, lineno: int) -> HttpxResult:
        rec = cast("HttpxResult", super().from_json(tool, text, lineno))
        rec.target = rec.url
        rec.kind = "http"
        return rec


# -- Ffuf ----------------------------------------------------------------------
class FfufResult(ToolRecord):
    """Web fuzzing: ``{"input1", "status", "length", "url", "redirectlocation"}``."""

    input1: str = ""
    status: int = 0
    length: int = 0
    url: str = ""
    redirectlocation: str = ""

    @classmethod
    def from_json(cls, tool: str, text: str, lineno: int) -> FfufResult:
        rec = cast("FfufResult", super().from_json(tool, text, lineno))
        rec.target = rec.url
        rec.kind = "fuzz"
        return rec


# -- Nuclei --------------------------------------------------------------------
class NucleiResult(ToolRecord):
    """Template-based vulnerability scan: ``{"template-id", "info", "matched-at"}``."""

    template_id: str = Field(default="", validation_alias="template-id")
    template: str = ""
    matched_at: str = Field(default="", validation_alias="matched-at")
    info: dict[str, Any] = Field(default_factory=dict)

    @property
    def name(self) -> str:
        name = self.info.get("name", "")
        return str(name) if name else self.template_id

    @property
    def severity(self) -> str:
        severity = self.info.get("severity", "")
        return str(severity) if severity else "unknown"

    @classmethod
    def from_json(cls, tool: str, text: str, lineno: int) -> NucleiResult:
        rec = cast("NucleiResult", super().from_json(tool, text, lineno))
        rec.target = rec.matched_at
        rec.kind = "vuln"
        return rec


# -- Gitleaks ------------------------------------------------------------------
class GitleaksResult(ToolRecord):
    """Secret leak in a git repo: ``{"RuleID", "Description", "Secret", "File"}``."""

    rule_id: str = Field(default="", validation_alias="RuleID")
    description: str = Field(default="", validation_alias="Description")
    secret: str = Field(default="", validation_alias="Secret")
    file_path: str = Field(default="", validation_alias="File", alias="File")
    commit: str = Field(default="", validation_alias="Commit")

    @classmethod
    def from_json(cls, tool: str, text: str, lineno: int) -> GitleaksResult:
        rec = cast("GitleaksResult", super().from_json(tool, text, lineno))
        rec.target = rec.file_path
        rec.kind = "secret"
        return rec


# -- Gowitness -----------------------------------------------------------------
class GowitnessResult(ToolRecord):
    """Headless browser screenshot: ``{"url", "title", "filename"}``."""

    url: str = ""
    title: str = ""
    filename: str = ""
    status_code: int = Field(default=0, validation_alias="status_code", alias="status_code")

    @classmethod
    def from_json(cls, tool: str, text: str, lineno: int) -> GowitnessResult:
        rec = cast("GowitnessResult", super().from_json(tool, text, lineno))
        rec.target = rec.url or rec.filename
        rec.kind = "screenshot"
        return rec


# -- RustScan ------------------------------------------------------------------
class RustscanResult(ToolRecord):
    """Port scan (RustScan): ``{"host", "ports_list", "port_state"}``."""

    host: str = ""
    ports_list: str = ""
    port_state: str = "open"

    @classmethod
    def from_json(cls, tool: str, text: str, lineno: int) -> RustscanResult:
        rec = cast("RustscanResult", super().from_json(tool, text, lineno))
        rec.target = rec.host
        rec.kind = "scan"
        return rec


#: Dispatch map — registry name → validating model.
MODELS: dict[str, type[ToolRecord]] = {
    "subfinder": SubfinderResult,
    "naabu": NaabuResult,
    "httpx": HttpxResult,
    "ffuf": FfufResult,
    "nuclei": NucleiResult,
    "gitleaks": GitleaksResult,
    "gowitness": GowitnessResult,
    "rustscan": RustscanResult,
}


def validate_record(tool: str, line: str, lineno: int) -> ToolRecord:
    """Validate one raw JSONL line for ``tool``.

    Raises :class:`ParseError` for malformed or unknown-tool input.
    """
    model = MODELS.get(tool)
    if model is None:
        raise ParseError(f"[{tool}:{lineno}] no schema for tool {tool!r}")
    return model.from_json(tool, line, lineno)
