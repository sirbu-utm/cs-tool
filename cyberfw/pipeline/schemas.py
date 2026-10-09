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

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

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
    "VirusTotalResult",
    "CveIntel",
    "PostureFinding",
    "MailSecurity",
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
    """HTTP probing / tech detection: ``{"url", "status_code", ...}``.

    ``tls`` is httpx's ``-tls-grab`` block for an HTTPS URL (certificate subject,
    SANs, issuer, ``not_after``, negotiated version, and ``expired`` /
    ``self_signed`` / ``mismatched`` flags when true). It stays a raw mapping —
    read leniently by :mod:`cyberfw.posture.tls` — so an unexpected shape there
    can never cost the whole live-host record.
    """

    url: str = ""
    status_code: int = 0
    title: str = ""
    tech: list[str] = Field(default_factory=list)
    webserver: str = ""
    content_length: int = 0
    tls: dict[str, Any] | None = None

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
class CveIntel(BaseModel):
    """How urgent a CVE finding is, from public feeds (see :mod:`cyberfw.threatintel`).

    Not something nuclei prints: attached to a finding after the scan, from
    CISA KEV, EPSS and Exploit-DB, looked up by CVE id only.
    """

    cves: list[str] = Field(default_factory=list)
    #: ``now`` — exploited in real attacks (KEV); ``soon`` — likely to be
    #: (high EPSS) or a public exploit exists; ``""`` — no signal.
    priority: str = ""
    kev: bool = False
    kev_added: str = ""
    kev_due: str = ""
    ransomware: bool = False
    epss: float | None = None
    epss_percentile: float | None = None
    exploits: list[str] = Field(default_factory=list)
    metasploit: bool = False


class NucleiResult(ToolRecord):
    """Template-based vulnerability scan: ``{"template-id", "info", "matched-at"}``."""

    template_id: str = Field(default="", validation_alias="template-id")
    template: str = ""
    matched_at: str = Field(default="", validation_alias="matched-at")
    info: dict[str, Any] = Field(default_factory=dict)
    intel: CveIntel | None = None

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
    """Headless browser screenshot: ``{"url", "title", "file_name", "response_code"}``.

    gowitness v3 names the image ``file_name`` and the HTTP status
    ``response_code``; the v2-era ``filename`` / ``status_code`` are still read.
    """

    url: str = ""
    title: str = ""
    filename: str = Field(default="", validation_alias=AliasChoices("file_name", "filename"))
    status_code: int = Field(default=0, validation_alias=AliasChoices("response_code", "status_code"))

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


class VirusTotalResult(ToolRecord):
    """VirusTotal reputation: ``{"target", "vt_kind", "malicious", "suspicious", ...}``.

    Not a downloaded binary — emitted by the reputation enrichment (see
    :mod:`cyberfw.vt`), but validated like every other record.
    """

    vt_kind: str = ""
    found: bool = False
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int = 0
    categories: list[str] = Field(default_factory=list)
    permalink: str = ""

    @classmethod
    def from_json(cls, tool: str, text: str, lineno: int) -> VirusTotalResult:
        rec = cast("VirusTotalResult", super().from_json(tool, text, lineno))
        rec.kind = "reputation"
        return rec


class PostureFinding(ToolRecord):
    """A finding cyberfw works out itself (TLS certificates, email spoofing).

    Shaped like a nuclei finding — ``template_id``, ``matched_at`` and an
    ``info`` block with ``name`` / ``severity`` / ``description`` /
    ``remediation`` — so the report and every reader of ``report.json`` treat it
    exactly like one. ``tool`` names the check (``tlscheck`` / ``mailcheck``).
    """

    template_id: str = ""
    matched_at: str = ""
    info: dict[str, Any] = Field(default_factory=dict)

    @property
    def name(self) -> str:
        return str(self.info.get("name") or self.template_id)

    @property
    def severity(self) -> str:
        return str(self.info.get("severity") or "unknown")

    @classmethod
    def make(
        cls,
        tool: str,
        check_id: str,
        target: str,
        *,
        name: str,
        severity: str,
        description: str,
        remediation: str,
        tags: list[str] | None = None,
    ) -> PostureFinding:
        return cls(
            tool=tool,
            kind="vuln",
            target=target,
            template_id=check_id,
            matched_at=target,
            info={
                "name": name,
                "severity": severity,
                "description": description,
                "remediation": remediation,
                "tags": tags or [],
            },
        )


class MailSecurity(ToolRecord):
    """Whether mail can be forged as a domain (kind ``mail``): SPF, DMARC, MX.

    ``verdict`` is ``protected`` (DMARC rejects or quarantines all forged mail),
    ``partial`` (enforced, but not for every message or subdomain) or
    ``spoofable``. Built by :mod:`cyberfw.posture.mail`.
    """

    domain: str = ""
    verdict: str = ""
    mx: list[str] = Field(default_factory=list)
    spf: str = ""
    spf_all: str = ""
    dmarc: str = ""
    dmarc_domain: str = ""
    dmarc_policy: str = ""
    dmarc_subdomain_policy: str = ""
    dmarc_pct: int = 100


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
    "virustotal": VirusTotalResult,
}


def validate_record(tool: str, line: str, lineno: int) -> ToolRecord:
    """Validate one raw JSONL line for ``tool``.

    Raises :class:`ParseError` for malformed or unknown-tool input.
    """
    model = MODELS.get(tool)
    if model is None:
        raise ParseError(f"[{tool}:{lineno}] no schema for tool {tool!r}")
    return model.from_json(tool, line, lineno)
