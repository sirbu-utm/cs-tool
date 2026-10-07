"""Plain data carried between the bot's layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

__all__ = ["Finding", "Summary", "Scan", "SEVERITY_ORDER"]

#: nuclei severities, most serious first; anything else folds into "unknown".
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info", "unknown")


@dataclass(frozen=True)
class Finding:
    """One nuclei vulnerability, normalised for display."""

    name: str
    severity: str
    target: str
    template_id: str


@dataclass(frozen=True)
class Summary:
    """What a scan produced, reduced to what a message needs."""

    ok: bool
    severity_counts: dict[str, int]
    findings: list[Finding]
    subdomains: int = 0
    live_hosts: int = 0
    duration_s: float | None = None

    @property
    def total_findings(self) -> int:
        return sum(self.severity_counts.values())

    @property
    def has_serious(self) -> bool:
        return bool(self.severity_counts.get("critical") or self.severity_counts.get("high"))


@dataclass
class Scan:
    """A scan request and its lifecycle, mirrored in sqlite."""

    id: str
    user_id: int
    chat_id: int
    target: str
    username: str | None = None  # Telegram @username (or None / "web")
    status: str = "queued"  # queued | running | done | failed | cancelled
    created_at: datetime | None = None
    finished_at: datetime | None = None
    exit_code: int | None = None
    error: str | None = None
    report_json: str | None = None
    report_html: str | None = None
    summary: Summary | None = field(default=None, repr=False)
