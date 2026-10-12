"""Silence findings you have already judged, so a re-scan does not nag.

A finding that is a false positive, or a risk the owner has knowingly accepted,
should not reappear as a fresh alarm every scan — nor count as "new" the next
time the run is compared with the previous one. This module keeps a small list
of *mute rules* in ``triage.yaml`` and, after a scan, marks each matching
finding so the report sets it aside and :mod:`cyberfw.report.diff` ignores it.

A rule names a check (``template``, matched case-insensitively; ``*`` for any)
and optionally a ``target`` (an fnmatch pattern tried against the finding's
host and its full URL, so ``*.dev.example.com`` or a single URL both work), a
``reason``, a ``note`` and an ``expires`` date. Nothing here reaches the
network or the scanned host; muting is a local, reversible annotation, never a
change to what was found.
"""

from __future__ import annotations

import fnmatch
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.tools.targets import hostname_of

__all__ = ["REASONS", "Rule", "TriageError", "apply", "load_rules", "save_rules", "new_rule_id"]

#: Why a finding is muted; free text is also allowed but these read best in the report.
REASONS = {
    "false_positive": "false positive",
    "accepted_risk": "accepted risk",
    "wont_fix": "won't fix",
    "other": "muted",
}
#: Record kinds a rule can silence — the finding-shaped ones.
_MUTABLE = frozenset({"vuln", "secret"})
_ID_RE = re.compile(r"^m(\d+)$")


class TriageError(RuntimeError):
    """The triage file is malformed, or a rule is invalid."""


@dataclass
class Rule:
    """One mute: which finding to silence, why, and until when."""

    id: str
    template: str  # check / template id; "*" matches any
    target: str = ""  # fnmatch against the finding's host and URL; "" matches any
    reason: str = "other"
    note: str = ""
    added: str = ""  # ISO date the rule was written
    expires: str = ""  # ISO date; on/after it the rule is inactive

    def active(self, today: date) -> bool:
        """True unless the rule has an expiry date that has passed."""
        if not self.expires:
            return True
        due = _parse_date(self.expires)
        return due is None or today < due

    def matches(self, record: ToolRecord) -> bool:
        """Whether this rule silences ``record`` (a vuln or secret)."""
        if record.kind not in _MUTABLE:
            return False
        if self.template != "*" and self.template.lower() != _check_id(record).lower():
            return False
        if not self.target:
            return True
        pattern = self.target.lower()
        host = hostname_of(record.target).lower()
        where = str(getattr(record, "matched_at", "") or record.target or "").lower()
        return any(fnmatch.fnmatch(value, pattern) for value in (host, where) if value)

    def mark(self) -> dict[str, Any]:
        """The ``muted`` block attached to a finding this rule silences."""
        mark: dict[str, Any] = {"reason": self.reason, "rule": self.id}
        if self.note:
            mark["note"] = self.note
        if self.expires:
            mark["until"] = self.expires
        return mark

    def as_dict(self) -> dict[str, Any]:
        """The rule as it is stored in ``triage.yaml`` (empty fields dropped)."""
        out = {"id": self.id, "template": self.template}
        for key in ("target", "reason", "note", "added", "expires"):
            value = getattr(self, key)
            if value and not (key == "reason" and value == "other"):
                out[key] = value
        return out


@dataclass
class TriageSummary:
    """What :func:`apply` muted, for the console line."""

    muted: int = 0
    by_reason: Counter[str] = field(default_factory=Counter)
    rules_used: set[str] = field(default_factory=set)
    expired: list[str] = field(default_factory=list)  # rule ids skipped as past their expiry

    def line(self) -> str:
        reasons = ", ".join(
            f"{count} {REASONS.get(reason, reason)}" for reason, count in self.by_reason.most_common()
        )
        return f"{self.muted} finding(s) muted by {len(self.rules_used)} rule(s)" + (f" ({reasons})" if reasons else "")


def _check_id(record: ToolRecord) -> str:
    """The id a rule matches on: nuclei/posture ``template_id``, gitleaks ``rule_id``."""
    return str(getattr(record, "template_id", "") or getattr(record, "rule_id", "") or "")


def _parse_date(value: str) -> date | None:
    try:
        return date.fromisoformat(value.strip())
    except (ValueError, AttributeError):
        return None


# -- applying ----------------------------------------------------------------------
def apply(records: list[ToolRecord], rules: list[Rule], *, today: date | None = None) -> TriageSummary:
    """Mark every finding an active rule silences; return what was muted.

    The first matching active rule wins. Expired rules are skipped and named in
    the summary so a lapsed acceptance resurfaces rather than hides silently.
    """
    now = today or date.today()
    active = [r for r in rules if r.active(now)]
    summary = TriageSummary(expired=[r.id for r in rules if not r.active(now)])
    for record in records:
        if record.kind not in _MUTABLE or getattr(record, "muted", None):
            continue
        for rule in active:
            if rule.matches(record):
                record.muted = rule.mark()  # type: ignore[attr-defined]
                summary.muted += 1
                summary.by_reason[rule.reason] += 1
                summary.rules_used.add(rule.id)
                break
    return summary


# -- persistence -------------------------------------------------------------------
def _rule_from(raw: dict[str, Any], index: int) -> Rule:
    if not isinstance(raw, dict):
        raise TriageError(f"mute #{index} is not a mapping")
    template = str(raw.get("template") or raw.get("id") or "").strip()
    if not template:
        raise TriageError(f"mute #{index} has no `template`")
    reason = str(raw.get("reason") or "other").strip()
    return Rule(
        id=str(raw.get("id") or f"m{index}").strip(),
        template=template,
        target=str(raw.get("target") or "").strip(),
        reason=reason,
        note=str(raw.get("note") or "").strip(),
        added=str(raw.get("added") or "").strip(),
        expires=str(raw.get("expires") or "").strip(),
    )


def load_rules(path: Path) -> list[Rule]:
    """Read the mute rules from ``path``; an absent file means no rules."""
    if not path.exists():
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise TriageError(f"cannot read {path}: {exc}") from exc
    if data in (None, ""):
        return []
    mutes = data.get("mutes") if isinstance(data, dict) else data
    if not isinstance(mutes, list):
        raise TriageError(f"{path}: expected a `mutes:` list")
    rules = [_rule_from(raw, index) for index, raw in enumerate(mutes, start=1)]
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            raise TriageError(f"{path}: duplicate mute id {rule.id!r}")
        seen.add(rule.id)
    return rules


_HEADER = (
    "# cyberfw triage — findings to silence on future scans.\n"
    "# Managed with `cyberfw mute` / `cyberfw unmute <id>` / `cyberfw mutes`,\n"
    "# or edited by hand. A mute is a local annotation; it never changes a scan.\n"
)


def save_rules(path: Path, rules: list[Rule]) -> None:
    """Write ``rules`` back to ``path`` (atomically)."""
    body = yaml.safe_dump(
        {"mutes": [rule.as_dict() for rule in rules]}, sort_keys=False, allow_unicode=True
    )
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.tmp")
        tmp.write_text(_HEADER + body, encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        raise TriageError(f"cannot write {path}: {exc}") from exc


def new_rule_id(rules: list[Rule]) -> str:
    """The next free ``m<N>`` id for a list of rules."""
    used = [int(m.group(1)) for rule in rules if (m := _ID_RE.match(rule.id))]
    return f"m{(max(used) + 1) if used else 1}"
