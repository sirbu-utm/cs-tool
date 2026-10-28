"""What changed since an earlier run of the same scan.

A scan is a snapshot; run it again a week later and the useful part is the
difference: a subdomain that appeared, a port that opened, a finding that is
new — or gone — a certificate that was renewed, a CVE that has since entered
CISA's catalog of exploited vulnerabilities. This module compares two
``report.json`` documents (the earlier one read from disk, the current one
built in memory by :func:`~cyberfw.report.json_report.report_payload`).

Absence is only trusted where the tool that would have reported something
completed in *both* runs. If nuclei failed this time, its findings are not
"gone"; if the earlier run predates the TLS check, its certificate findings
are not "new". Such results are skipped and named in ``not_compared``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cyberfw.pipeline.schemas import as_int
from cyberfw.tools.targets import hostname_of

__all__ = ["Change", "RunDiff", "compare", "coverage", "find_baseline", "load_report", "resolve_report"]

BAD, NEUTRAL, GOOD = "bad", "neutral", "good"
#: Severities that count as a real finding; info / unknown changes are listed but not alarming.
REAL = ("critical", "high", "medium", "low")
_SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown", "")
_AREAS = ("finding", "secret", "email", "reputation", "certificate", "port", "subdomain", "web", "path")
_TONES = (BAD, NEUTRAL, GOOD)
_ADDED = {
    "finding": "new finding", "secret": "new secret", "port": "port opened",
    "subdomain": "new subdomain", "web": "new web service", "path": "new path",
}
_REMOVED = {
    "finding": "gone", "secret": "secret gone", "port": "port closed",
    "subdomain": "subdomain gone", "web": "web service gone", "path": "path gone",
}
_VERDICT_RANK = {"protected": 0, "partial": 1, "spoofable": 2}


@dataclass(frozen=True)
class Change:
    """One difference between the runs, ready to print."""

    area: str  # see _AREAS
    status: str  # added | removed | changed
    label: str  # "new finding", "port closed", "renewed", ...
    subject: str  # the host / URL / host:port / finding name it is about
    detail: str = ""
    severity: str = ""  # findings only
    tone: str = NEUTRAL  # bad | neutral | good, for the owner

    def as_dict(self) -> dict[str, str]:
        return {
            "area": self.area, "status": self.status, "label": self.label, "subject": self.subject,
            "detail": self.detail, "severity": self.severity, "tone": self.tone,
        }


@dataclass
class RunDiff:
    """Every change since ``baseline`` (the earlier run's provenance)."""

    baseline: dict[str, Any]
    changes: list[Change] = field(default_factory=list)
    not_compared: list[str] = field(default_factory=list)

    def _count(self, area: str, status: str, *, real: bool | None = None) -> int:
        return sum(
            1
            for c in self.changes
            if c.area == area and c.status == status and (real is None or (c.severity in REAL) == real)
        )

    @property
    def new_findings(self) -> int:
        """Findings of severity low or worse that the earlier run did not have."""
        return self._count("finding", "added", real=True)

    def new_findings_at_least(self, level: str) -> int:
        """Newly added findings whose severity is ``level`` or worse.

        ``level`` is one of :data:`REAL` (``critical`` < ``high`` < ``medium``
        < ``low``). ``info`` / unknown findings never count, so this is a
        refinement of :attr:`new_findings` (which is the ``low`` case)."""
        cutoff = REAL.index(level)
        return sum(
            1
            for c in self.changes
            if c.area == "finding" and c.status == "added" and c.severity in REAL and REAL.index(c.severity) <= cutoff
        )

    def summary(self) -> list[str]:
        """Short phrases — ``["2 new findings", "1 port opened"]``; empty when nothing changed."""
        info = self._count("finding", "added", real=False) + self._count("finding", "removed", real=False)
        parts = [
            _n(self.new_findings, "new finding"),
            _n(self._count("finding", "removed", real=True), "finding gone", "findings gone"),
            _n(self._count("finding", "changed"), "now exploited in the wild", "now exploited in the wild"),
            _n(self._count("secret", "added"), "new secret"),
            _n(self._count("secret", "removed"), "secret gone", "secrets gone"),
            _n(self._count("port", "added"), "port opened", "ports opened"),
            _n(self._count("port", "removed"), "port closed", "ports closed"),
            _n(self._count("subdomain", "added"), "new subdomain"),
            _n(self._count("subdomain", "removed"), "subdomain gone", "subdomains gone"),
            _n(self._count("web", "added"), "new web service"),
            _n(self._count("web", "removed"), "web service gone", "web services gone"),
            _n(self._count("web", "changed"), "HTTP status change"),
            _n(self._count("path", "added"), "new path"),
            _n(self._count("path", "removed"), "path gone", "paths gone"),
            _n(sum(1 for c in self.changes if c.area == "certificate" and c.label == "renewed"),
               "certificate renewed", "certificates renewed"),
            _n(sum(1 for c in self.changes if c.area == "reputation" and c.tone == BAD),
               "newly flagged on VirusTotal", "newly flagged on VirusTotal"),
            _n(sum(1 for c in self.changes if c.area == "reputation" and c.tone == GOOD),
               "no longer flagged on VirusTotal", "no longer flagged on VirusTotal"),
            _n(info, "info-level finding change"),
        ]
        parts += [f"email {c.subject}: {c.detail}" for c in self.changes if c.area == "email"]
        return [part for part in parts if part]

    def as_dict(self) -> dict[str, Any]:
        """The ``changes`` block of ``report.json``."""
        return {
            "baseline": self.baseline,
            "summary": self.summary(),
            "changes": [c.as_dict() for c in self.changes],
            "not_compared": self.not_compared,
        }


def _n(count: int, singular: str, plural: str | None = None) -> str:
    if not count:
        return ""
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


# -- what each record is, across runs ------------------------------------------------
@dataclass(frozen=True)
class _Item:
    area: str
    tool: str
    subject: str
    detail: str = ""
    severity: str = ""
    state: Any = None  # compared for "changed"
    tracked: bool = True  # whether appearing / disappearing means anything


def _mapping(value: object) -> dict[str, Any]:
    """``value`` if it is a JSON object, else an empty one (a report may be hand-edited)."""
    return value if isinstance(value, dict) else {}


def _url_key(url: str) -> str:
    """``HTTPS://A.example.com:443/`` → ``https://a.example.com``; non-URLs are lower-cased."""
    text = url.strip()
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return text.lower()
    if not parts.scheme or not parts.hostname:
        return text.lower()
    scheme = parts.scheme.lower()
    netloc = parts.hostname if port in (None, {"http": 80, "https": 443}.get(scheme)) else f"{parts.hostname}:{port}"
    query = f"?{parts.query}" if parts.query else ""
    return f"{scheme}://{netloc}{parts.path.rstrip('/')}{query}"


def _matcher(record: dict[str, Any]) -> str:
    """nuclei's ``matcher-name`` (kept only in the raw line): one template can match a URL twice."""
    try:
        raw = json.loads(record.get("raw") or "{}")
    except ValueError:
        return ""
    return str(raw.get("matcher-name") or "") if isinstance(raw, dict) else ""


def _items(record: dict[str, Any]) -> list[tuple[tuple[str, str], _Item]]:
    """The comparable things one ``report.json`` record stands for."""
    kind, tool = record.get("kind"), str(record.get("tool") or "")
    target = str(record.get("target") or "")
    if kind == "host":
        host = str(record.get("host") or target).lower().rstrip(".")
        return [(("subdomain", host), _Item("subdomain", tool, host))] if host else []
    if kind == "http":
        url = str(record.get("url") or target)
        status = record.get("status_code")
        out = [(("web", _url_key(url)), _Item("web", tool, url, detail=f"HTTP {status}", state=status))]
        tls = record.get("tls")
        if isinstance(tls, dict) and tls.get("not_after"):
            host = str(tls.get("host") or hostname_of(url)).lower()
            port = str(tls.get("port") or "443")
            name = host if port == "443" else f"{host}:{port}"
            out.append((("certificate", name),
                        _Item("certificate", tool, name, state=str(tls["not_after"]), tracked=False)))
        return out
    if kind == "port":
        return [(("port", target.lower()), _Item("port", tool, target))] if target else []
    if kind == "scan":
        host = str(record.get("host") or target).lower()
        ports = [p.strip() for p in str(record.get("ports_list") or "").split(",") if p.strip()]
        return [(("port", f"{host}:{p}"), _Item("port", tool, f"{host}:{p}")) for p in ports]
    if kind == "vuln":
        info = _mapping(record.get("info"))
        template = str(record.get("template_id") or "")
        where = str(record.get("matched_at") or target)
        intel = record.get("intel")
        kev = bool(intel.get("kev")) if isinstance(intel, dict) else None
        severity = str(info.get("severity") or "unknown").lower()
        key = f"{template}|{_matcher(record)}|{_url_key(where)}"
        name = str(info.get("name") or template or "finding")
        # A muted finding (triage) is not news when it appears or disappears; a
        # mute that became exploited in the wild still surfaces (the "changed"
        # path is not gated by `tracked`).
        tracked = not record.get("muted")
        return [(("finding", key),
                 _Item("finding", tool, name, detail=where, severity=severity, state=kev, tracked=tracked))]
    if kind == "secret":
        rule, path = str(record.get("rule_id") or "secret"), str(record.get("file_path") or target)
        key = f"{rule}|{path}|{record.get('commit') or ''}"
        # never the secret itself
        return [(("secret", key), _Item("secret", tool, rule, detail=path, tracked=not record.get("muted")))]
    if kind == "fuzz":
        url = str(record.get("url") or target)
        return [(("path", _url_key(url)), _Item("path", tool, url, detail=f"HTTP {record.get('status')}"))]
    if kind == "mail":
        domain = str(record.get("domain") or target)
        return [(("email", domain), _Item("email", tool, domain, state=record.get("verdict"), tracked=False))]
    if kind == "reputation":
        state = (as_int(record.get("malicious")), as_int(record.get("suspicious")))
        return [(("reputation", target.lower()), _Item("reputation", tool, target, state=state, tracked=False))]
    return []  # screenshots and anything new: nothing to compare


def _records(doc: dict[str, Any]) -> list[dict[str, Any]]:
    records = doc.get("records")
    return [r for r in records if isinstance(r, dict)] if isinstance(records, list) else []


def _index(doc: dict[str, Any]) -> dict[tuple[str, str], _Item]:
    index: dict[tuple[str, str], _Item] = {}
    for record in _records(doc):
        for key, item in _items(record):
            index.setdefault(key, item)
    return index


def coverage(doc: dict[str, Any]) -> set[str]:
    """Tools whose every recorded stage finished, so an absence can be trusted."""
    raw_stages = doc.get("stages")
    stages: list[Any] = raw_stages if isinstance(raw_stages, list) else []
    tools = {
        str(s.get("tool")) for s in stages
        if isinstance(s, dict) and s.get("ok") and not s.get("skipped")
    }
    # A tool may run in several stages (e.g. nuclei with different tags). One
    # successful stage cannot vouch for results missing from a failed sibling.
    tools.difference_update(
        str(s.get("tool")) for s in stages
        if isinstance(s, dict) and (not s.get("ok") or s.get("skipped"))
    )
    records = _records(doc)
    # The post-scan checks are not stages; they count where they evidently ran.
    if "httpx" in tools and any(isinstance(r.get("tls"), dict) for r in records if r.get("kind") == "http"):
        tools.add("tlscheck")
    if any(r.get("kind") == "mail" for r in records):
        tools.add("mailcheck")
    if any(r.get("tool") == "virustotal" for r in records):
        tools.add("virustotal")
    return tools


# -- the comparison ----------------------------------------------------------------------
def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _presence(item: _Item, status: str) -> Change:
    labels = _ADDED if status == "added" else _REMOVED
    if item.area == "finding":
        real = item.severity in REAL
        tone = (BAD if status == "added" else GOOD) if real else NEUTRAL
        detail = item.detail if status == "added" else f"{item.detail} — fixed, or not seen this time"
        return Change("finding", status, labels["finding"], item.subject, detail, item.severity, tone)
    if item.area == "secret":
        return Change("secret", status, labels["secret"], item.subject, item.detail, "",
                      BAD if status == "added" else GOOD)
    return Change(item.area, status, labels[item.area], item.subject, item.detail)


def _changed(old: _Item, new: _Item) -> Change | None:
    if old.state == new.state or old.state is None or new.state is None:
        return None
    if new.area == "web":
        tone = BAD if isinstance(new.state, int) and new.state >= 500 else NEUTRAL
        return Change("web", "changed", "status changed", new.subject, f"HTTP {old.state} → {new.state}", "", tone)
    if new.area == "finding":
        if new.state and not old.state:
            return Change("finding", "changed", "now exploited", new.subject,
                          f"{new.detail} — now in CISA KEV: exploited in real attacks", new.severity, BAD)
        return None
    if new.area == "certificate":
        before, after = _parse_time(old.state), _parse_time(new.state)
        if before is None or after is None:
            return None
        renewed = after > before
        return Change("certificate", "changed", "renewed" if renewed else "replaced", new.subject,
                      f"valid until {before:%Y-%m-%d} → {after:%Y-%m-%d}", "", GOOD if renewed else NEUTRAL)
    if new.area == "email":
        worse = _VERDICT_RANK.get(str(new.state), 2) > _VERDICT_RANK.get(str(old.state), 2)
        return Change("email", "changed", "worse" if worse else "better", new.subject,
                      f"{old.state} → {new.state}", "", BAD if worse else GOOD)
    if new.area == "reputation":
        was, now = sum(old.state), sum(new.state)
        if bool(was) == bool(now):
            return None
        malicious, suspicious = new.state
        if now:
            return Change("reputation", "changed", "flagged", new.subject,
                          f"VirusTotal: {malicious} malicious · {suspicious} suspicious", "", BAD)
        return Change("reputation", "changed", "cleared", new.subject, "VirusTotal no longer flags it", "", GOOD)
    return None


def _order(change: Change) -> tuple[int, int, int, int, str]:
    severity = _SEVERITIES.index(change.severity) if change.severity in _SEVERITIES else len(_SEVERITIES)
    return (
        _TONES.index(change.tone), severity, _AREAS.index(change.area),
        ("added", "changed", "removed").index(change.status), change.subject,
    )


def _baseline_ref(doc: dict[str, Any]) -> dict[str, Any]:
    run = _mapping(doc.get("run"))
    return {key: run.get(key) for key in ("session_id", "pipeline", "seed", "started_at")}


def compare(old: dict[str, Any], new: dict[str, Any]) -> RunDiff:
    """Everything that changed from ``old`` to ``new`` (both ``report.json`` documents)."""
    before, after = _index(old), _index(new)
    covered_before, covered_after = coverage(old), coverage(new)
    unseen: dict[str, set[str]] = {}
    changes: list[Change] = []
    for key in sorted(after.keys() - before.keys()):
        item = after[key]
        if not item.tracked:
            continue
        if item.tool not in covered_before:
            unseen.setdefault(item.tool, set()).add("the earlier run")
            continue
        changes.append(_presence(item, "added"))
    for key in sorted(before.keys() - after.keys()):
        item = before[key]
        if not item.tracked:
            continue
        if item.tool not in covered_after:
            unseen.setdefault(item.tool, set()).add("this run")
            continue
        changes.append(_presence(item, "removed"))
    for key in sorted(before.keys() & after.keys()):
        change = _changed(before[key], after[key])
        if change is not None:
            changes.append(change)
    changes.sort(key=_order)
    notes = [
        f"{tool} did not run (or did not finish) in {' or '.join(sorted(sides))}, "
        "so its results were not compared"
        for tool, sides in sorted(unseen.items())
    ]
    return RunDiff(baseline=_baseline_ref(old), changes=changes, not_compared=notes)


# -- finding the earlier run ---------------------------------------------------------------
def load_report(path: Path) -> dict[str, Any]:
    """A ``report.json`` as a dict; ``ValueError`` if it is not one."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a cyberfw report")
    return data


def resolve_report(ref: str, reports_dir: Path) -> Path:
    """A session id, a session directory or a ``report.json`` path → that ``report.json``."""
    for candidate in (Path(ref), reports_dir / ref):
        if candidate.is_file():
            return candidate
        if (candidate / "report.json").is_file():
            return candidate / "report.json"
    raise FileNotFoundError(f"no report.json for {ref!r} (looked in {reports_dir})")


def _run_block(path: Path) -> dict[str, Any] | None:
    """The ``run`` block, read from the head of the file when it fits there.

    cyberfw writes ``run`` second, so a folder of large reports is scanned
    without parsing each one in full.
    """
    try:
        with path.open(encoding="utf-8") as handle:
            head = handle.read(16_384)
    except OSError:
        return None
    at = head.find('"run"')
    if at >= 0:
        start = head.find("{", at)
        try:
            block, _ = json.JSONDecoder().raw_decode(head, start)
        except ValueError:
            block = None
        if isinstance(block, dict):
            return block
    try:
        run = load_report(path).get("run")
    except ValueError:
        return None
    return run if isinstance(run, dict) else None


def _seed_key(seed: str) -> str:
    return hostname_of(seed.strip()).lower().rstrip(".")


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:  # removed between the listing and now
        return 0.0


def find_baseline(
    reports_dir: Path, *, seed: str | None, pipeline: str | None, before: datetime | None
) -> Path | None:
    """The newest earlier ``report.json`` of the same pipeline and seed target, or ``None``."""
    if not seed or not pipeline or not reports_dir.is_dir():
        return None
    want = _seed_key(seed)
    reports = sorted(reports_dir.glob("*/report.json"), key=_mtime, reverse=True)
    for path in reports:
        run = _run_block(path)
        if run is None or run.get("pipeline") != pipeline or _seed_key(str(run.get("seed") or "")) != want:
            continue
        started = _parse_time(run.get("started_at"))
        if before is not None and (started is None or started >= before):
            continue
        return path
    return None
