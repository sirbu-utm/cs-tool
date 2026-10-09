"""Exploit intelligence for CVE findings: CISA KEV, EPSS and Exploit-DB.

A nuclei match says a CVE is *present*; it does not say how urgent fixing it
is. This module answers that from three free, keyless public feeds, looked up
by CVE id alone — the scanned target is never contacted again:

* **CISA KEV** — the catalog of vulnerabilities known to be exploited in real
  attacks, with the date each was added and whether ransomware crews use it;
* **EPSS** (FIRST.org) — the probability, recomputed daily, that a CVE is
  exploited in the next 30 days;
* **Exploit-DB** — whether a public exploit is published, and whether one ships
  as a Metasploit module (point-and-click to use).

KEV and Exploit-DB are whole-catalog downloads, reduced to a small CVE index and
cached under ``cache_dir`` for a day; when a refresh fails the stale index is
used. EPSS is queried live for just the CVEs found. Every source is
best-effort: one that cannot be reached leaves its fields empty and is
reported, never failing the scan.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import re
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from cyberfw.pipeline.schemas import CveIntel, NucleiResult, ToolRecord

__all__ = [
    "EPSS_HIGH",
    "IntelError",
    "IntelSummary",
    "cve_ids",
    "enrich",
    "exploit_url",
    "priority_of",
]

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
EXPLOITDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

#: EPSS at or above this — a 10% chance of exploitation within 30 days — puts a
#: CVE in roughly the top few percent of all CVEs: treated as "fix soon".
EPSS_HIGH = 0.1
#: How long a downloaded catalog index is trusted before it is refreshed.
CACHE_MAX_AGE_S = 24 * 3600
_EPSS_BATCH = 50
_MAX_EXPLOITS = 10

_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

#: KEV / Exploit-DB index shape: ``{cve: {...}}``.
Index = dict[str, dict[str, Any]]


class IntelError(RuntimeError):
    """A feed came back in a shape this module does not understand."""


@dataclass
class IntelSummary:
    """What :func:`enrich` found, for the console line."""

    cves: int = 0  # distinct CVEs looked up
    findings: int = 0  # findings naming at least one CVE
    exploited: int = 0  # ... of which in CISA KEV
    exploits: int = 0  # ... with a public exploit
    likely: int = 0  # ... with EPSS >= EPSS_HIGH
    errors: list[str] = field(default_factory=list)  # sources unreachable / stale


def cve_ids(record: ToolRecord) -> list[str]:
    """CVE ids a nuclei finding names: its template id and ``classification.cve-id``."""
    info = getattr(record, "info", None)
    classification = info.get("classification") if isinstance(info, dict) else None
    raw = classification.get("cve-id") if isinstance(classification, dict) else None
    values = raw if isinstance(raw, list) else [raw]
    found: list[str] = []
    for value in [getattr(record, "template_id", ""), *values]:
        for match in _CVE.findall(str(value or "")):
            cve = match.upper()
            if cve not in found:
                found.append(cve)
    return found


def priority_of(kev: bool, epss: float | None, exploits: list[str]) -> str:
    """``now`` when exploited in the wild; ``soon`` when likely or a public exploit exists."""
    if kev:
        return "now"
    if (epss or 0.0) >= EPSS_HIGH or exploits:
        return "soon"
    return ""


def exploit_url(edb_id: str) -> str:
    """The public Exploit-DB page of one exploit."""
    return f"https://www.exploit-db.com/exploits/{edb_id}"


# -- catalog parsing ---------------------------------------------------------------
def kev_index(payload: Any) -> Index:
    """Reduce the KEV catalog to ``{cve: {"added", "due", "ransomware"}}``."""
    vulns = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(vulns, list):
        raise IntelError("unexpected CISA KEV format")
    index: Index = {}
    for item in vulns:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cveID") or "").upper()
        if not _CVE.fullmatch(cve):
            continue
        index[cve] = {
            "added": str(item.get("dateAdded") or ""),
            "due": str(item.get("dueDate") or ""),
            "ransomware": str(item.get("knownRansomwareCampaignUse") or "").lower() == "known",
        }
    return index


def exploitdb_index(text: str) -> Index:
    """Reduce Exploit-DB's ``files_exploits.csv`` to ``{cve: {"ids", "msf"}}``."""
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or not {"id", "codes"} <= set(reader.fieldnames):
        raise IntelError("unexpected Exploit-DB format")
    index: Index = {}
    for row in reader:
        codes = row.get("codes") or ""
        cves = {match.upper() for match in _CVE.findall(codes)}
        if not cves:
            continue
        edb_id = (row.get("id") or "").strip()
        msf = "metasploit" in f"{row.get('tags') or ''} {row.get('description') or ''}".lower()
        for cve in cves:
            entry = index.setdefault(cve, {"ids": [], "msf": False})
            if edb_id and edb_id not in entry["ids"] and len(entry["ids"]) < _MAX_EXPLOITS:
                entry["ids"].append(edb_id)
            entry["msf"] = entry["msf"] or msf
    return index


def epss_scores(payload: Any) -> dict[str, tuple[float, float]]:
    """``{cve: (epss, percentile)}`` from one EPSS API response."""
    items = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        raise IntelError("unexpected EPSS format")
    scores: dict[str, tuple[float, float]] = {}
    for item in items:
        try:
            scores[str(item["cve"]).upper()] = (float(item["epss"]), float(item.get("percentile") or 0))
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
    return scores


# -- fetching + caching -------------------------------------------------------------
async def _fetch_kev(client: httpx.AsyncClient) -> Index:
    resp = await client.get(KEV_URL)
    resp.raise_for_status()
    return kev_index(resp.json())


async def _fetch_exploitdb(client: httpx.AsyncClient) -> Index:
    resp = await client.get(EXPLOITDB_URL)
    resp.raise_for_status()
    return exploitdb_index(resp.text)


async def _fetch_epss(client: httpx.AsyncClient, cves: list[str]) -> dict[str, tuple[float, float]]:
    scores: dict[str, tuple[float, float]] = {}
    for start in range(0, len(cves), _EPSS_BATCH):
        batch = ",".join(cves[start : start + _EPSS_BATCH])
        resp = await client.get(f"{EPSS_URL}?cve={batch}")
        resp.raise_for_status()
        scores.update(epss_scores(resp.json()))
    return scores


def _read_index(path: Path) -> Index | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _write_index(path: Path, index: Index) -> None:
    """Write atomically, so a concurrent run never reads half a file."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(index, separators=(",", ":")), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        pass  # the cache is an optimisation; this run already has the data


async def _cached(
    path: Path,
    fetch: Callable[[], Awaitable[Index]],
    *,
    name: str,
    max_age_s: float,
    errors: list[str],
) -> Index:
    """A catalog index: the cached copy if fresh, else a fresh fetch (stale on failure)."""
    try:
        fresh = time.time() - path.stat().st_mtime < max_age_s
    except OSError:
        fresh = False
    if fresh and (cached := _read_index(path)) is not None:
        return cached
    try:
        index = await fetch()
    except (httpx.HTTPError, IntelError, ValueError, csv.Error) as exc:
        stale = _read_index(path)
        if stale is not None:
            errors.append(f"{name}: refresh failed ({exc}); using the cached copy")
            return stale
        errors.append(f"{name}: unavailable ({exc})")
        return {}
    _write_index(path, index)
    return index


async def _epss_or_empty(
    client: httpx.AsyncClient, cves: list[str], errors: list[str]
) -> dict[str, tuple[float, float]]:
    try:
        return await _fetch_epss(client, cves)
    except (httpx.HTTPError, IntelError, ValueError) as exc:
        errors.append(f"EPSS: unavailable ({exc})")
        return {}


# -- enrichment -----------------------------------------------------------------------
def intel_for(
    cves: list[str], kev: Index, epss: dict[str, tuple[float, float]], exploitdb: Index
) -> CveIntel:
    """Fold what the three feeds say about a finding's CVEs into one :class:`CveIntel`."""
    kev_hits = [kev[cve] for cve in cves if cve in kev]
    first = min(kev_hits, key=lambda hit: str(hit.get("added") or "9999")) if kev_hits else {}
    best = max((epss[cve] for cve in cves if cve in epss), default=None)
    exploits: list[str] = []
    metasploit = False
    for cve in cves:
        entry = exploitdb.get(cve) or {}
        for edb_id in entry.get("ids") or []:
            if str(edb_id) not in exploits:
                exploits.append(str(edb_id))
        metasploit = metasploit or bool(entry.get("msf"))
    exploits = exploits[:_MAX_EXPLOITS]
    score = best[0] if best else None
    return CveIntel(
        cves=cves,
        priority=priority_of(bool(kev_hits), score, exploits),
        kev=bool(kev_hits),
        kev_added=str(first.get("added") or ""),
        kev_due=str(first.get("due") or ""),
        ransomware=any(bool(hit.get("ransomware")) for hit in kev_hits),
        epss=score,
        epss_percentile=best[1] if best else None,
        exploits=exploits,
        metasploit=metasploit,
    )


async def enrich(
    records: Iterable[ToolRecord],
    cache_dir: Path,
    *,
    client: httpx.AsyncClient | None = None,
    max_age_s: float = CACHE_MAX_AGE_S,
) -> IntelSummary:
    """Attach a :class:`CveIntel` to every nuclei finding that names a CVE.

    Findings without a CVE are left alone, and when none names one nothing is
    fetched at all.
    """
    targets = [(r, ids) for r in records if isinstance(r, NucleiResult) and (ids := cve_ids(r))]
    summary = IntelSummary(findings=len(targets))
    if not targets:
        return summary
    cves = sorted({cve for _, ids in targets for cve in ids})
    summary.cves = len(cves)
    http = client or httpx.AsyncClient(
        timeout=60.0, follow_redirects=True, headers={"User-Agent": "cyberfw"}
    )
    folder = cache_dir / "threatintel"
    try:
        kev, exploitdb, epss = await asyncio.gather(
            _cached(folder / "kev.json", lambda: _fetch_kev(http),
                    name="CISA KEV", max_age_s=max_age_s, errors=summary.errors),
            _cached(folder / "exploitdb.json", lambda: _fetch_exploitdb(http),
                    name="Exploit-DB", max_age_s=max_age_s, errors=summary.errors),
            _epss_or_empty(http, cves, summary.errors),
        )
    finally:
        if client is None:
            await http.aclose()
    for record, ids in targets:
        intel = intel_for(ids, kev, epss, exploitdb)
        record.intel = intel
        summary.exploited += intel.kev
        summary.exploits += bool(intel.exploits)
        summary.likely += (intel.epss or 0.0) >= EPSS_HIGH
    return summary
