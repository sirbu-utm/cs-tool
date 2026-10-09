"""Threat intel: CVE extraction, feed parsing, caching and enrichment (no network)."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import httpx
import pytest

from cyberfw import threatintel
from cyberfw.pipeline.schemas import NucleiResult, ToolRecord, validate_record

_KEV = {
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
         "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2014-0160", "dateAdded": "2022-05-04", "dueDate": "2022-05-25",
         "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "not-a-cve"},
    ]
}

_EDB = (
    "id,file,description,date_published,author,type,platform,port,date_added,date_updated,"
    "verified,codes,tags,aliases,screenshot_url,application_url,source_url\n"
    '50592,exploits/java/remote/50592.py,"Apache Log4j 2 - Remote Code Execution (RCE)",'
    "2021-12-14,kozmer,remote,java,,2021-12-14,2021-12-15,0,CVE-2021-44228,,,,,\n"
    '16929,exploits/aix/dos/16929.rb,"AIX rpc.cmsd - Buffer Overflow (Metasploit)",'
    '2010-11-11,Metasploit,dos,aix,,2010-11-11,2011-03-06,1,CVE-2009-3699;OSVDB-58726,'
    '"Metasploit Framework (MSF)",,,,\n'
    "1,exploits/x.txt,No CVE here,2000-01-01,a,local,linux,,2000-01-01,2000-01-01,0,OSVDB-1,,,,,\n"
)


def _epss(cves: list[str]) -> dict[str, object]:
    scores = {"CVE-2021-44228": "0.944", "CVE-2023-0001": "0.0004"}
    return {"data": [{"cve": c, "epss": scores[c], "percentile": "0.99"} for c in cves if c in scores]}


def _transport(calls: list[str], *, fail: bool = False) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        calls.append(url)
        if fail:
            return httpx.Response(500)
        if "cisa.gov" in url:
            return httpx.Response(200, json=_KEV)
        if "gitlab.com" in url:
            return httpx.Response(200, text=_EDB)
        if "api.first.org" in url:
            cves = request.url.params.get("cve", "").split(",")
            return httpx.Response(200, json=_epss(cves))
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _finding(template_id: str, cve_ids: object = None, lineno: int = 1) -> ToolRecord:
    info: dict[str, object] = {"name": template_id, "severity": "critical"}
    if cve_ids is not None:
        info["classification"] = {"cve-id": cve_ids}
    raw = {"template-id": template_id, "matched-at": "https://a.example.com/", "info": info}
    return validate_record("nuclei", json.dumps(raw), lineno)


# -- extraction & parsing -----------------------------------------------------------
def test_cve_ids_reads_template_id_and_classification() -> None:
    record = _finding("CVE-2021-44228", ["cve-2021-44228", "CVE-2021-45046"])
    assert threatintel.cve_ids(record) == ["CVE-2021-44228", "CVE-2021-45046"]  # upper, deduped
    assert threatintel.cve_ids(_finding("tech-detect")) == []
    assert threatintel.cve_ids(_finding("x", "CVE-2020-1111, CVE-2020-2222")) == [
        "CVE-2020-1111", "CVE-2020-2222",
    ]


def test_kev_index_keeps_dates_and_ransomware() -> None:
    index = threatintel.kev_index(_KEV)
    assert set(index) == {"CVE-2021-44228", "CVE-2014-0160"}  # junk id dropped
    assert index["CVE-2021-44228"] == {"added": "2021-12-10", "due": "2021-12-24", "ransomware": True}
    assert index["CVE-2014-0160"]["ransomware"] is False
    with pytest.raises(threatintel.IntelError):
        threatintel.kev_index({"nope": []})


def test_exploitdb_index_maps_cves_and_spots_metasploit() -> None:
    index = threatintel.exploitdb_index(_EDB)
    assert index["CVE-2021-44228"] == {"ids": ["50592"], "msf": False}
    assert index["CVE-2009-3699"] == {"ids": ["16929"], "msf": True}
    assert len(index) == 2  # the row without a CVE is ignored
    with pytest.raises(threatintel.IntelError):
        threatintel.exploitdb_index("a,b\n1,2\n")


def test_epss_scores_parse_the_string_numbers() -> None:
    scores = threatintel.epss_scores(_epss(["CVE-2021-44228"]))
    assert scores == {"CVE-2021-44228": (0.944, 0.99)}


def test_priority_of() -> None:
    assert threatintel.priority_of(True, None, []) == "now"
    assert threatintel.priority_of(False, 0.5, []) == "soon"
    assert threatintel.priority_of(False, 0.001, ["123"]) == "soon"
    assert threatintel.priority_of(False, 0.001, []) == ""


def test_intel_for_folds_several_cves() -> None:
    intel = threatintel.intel_for(
        ["CVE-2021-45046", "CVE-2021-44228"],
        threatintel.kev_index(_KEV),
        {"CVE-2021-44228": (0.94, 0.99), "CVE-2021-45046": (0.5, 0.9)},
        threatintel.exploitdb_index(_EDB),
    )
    assert intel.kev and intel.ransomware and intel.kev_added == "2021-12-10"
    assert intel.epss == 0.94  # the likeliest of the finding's CVEs
    assert intel.exploits == ["50592"]
    assert intel.priority == "now"


# -- enrichment -----------------------------------------------------------------------
async def test_enrich_attaches_intel_and_caches_the_catalogs(tmp_path: Path) -> None:
    calls: list[str] = []
    records = [
        _finding("CVE-2021-44228", lineno=1),
        _finding("CVE-2023-0001", lineno=2),
        _finding("tech-detect", lineno=3),
    ]
    async with httpx.AsyncClient(transport=_transport(calls)) as client:
        summary = await threatintel.enrich(records, tmp_path, client=client)

    log4j, minor, tech = records
    assert isinstance(log4j, NucleiResult) and log4j.intel is not None
    assert log4j.intel.kev and log4j.intel.epss == 0.944 and log4j.intel.exploits == ["50592"]
    assert isinstance(minor, NucleiResult) and minor.intel is not None
    assert minor.intel.priority == "" and minor.intel.epss == 0.0004
    assert isinstance(tech, NucleiResult) and tech.intel is None  # no CVE → untouched
    assert (summary.cves, summary.findings, summary.exploited, summary.exploits, summary.likely) == (2, 2, 1, 1, 1)
    assert summary.errors == []
    assert (tmp_path / "threatintel" / "kev.json").is_file()
    assert (tmp_path / "threatintel" / "exploitdb.json").is_file()
    assert log4j.as_dict()["intel"]["kev"] is True  # lands in report.json

    # Second run inside the cache window: only EPSS goes to the network.
    calls.clear()
    async with httpx.AsyncClient(transport=_transport(calls)) as client:
        await threatintel.enrich([_finding("CVE-2021-44228")], tmp_path, client=client)
    assert all("api.first.org" in url for url in calls)


async def test_enrich_without_cves_never_touches_the_network(tmp_path: Path) -> None:
    def boom(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("no CVE, no request")

    async with httpx.AsyncClient(transport=httpx.MockTransport(boom)) as client:
        summary = await threatintel.enrich([_finding("tech-detect")], tmp_path, client=client)
    assert summary.findings == 0 and summary.cves == 0


async def test_enrich_falls_back_to_a_stale_cache_and_reports_dead_feeds(tmp_path: Path) -> None:
    folder = tmp_path / "threatintel"
    folder.mkdir()
    kev = folder / "kev.json"
    kev.write_text(json.dumps(threatintel.kev_index(_KEV)), encoding="utf-8")
    old = time.time() - 3 * 24 * 3600
    os.utime(kev, (old, old))

    record = _finding("CVE-2021-44228")
    async with httpx.AsyncClient(transport=_transport([], fail=True)) as client:
        summary = await threatintel.enrich([record], tmp_path, client=client)

    assert isinstance(record, NucleiResult) and record.intel is not None
    assert record.intel.kev is True  # from the stale KEV copy
    assert record.intel.epss is None and record.intel.exploits == []
    joined = " | ".join(summary.errors)
    assert "CISA KEV: refresh failed" in joined and "using the cached copy" in joined
    assert "Exploit-DB: unavailable" in joined and "EPSS: unavailable" in joined
