"""Tests for the ready-made pipeline definitions (node wiring, not execution)."""

from __future__ import annotations

from cyberfw.pipelines import build
from cyberfw.pipelines.recon_to_vuln import ReconToVulnOptions, build_recon_to_vuln


def test_recon_to_vuln_default_chain() -> None:
    nodes = build_recon_to_vuln()
    assert [n.tool for n in nodes] == ["subfinder", "httpx", "nuclei"]


def test_recon_to_vuln_vuln_stages_all_consume_live_http() -> None:
    """nuclei, ffuf and gowitness each scan httpx's live hosts — never the previous stage's findings.

    Otherwise a clean nuclei run (0 records) makes ffuf fall back to the bare seed,
    and gowitness would screenshot ffuf's fuzz hits instead of the live hosts.
    """
    nodes = build_recon_to_vuln(ReconToVulnOptions(include_ffuf=True, include_gowitness=True))
    by_tool = {n.tool: n for n in nodes}
    assert [n.tool for n in nodes] == ["subfinder", "httpx", "nuclei", "ffuf", "gowitness"]
    assert by_tool["subfinder"].input_from is None
    assert by_tool["httpx"].input_from is None
    for tool in ("nuclei", "ffuf", "gowitness"):
        assert by_tool[tool].input_from == "live_http", tool


def test_build_by_name_passes_options_through() -> None:
    nodes = build("recon-to-vuln", include_gowitness=True, max_httpx=5)
    assert [n.tool for n in nodes] == ["subfinder", "httpx", "nuclei", "gowitness"]
    assert nodes[1].max_records == 5
