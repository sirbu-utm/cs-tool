"""`recon-to-vuln` pipeline: Subfinder → Httpx → Nuclei (+ optional Ffuf/Gowitness).

::

    subfinder  --passive subdomain discovery from a seed domain
    httpx      --probe live hosts, tech detection, drop non-200s
    nuclei     --template-driven vuln scan against live hosts (-l)
    ffuf*      --brute-force open .git dirs on live hosts      (--ffuf)
    gowitness* --headless screenshots of live hosts            (--gowitness)

The first stage seeds from the user's ``-d`` target; every later stage reads the
previous stage's validated records from the Context Store, so a crash mid-run
loses nothing already written.
"""

from __future__ import annotations

from dataclasses import dataclass

from cyberfw.pipeline.engine import Node

__all__ = ["ReconToVulnOptions", "build_recon_to_vuln"]


@dataclass
class ReconToVulnOptions:
    include_ffuf: bool = False
    include_gowitness: bool = False
    max_httpx: int = 0  # cap on live hosts passed onward (0 = unlimited)
    max_nuclei: int = 0


def build_recon_to_vuln(options: ReconToVulnOptions | None = None) -> list[Node]:
    """Return the ordered node list for ``recon-to-vuln``."""
    opts = options or ReconToVulnOptions()
    nodes: list[Node] = [
        Node(tool="subfinder", stage="subdomains"),
        Node(tool="httpx", stage="live_http", max_records=opts.max_httpx),
        Node(tool="nuclei", stage="vulns", max_records=opts.max_nuclei),
    ]
    if opts.include_ffuf:
        nodes.append(Node(tool="ffuf", stage="fuzz"))
    if opts.include_gowitness:
        nodes.append(Node(tool="gowitness", stage="screenshots"))
    return nodes
