"""RustScan adapter for fast open-port discovery.

This adapter intentionally reports RustScan's port results only. Nmap service and
version detection is not launched by this stage; callers that need it should run
Nmap as a separate, explicitly configured stage.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from cyberfw.exceptions import ParseError, ToolNotFoundError
from cyberfw.pipeline.schemas import RustscanResult
from cyberfw.tools.base import BaseTool, ToolContext


class RustscanTool(BaseTool):
    # Real ``--greppable`` output is one summary line per scanned host, e.g.
    # ``127.0.0.1 -> [22,80,443]`` — not the "Open host:port" format RustScan's
    # own non-greppable/human banner uses.
    _GREPPABLE_LINE = re.compile(r"^(?P<host>\S+)\s*->\s*\[(?P<ports>[\d,\s]+)\]\s*$")

    # Consumes every host in one pass, so no fan-out.
    per_target = False

    target_prompt = "Target host, IP or URL"

    @property
    def input_flag(self) -> str | None:
        # ``--addresses`` takes either a comma list or a newline-delimited file.
        # Prefer the file for multi-host input: comma-joining thousands of
        # subfinder hosts into one argument overflows Windows' command line.
        return "--addresses"

    def prepare_inputs(self, inputs: list[str]) -> list[str]:
        return [_hostname(host) for host in inputs]

    def build_cmd(self, ctx: ToolContext) -> list[str]:
        if ctx.input_file is not None:
            addresses = str(ctx.input_file)
        else:
            hosts = ctx.inputs if ctx.inputs else ([ctx.target] if ctx.target else [])
            if not hosts:
                raise ToolNotFoundError("RustScan needs at least one target (host or IP).")
            addresses = ",".join(_hostname(host) for host in hosts)
        return [
            str(self.binary),
            "--addresses",
            addresses,
            "--greppable",
            *self._static_flags(),
        ]

    def parse_line(self, line: str, lineno: int) -> RustscanResult:
        """Parse RustScan's greppable ``host -> [port,port,...]`` summary line."""
        match = self._GREPPABLE_LINE.match(line.strip())
        if match is None:
            raise ParseError(f"[rustscan:{lineno}] invalid greppable output")
        host = match.group("host")
        ports = match.group("ports").replace(" ", "")
        return RustscanResult(
            tool=self.name,
            line_number=lineno,
            raw=line,
            host=host,
            ports_list=ports,
            port_state="open",
            target=host,
            kind="scan",
        )


def _hostname(target: str) -> str:
    """Accept a URL or ``host:port`` in the UI while passing RustScan only a host name.

    ``urlsplit`` only recognises a netloc after ``//``; a scheme-less
    ``192.0.2.10:8080`` (naabu's ``target`` shape) would otherwise parse as
    ``scheme="192.0.2.10"`` and come back unchanged, port included.
    """
    parsed = urlsplit(target if "://" in target else f"//{target}")
    return parsed.hostname or target
