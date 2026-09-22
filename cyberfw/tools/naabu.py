"""Naabu adapter — high-speed port / live-host scanning (ProjectDiscovery).

Naabu scans hosts, not URLs: given ``-host https://example.com`` it exits 1 with
``no valid ipv4 or ipv6 targets were found``. Both the seed and any upstream
targets (httpx's live URLs) are therefore reduced to a bare hostname.
"""

from __future__ import annotations

from cyberfw.tools.base import BaseTool, ToolContext
from cyberfw.tools.targets import hostname_of


class NaabuTool(BaseTool):
    target_prompt = "Target host, IP or URL"

    @property
    def input_flag(self) -> str | None:
        return "-iL"

    def prepare_inputs(self, inputs: list[str]) -> list[str]:
        return [hostname_of(host) for host in inputs]

    def build_cmd(self, ctx: ToolContext) -> list[str]:
        cmd: list[str] = [str(self.binary), "-silent", "-json", *self._static_flags()]
        if ctx.target:
            cmd += ["-host", hostname_of(ctx.target)]
        elif ctx.input_file:
            cmd += ["-iL", str(ctx.input_file)]
        return cmd
