"""Naabu adapter — high-speed port / live-host scanning (ProjectDiscovery)."""

from __future__ import annotations

from cyberfw.tools.base import BaseTool, ToolContext


class NaabuTool(BaseTool):
    @property
    def input_flag(self) -> str | None:
        return "-iL"

    def build_cmd(self, ctx: ToolContext) -> list[str]:
        cmd: list[str] = [str(self.binary), "-silent", "-json", *self._static_flags()]
        if ctx.target:
            cmd += ["-host", ctx.target]
        elif ctx.input_file:
            cmd += ["-iL", str(ctx.input_file)]
        return cmd
