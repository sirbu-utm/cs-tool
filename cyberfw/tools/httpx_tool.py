"""Httpx adapter — HTTP probing, tech detection, WAF identification (ProjectDiscovery)."""

from __future__ import annotations

from cyberfw.tools.base import BaseTool, ToolContext


class HttpxTool(BaseTool):
    @property
    def input_flag(self) -> str | None:
        return "-l"

    def build_cmd(self, ctx: ToolContext) -> list[str]:
        # httpx's JSONL flag is -json/-j, NOT -jsonl (that errors out).
        cmd: list[str] = [str(self.binary), "-silent", "-json", *self._static_flags()]
        if ctx.target:
            cmd += ["-u", ctx.target]
        elif ctx.input_file:
            cmd += ["-l", str(ctx.input_file)]
        return cmd
