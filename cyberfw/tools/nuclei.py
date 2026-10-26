"""Nuclei adapter — template-driven vulnerability scanning (ProjectDiscovery)."""

from __future__ import annotations

from cyberfw.plugin import BaseTool, ToolContext


class NucleiTool(BaseTool):
    @property
    def input_flag(self) -> str | None:
        return "-l"

    def build_cmd(self, ctx: ToolContext) -> list[str]:
        cmd: list[str] = [str(self.binary), "-silent", "-jsonl", *self.static_flags()]
        if ctx.controls.severity:
            cmd += ["-severity", ctx.controls.severity]
        if ctx.controls.tags:
            cmd += ["-tags", ctx.controls.tags]
        cmd += self.rate_args(ctx)  # nuclei: -rate-limit
        if ctx.target:
            cmd += ["-u", ctx.target]
        elif ctx.input_file:
            cmd += ["-l", str(ctx.input_file)]
        return cmd
