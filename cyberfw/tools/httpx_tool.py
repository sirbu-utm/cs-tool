"""Httpx adapter — HTTP probing, tech detection, WAF identification (ProjectDiscovery)."""

from __future__ import annotations

from cyberfw.plugin import BaseTool, ToolContext


class HttpxTool(BaseTool):
    @property
    def input_flag(self) -> str | None:
        return "-l"

    def build_cmd(self, ctx: ToolContext) -> list[str]:
        # httpx's JSONL flag is -json/-j, NOT -jsonl (that errors out).
        # -tls-grab adds each HTTPS host's certificate (expiry, issuer, SANs,
        # expired/self-signed/mismatched) to the same probe — no second
        # connection — which cyberfw.posture.tls turns into certificate health.
        cmd: list[str] = [str(self.binary), "-silent", "-json", "-tls-grab", *self.static_flags()]
        cmd += self.rate_args(ctx)  # httpx: -rate-limit
        if ctx.target:
            cmd += ["-u", ctx.target]
        elif ctx.input_file:
            cmd += ["-l", str(ctx.input_file)]
        return cmd
