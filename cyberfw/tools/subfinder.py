"""Subfinder adapter — passive subdomain enumeration (ProjectDiscovery)."""

from __future__ import annotations

from urllib.parse import urlsplit

from cyberfw.tools.base import BaseTool, ToolContext


class SubfinderTool(BaseTool):
    # ProjectDiscovery subfinder reads a host list via -dL.
    @property
    def input_flag(self) -> str | None:
        return "-dL"

    def build_cmd(self, ctx: ToolContext) -> list[str]:
        assert self.spec.name == "subfinder"
        # subfinder's JSONL flag is -json/-oJ, NOT -jsonl (that errors out).
        cmd: list[str] = [str(self.binary), "-silent", "-json", *self._static_flags()]
        if ctx.target:
            cmd += ["-d", _apex(ctx.target)]
        elif ctx.input_file:
            cmd += ["-dL", str(ctx.input_file)]
        return cmd


def _apex(target: str) -> str:
    """Reduce a pasted URL to the bare domain subfinder expects for ``-d``."""
    host = urlsplit(target).hostname if "://" in target else None
    return host or target.strip("/")
