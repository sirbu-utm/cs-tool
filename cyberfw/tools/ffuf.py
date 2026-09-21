"""Ffuf adapter — web fuzzing / directory & parameter brute-force.

Ffuf targets a single URL template, so ``per_target`` fans the stage out across
whatever live hosts the previous stage handed over. Ffuf cannot run without a
wordlist (``-w``); one must be supplied via ``--wordlist`` (CLI) / ``wordlist``
(config), since no dictionary ships with the framework and there is no portable
default path across Windows/Linux/macOS.
"""

from __future__ import annotations

from pathlib import Path

from cyberfw.exceptions import ToolNotFoundError
from cyberfw.tools.base import BaseTool, ToolContext


class FfufTool(BaseTool):
    per_target = True

    def build_cmd(self, ctx: ToolContext) -> list[str]:
        targets = ctx.inputs if ctx.inputs else ([ctx.target] if ctx.target else [])
        if not targets:
            raise ToolNotFoundError("Ffuf needs at least one target URL.")
        wordlist = ctx.extra_input
        if not wordlist:
            raise ToolNotFoundError(
                "Ffuf needs a wordlist. Pass one with --wordlist <path> "
                "(or set `wordlist:` in config.local.yaml)."
            )
        if not Path(wordlist).expanduser().is_file():
            raise ToolNotFoundError(f"Ffuf wordlist not found: {wordlist}")
        base = targets[0]
        if not base.startswith(("http://", "https://")):
            base = f"https://{base}"  # bare host from subfinder -> https seed
        base = base.rstrip("/")
        cmd: list[str] = [
            str(self.binary),
            "-u",
            f"{base}/FUZZ",
            "-w",
            wordlist,
            "-json",
            *self._static_flags(),
        ]
        return cmd

    @property
    def input_flag(self) -> str | None:
        return None
