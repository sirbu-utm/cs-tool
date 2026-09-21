"""Gitleaks adapter — secret & key detection in a local directory.

Targets gitleaks v8.x, whose scanning commands are ``dir`` (files) and ``git``
(repos); the old ``detect`` verb is gone. We scan a directory of files with
``dir <path> -f json -r - --exit-code 0``:

* ``-r -`` streams the report to stdout,
* ``--exit-code 0`` keeps a *successful* scan that found leaks from looking like
  a crash (gitleaks otherwise exits 1 when it finds secrets),
* the report is a single pretty-printed JSON *array* (not JSONL), so the adapter
  is ``buffered`` and parses the whole document at once via :meth:`parse_output`.
"""

from __future__ import annotations

import json

from cyberfw.exceptions import ParseError
from cyberfw.pipeline.schemas import GitleaksResult, ToolRecord
from cyberfw.tools.base import BaseTool, ToolContext


class GitleaksTool(BaseTool):
    # gitleaks writes one JSON array to stdout, not line-delimited JSON.
    buffered = True

    def build_cmd(self, ctx: ToolContext) -> list[str]:
        cmd: list[str] = [str(self.binary), "dir"]
        if ctx.target:
            cmd.append(ctx.target)
        cmd += ["--report-format", "json", "--report-path", "-", "--exit-code", "0", "--no-banner"]
        cmd += self._static_flags()
        return cmd

    def parse_output(self, text: str) -> list[ToolRecord]:
        """Parse gitleaks' JSON-array report into one record per finding."""
        text = text.strip()
        if not text:
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseError(f"[gitleaks] invalid JSON report: {exc}") from exc
        if not isinstance(data, list):
            raise ParseError("[gitleaks] expected a JSON array report")
        records: list[ToolRecord] = []
        for index, item in enumerate(data, start=1):
            if not isinstance(item, dict):
                continue
            rec = GitleaksResult(tool=self.name, line_number=index, raw=json.dumps(item), **item)
            rec.target = rec.file_path
            rec.kind = "secret"
            records.append(rec)
        return records

    @property
    def input_flag(self) -> str | None:
        return None
