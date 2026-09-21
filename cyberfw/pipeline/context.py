"""Context Store — per-stage JSONL persistence for a pipeline session.

Each stage appends every validated record to ``reports/<session>/<stage>.jsonl``
as it arrives, so a crash mid-run never loses the data already scraped and the
records are available for the next stage's input, live tables and final reports.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cyberfw.exceptions import ContextStoreError
from cyberfw.pipeline.schemas import ToolRecord

__all__ = ["SessionContext"]


class SessionContext:
    """Writer + reader for one pipeline session.

    Safe for concurrent use from coroutines on one event loop: ``append`` opens,
    writes and closes synchronously with no ``await`` in between, so writes can
    never interleave. It is *not* guarded against multiple OS threads or
    processes writing the same session — the framework never does that.
    """

    def __init__(self, root_dir: Path, session_id: str) -> None:
        self.root_dir = Path(root_dir)
        self.session_id = session_id
        self.session_dir = self.root_dir / session_id
        self.session_dir.mkdir(parents=True, exist_ok=True)

    # -- writers --------------------------------------------------------------
    def append(self, stage: str, record: ToolRecord) -> None:
        """Persist one validated record to ``<session_dir>/<stage>.jsonl``."""
        path = self._stage_path(stage)
        line = record.as_dict()
        line["stage"] = stage
        try:
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(line, ensure_ascii=False) + "\n")
        except OSError as exc:
            raise ContextStoreError(f"cannot write {path}: {exc}") from exc

    def append_raw(self, stage: str, text: str) -> None:
        """Persist an unparsed line (diagnostics); tolerated but discouraged."""
        self._stage_path(stage).open("a", encoding="utf-8").write(text.rstrip("\n") + "\n")

    # -- readers --------------------------------------------------------------
    def records(self, stage: str) -> list[dict[str, Any]]:
        """Re-read every persisted record for ``stage`` as plain dicts."""
        path = self._stage_path(stage)
        if not path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:  # pragma: no cover - corrupt store
                raise ContextStoreError(f"corrupt store {path}: {exc}") from exc
        return out

    def targets(self, stage: str) -> list[str]:
        """Deduplicated ``target`` values (hosts/URLs) for passthrough ``-l``."""
        seen: set[str] = set()
        ordered: list[str] = []
        for rec in self.records(stage):
            target = (rec.get("target") or "").strip()
            if target and target not in seen:
                seen.add(target)
                ordered.append(target)
        return ordered

    # -- helpers --------------------------------------------------------------
    def _stage_path(self, stage: str) -> Path:
        # sanitise arbitrary stage names to a single path segment
        safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in stage) or "stage"
        path = self.session_dir / f"{safe}.jsonl"
        return path
