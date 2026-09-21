"""Provenance for a report: what was scanned, with which tool versions, when.

A finding without this cannot be reproduced or attributed to a scanner
release. The CLI fills a :class:`RunInfo` from the pipeline name, seed target,
session id, platform and the versions recorded in ``tools_bin/.<tool>.install.json``;
the engine supplies the timing on :class:`PipelineResult`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cyberfw import __version__
from cyberfw.pipeline.engine import PipelineResult

__all__ = ["RunInfo"]


@dataclass
class RunInfo:
    pipeline: str | None = None
    seed: str | None = None
    session_id: str | None = None
    #: ``<os>/<arch>`` the binaries were installed for, e.g. ``windows/amd64``.
    platform: str | None = None
    #: Installed version per tool used by the run; ``None`` when unrecorded.
    tool_versions: dict[str, str | None] = field(default_factory=dict)

    def as_dict(self, result: PipelineResult) -> dict[str, Any]:
        """The ``run`` block of ``report.json`` (timestamps ISO-8601, UTC)."""
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "cyberfw_version": __version__,
            "pipeline": self.pipeline,
            "seed": self.seed,
            "session_id": self.session_id,
            "platform": self.platform,
            "started_at": _iso(result.started_at),
            "finished_at": _iso(result.finished_at),
            "duration_s": result.duration_s,
            "tool_versions": dict(self.tool_versions),
        }


def _iso(moment: datetime | None) -> str | None:
    return None if moment is None else moment.isoformat(timespec="seconds")
