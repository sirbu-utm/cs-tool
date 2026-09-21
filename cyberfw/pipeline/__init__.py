"""Orchestration and state-passing subsystem."""

from cyberfw.pipeline.context import SessionContext
from cyberfw.pipeline.executor import run_stage
from cyberfw.pipeline.schemas import (
    FfufResult,
    GitleaksResult,
    GowitnessResult,
    HttpxResult,
    NaabuResult,
    NucleiResult,
    RustscanResult,
    SubfinderResult,
    ToolRecord,
    validate_record,
)

__all__ = [
    "SessionContext",
    "PipelineEngine",
    "PipelineResult",
    "Node",
    "NodeResult",
    "run_stage",
    "ToolRecord",
    "validate_record",
    "SubfinderResult",
    "NaabuResult",
    "HttpxResult",
    "FfufResult",
    "NucleiResult",
    "GitleaksResult",
    "GowitnessResult",
    "RustscanResult",
]


def __getattr__(name: str) -> object:
    """Load engine symbols only when requested, avoiding tools/pipeline cycles."""
    if name in {"Node", "NodeResult", "PipelineEngine", "PipelineResult"}:
        from cyberfw.pipeline.engine import Node, NodeResult, PipelineEngine, PipelineResult

        return {
            "Node": Node,
            "NodeResult": NodeResult,
            "PipelineEngine": PipelineEngine,
            "PipelineResult": PipelineResult,
        }[name]
    raise AttributeError(name)
