"""PipelineEngine — Pipes and Filters over typed, object context.

A pipeline is an ordered list of :class:`Node` values. Each node runs its tool
with a :class:`ToolContext` seeded either from the original ``-d`` target or from
the previous stage's validated records (written to the Context Store and
re-read as deduplicated targets). Tools that accept a host list run in one
process via ``-l``/``-iL``; ``per_target`` tools fan out one invocation per input.
A crashed or non-zero child (:class:`ExecutionError`) is recorded on the node but
never aborts the whole pipeline — the stage simply contributes no records.
"""

from __future__ import annotations

import asyncio
import shutil
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cyberfw.config import Settings
from cyberfw.exceptions import ExecutionError, ToolNotFoundError
from cyberfw.logging import get_logger
from cyberfw.manager import ToolManager
from cyberfw.pipeline.context import SessionContext
from cyberfw.pipeline.executor import run_stage
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.tools.base import BaseTool, ToolContext

LOG = get_logger("engine")

__all__ = ["Node", "NodeResult", "PipelineResult", "PipelineEngine"]

#: Native package-manager hints for external dependencies declared in
#: ``registry.yaml`` (e.g. ``nmap`` for RustScan's service/version detection).
#: Graceful degradation per spec: a missing dependency only produces a warning,
#: it never blocks a stage or the framework's initialization.
_DEP_INSTALL_HINTS: dict[str, dict[str, str]] = {
    "nmap": {
        "win": "winget install -e --id Insecure.Nmap",
        "darwin": "brew install nmap",
        "linux": "sudo apt-get install nmap (or: dnf install nmap / pacman -S nmap)",
    },
}


def _dependency_hint(dep: str) -> str:
    """Return an install command for ``dep`` on the current platform."""
    hints = _DEP_INSTALL_HINTS.get(dep)
    if not hints:
        return f"install `{dep}` and make sure it is on PATH"
    platform_key = "win" if sys.platform.startswith("win") else "darwin" if sys.platform == "darwin" else "linux"
    return hints.get(platform_key, hints["linux"])


@dataclass
class Node:
    """One stage of a pipeline."""

    tool: str
    stage: str
    max_records: int = 0  # 0 = unlimited

    def __post_init__(self) -> None:
        allow = {"-", "_", ".", "/", "\\", ":"}
        self.stage_id = "".join(ch if ch.isalnum() or ch in allow else "_" for ch in self.stage)


@dataclass
class NodeResult:
    """Outcome of running one node."""

    node: Node
    ok: bool = True
    count: int = 0
    error: str | None = None


@dataclass
class PipelineResult:
    """Aggregate of a whole pipeline run."""

    nodes: list[NodeResult] = field(default_factory=list)
    records: list[ToolRecord] = field(default_factory=list)

    def succeeded(self) -> bool:
        return bool(self.nodes) and all(n.ok for n in self.nodes)

    @property
    def totals_by_tool(self) -> dict[str, int]:
        totals: dict[str, int] = {}
        for n in self.nodes:
            totals[n.node.tool] = totals.get(n.node.tool, 0) + n.count
        return totals


class PipelineEngine:
    """Executes an ordered chain of tool nodes."""

    def __init__(
        self,
        settings: Settings,
        tool_manager: ToolManager,
        context: SessionContext | None = None,
    ) -> None:
        self.settings = settings
        self.tool_manager = tool_manager
        self.context = context
        self._on_record: Any = None
        self._on_stderr: Any = None
        self._on_stdout_raw: Any = None

    # -- public --------------------------------------------------------------
    def set_record_callback(self, callback: Callable[[ToolRecord], Awaitable[None]]) -> None:
        """Register an ``async (ToolRecord) -> None`` hook (Rich live table)."""
        self._on_record = callback

    def set_stderr_callback(self, callback: Callable[[str], Awaitable[None]]) -> None:
        """Register an ``async (line) -> None`` hook for live stderr passthrough."""
        self._on_stderr = callback

    def set_stdout_raw_callback(self, callback: Callable[[str], Awaitable[None]]) -> None:
        """Register an ``async (line) -> None`` hook for live raw-stdout passthrough.

        Fires for every stdout line regardless of parsing, so a pipeline can show
        exactly what each tool prints while still parsing records for threading.
        """
        self._on_stdout_raw = callback

    def build_tool(self, name: str) -> BaseTool:
        from cyberfw.tools import adapter_for

        spec = self.tool_manager.spec(name)
        for dep in spec.check_deps:
            if shutil.which(dep) is None:
                LOG.warning(
                    "%s works best with `%s`, which was not found on PATH — %s.",
                    name,
                    dep,
                    _dependency_hint(dep),
                )
        binary = self.tool_manager.binary_path(name)
        return adapter_for(spec, binary)

    async def run(
        self, nodes: list[Node], seed: str | None, *, extra_input: str | None = None
    ) -> PipelineResult:
        """Run ``nodes`` in order, threading results forward.

        ``extra_input`` (e.g. an Ffuf wordlist) is offered to every stage that
        wants it; stages that don't consume it simply ignore it.
        """
        result = PipelineResult()
        inputs: list[str] = []
        for node in nodes:
            node_result, step_records = await self._run_node(
                node, seed, inputs, extra_input=extra_input
            )
            result.nodes.append(node_result)
            result.records.extend(step_records)
            inputs = [r.target for r in step_records]
        return result

    # -- internals -----------------------------------------------------------
    async def _run_node(
        self,
        node: Node,
        seed: str | None,
        inputs: list[str],
        *,
        parse: bool = True,
        extra_input: str | None = None,
    ) -> tuple[NodeResult, list[ToolRecord]]:
        adapter = self.build_tool(node.tool)
        ctx = ToolContext(
            target=seed,
            inputs=inputs,
            extra_input=extra_input if extra_input is not None else self.settings.wordlist,
        )

        try:
            records = await self._dispatch(adapter, ctx, node, parse=parse)
        except ExecutionError as exc:
            LOG.warning("stage %s failed: %s (stderr tail: %s)", node.stage, exc, exc.stderr_tail)
            return NodeResult(node=node, ok=False, count=0, error=str(exc)), []
        except (ToolNotFoundError, ValueError) as exc:
            # Expected, user-actionable pre-flight errors (missing wordlist,
            # missing target): a clean stage failure, no scary traceback.
            LOG.warning("stage %s skipped: %s", node.stage, exc)
            return NodeResult(node=node, ok=False, count=0, error=str(exc)), []
        except Exception as exc:  # noqa: BLE001 - never let one tool stop the pipeline
            LOG.exception("stage %s raised %s", node.stage, type(exc).__name__)
            return NodeResult(node=node, ok=False, count=0, error=f"{type(exc).__name__}: {exc}"), []

        if node.max_records:
            records = records[: node.max_records]
        return NodeResult(node=node, ok=True, count=len(records)), records

    async def _dispatch(
        self, adapter: BaseTool, ctx: ToolContext, node: Node, *, parse: bool = True
    ) -> list[ToolRecord]:
        if adapter.per_target:
            return await self._fan_out(adapter, ctx, node, parse=parse)

        # For stages 2+, ctx.inputs contains results from previous stage.
        # We must NOT pass target=seed in that case, otherwise adapters
        # will use -u <seed> instead of -l <input_file>.
        has_inputs = bool(ctx.inputs)
        use_inputs = ctx.inputs or ([ctx.target] if ctx.target else [])
        if not use_inputs:
            return []

        input_file: Path | None = None
        if adapter.input_flag and ctx.inputs:
            input_file = self._materialize(node.stage_id, ctx.inputs)

        run_ctx = ToolContext(
            target=ctx.target if not has_inputs else None,
            inputs=ctx.inputs,
            input_file=input_file,
            extra_input=ctx.extra_input,
        )
        cmd = adapter.build_cmd(run_ctx)
        return await run_stage(
            cmd,
            tool=node.tool,
            stage=node.stage_id,
            context=self.context,
            on_record=self._on_record,
            on_stderr=self._on_stderr,
            on_stdout_raw=self._on_stdout_raw,
            parse_line=adapter.parse_line,
            parse_buffer=adapter.parse_output if adapter.buffered else None,
            parse=parse,
        )

    async def _fan_out(
        self, adapter: BaseTool, ctx: ToolContext, node: Node, *, parse: bool = True
    ) -> list[ToolRecord]:
        targets = ctx.inputs or ([ctx.target] if ctx.target else [])
        semaphore = asyncio.Semaphore(self.settings.concurrency)

        async def run_target(target: str) -> list[ToolRecord]:
            async with semaphore:
                cmd = adapter.build_cmd(ToolContext(target=target, extra_input=ctx.extra_input))
                return await run_stage(
                    cmd,
                    tool=node.tool,
                    stage=node.stage_id,
                    context=self.context,
                    on_record=self._on_record,
                    on_stderr=self._on_stderr,
                    on_stdout_raw=self._on_stdout_raw,
                    parse_line=adapter.parse_line,
                    parse_buffer=adapter.parse_output if adapter.buffered else None,
                    parse=parse,
                )

        batches = await asyncio.gather(*(run_target(target) for target in targets))
        return [record for batch in batches for record in batch]

    def _materialize(self, stage_id: str, inputs: list[str]) -> Path:
        if self.context is None:
            raise ValueError("pipeline context required to materialise an input list")
        path = self.context.session_dir / f"{stage_id}.input"
        path.write_text("\n".join(self._uniq(inputs)) + "\n", encoding="utf-8")
        return path

    @staticmethod
    def _uniq(items: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for item in items:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out
