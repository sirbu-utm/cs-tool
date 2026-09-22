"""PipelineEngine — Pipes and Filters over typed, object context.

A pipeline is an ordered list of :class:`Node` values. Each node runs its tool
with a :class:`ToolContext` seeded either from the original ``-d`` target or from
an earlier stage's validated records — the immediately preceding node by
default, or the node named by ``Node.input_from``. Tools that accept a host
list run in one process via ``-l``/``-iL``; ``per_target`` tools fan out one
invocation per input.
A crashed or non-zero child (:class:`ExecutionError`) is recorded on the node but
never aborts the whole pipeline — the stage simply contributes no records.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
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

__all__ = ["Node", "NodeResult", "PipelineResult", "PipelineEngine", "StageEvent", "dependency_hint"]

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


def dependency_hint(dep: str) -> str:
    """Return an install command for ``dep`` on the current platform."""
    hints = _DEP_INSTALL_HINTS.get(dep)
    if not hints:
        return f"install `{dep}` and make sure it is on PATH"
    platform_key = "win" if sys.platform.startswith("win") else "darwin" if sys.platform == "darwin" else "linux"
    return hints.get(platform_key, hints["linux"])


@dataclass
class Node:
    """One stage of a pipeline.

    ``input_from`` names an *earlier* node's ``stage`` whose targets this node
    consumes; by default a node consumes the immediately preceding node's
    records. Several nodes may read the same upstream stage (e.g. nuclei, ffuf
    and gowitness all scanning httpx's live hosts).
    """

    tool: str
    stage: str
    max_records: int = 0  # 0 = unlimited
    input_from: str | None = None

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
    #: True when the node never ran because the stage it reads had failed.
    skipped: bool = False


@dataclass
class StageEvent:
    """Lifecycle notification for one stage — what a live progress view subscribes to.

    ``start`` is sent once the amount of work is known (``total`` targets for a
    fan-out stage, 1 for a single process), ``progress`` after each fan-out
    target finishes (successfully or not), ``done`` with the final
    :class:`NodeResult` — also for a stage that failed before it could start,
    in which case no ``start`` precedes it.
    """

    kind: str  # "start" | "progress" | "done"
    stage: str
    tool: str
    done: int = 0
    total: int = 0
    result: NodeResult | None = None


@dataclass
class PipelineResult:
    """Aggregate of a whole pipeline run."""

    nodes: list[NodeResult] = field(default_factory=list)
    records: list[ToolRecord] = field(default_factory=list)
    #: Wall-clock bounds of :meth:`PipelineEngine.run` (UTC); ``None`` until it ran.
    started_at: datetime | None = None
    finished_at: datetime | None = None

    def succeeded(self) -> bool:
        return bool(self.nodes) and all(n.ok for n in self.nodes)

    @property
    def duration_s(self) -> float | None:
        if self.started_at is None or self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

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
        *,
        report_missing_deps: bool = True,
    ) -> None:
        self.settings = settings
        self.tool_manager = tool_manager
        self.context = context
        #: False when the caller has already told the user about missing optional
        #: dependencies (the CLI's pipeline pre-flight), so the same sentence is
        #: not repeated as each stage starts — where the live region buries it.
        self.report_missing_deps = report_missing_deps
        self._on_record: Any = None
        self._on_stderr: Any = None
        self._on_stdout_raw: Any = None
        self._on_stage: Callable[[StageEvent], Awaitable[None]] | None = None

    # -- public --------------------------------------------------------------
    def set_record_callback(self, callback: Callable[[ToolRecord], Awaitable[None]]) -> None:
        """Register an ``async (ToolRecord) -> None`` hook (Rich live table)."""
        self._on_record = callback

    def set_stderr_callback(self, callback: Callable[[str], Awaitable[None]]) -> None:
        """Register an ``async (line) -> None`` hook for live stderr passthrough."""
        self._on_stderr = callback

    def set_stage_callback(self, callback: Callable[[StageEvent], Awaitable[None]]) -> None:
        """Register an ``async (StageEvent) -> None`` hook for stage start/progress/done."""
        self._on_stage = callback

    async def _emit(self, event: StageEvent) -> None:
        if self._on_stage is not None:
            await self._on_stage(event)

    def set_stdout_raw_callback(self, callback: Callable[[str], Awaitable[None]]) -> None:
        """Register an ``async (line) -> None`` hook for live raw-stdout passthrough.

        Fires for every stdout line regardless of parsing, so a pipeline can show
        exactly what each tool prints while still parsing records for threading.
        """
        self._on_stdout_raw = callback

    def build_tool(self, name: str) -> BaseTool:
        from cyberfw.tools import adapter_for

        spec = self.tool_manager.spec(name)
        for dep in spec.check_deps if self.report_missing_deps else ():
            if shutil.which(dep) is None:
                LOG.warning(
                    "%s works best with `%s`, which was not found on PATH — %s.",
                    name,
                    dep,
                    dependency_hint(dep),
                )
        binary = self.tool_manager.binary_path(name)
        return adapter_for(spec, binary)

    async def run(
        self, nodes: list[Node], seed: str | None, *, extra_input: str | None = None
    ) -> PipelineResult:
        """Run ``nodes`` in order, threading results forward.

        Each node consumes the targets of the node named by its ``input_from``,
        or of the immediately preceding node when unset. ``extra_input`` (e.g.
        an Ffuf wordlist) is offered to every stage that wants it; stages that
        don't consume it simply ignore it.
        """
        self._validate_wiring(nodes)
        result = PipelineResult(started_at=datetime.now(timezone.utc))
        outputs: dict[str, list[str]] = {}  # stage -> targets it produced
        failed: set[str] = set()  # stages that failed, so their consumers cannot run
        inputs: list[str] = []
        previous: str | None = None
        try:
            for node in nodes:
                source = node.input_from if node.input_from is not None else previous
                if node.input_from is not None:
                    inputs = outputs[node.input_from]
                if source in failed:
                    # Running anyway would fall back to the seed and quietly change
                    # what this stage means (probe the seed, not what the previous
                    # stage found), so the failure would look like a thin result.
                    node_result = NodeResult(
                        node=node,
                        ok=False,
                        skipped=True,
                        error=f"skipped: stage {source!r} failed, so it produced no targets",
                    )
                    await self._emit(
                        StageEvent(kind="done", stage=node.stage, tool=node.tool, result=node_result)
                    )
                    step_records: list[ToolRecord] = []
                    LOG.warning("stage %s skipped: source stage %s failed", node.stage, source)
                else:
                    node_result, step_records = await self._run_node(
                        node, seed, inputs, extra_input=extra_input
                    )
                if not node_result.ok:
                    failed.add(node.stage)
                result.nodes.append(node_result)
                result.records.extend(step_records)
                inputs = [r.target for r in step_records]
                outputs[node.stage] = inputs
                previous = node.stage
        finally:
            result.finished_at = datetime.now(timezone.utc)
        return result

    async def run_single(
        self, node: Node, ctx: ToolContext, *, parse: bool = True
    ) -> tuple[NodeResult, list[ToolRecord]]:
        """Run one node on its own (``cyberfw run``).

        Same fan-out, list materialisation, timeout and failure handling as a
        pipeline stage; ``ctx.inputs`` plays the role of the previous stage.
        """
        return await self._run_node(
            node, ctx.target, ctx.inputs, parse=parse, extra_input=ctx.extra_input
        )

    @staticmethod
    def _validate_wiring(nodes: list[Node]) -> None:
        """Fail fast on a pipeline whose ``input_from`` names a missing/later stage."""
        seen: set[str] = set()
        for node in nodes:
            if node.input_from is not None and node.input_from not in seen:
                raise ValueError(
                    f"node {node.stage!r} has input_from={node.input_from!r}, "
                    f"which is not an earlier stage (known: {sorted(seen) or '<none>'})"
                )
            seen.add(node.stage)

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
        ctx = ToolContext(
            target=seed,
            inputs=inputs,
            extra_input=extra_input if extra_input is not None else self.settings.wordlist,
        )

        node_result, records = await self._attempt(node, ctx, parse=parse)
        await self._emit(StageEvent(kind="done", stage=node.stage, tool=node.tool, result=node_result))
        return node_result, records

    async def _attempt(
        self, node: Node, ctx: ToolContext, *, parse: bool
    ) -> tuple[NodeResult, list[ToolRecord]]:
        """Run the node and fold every failure mode into a ``NodeResult``."""
        try:
            # Inside the try: a registered-but-uninstalled tool is a failed
            # stage like any other, not the end of the run (and its report).
            adapter = self.build_tool(node.tool)
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
        finally:
            # The store keeps this stage's JSONL file open while records stream
            # in; release it now rather than leaving it to the caller (or GC).
            if self.context is not None:
                self.context.close()

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

        inputs = self._uniq(adapter.prepare_inputs(ctx.inputs)) if has_inputs else []
        input_file: Path | None = None
        if adapter.input_flag and inputs:
            input_file = self._materialize(node.stage_id, inputs)

        run_ctx = ToolContext(
            target=ctx.target if not has_inputs else None,
            inputs=inputs,
            input_file=input_file,
            extra_input=ctx.extra_input,
        )
        cmd = adapter.build_cmd(run_ctx)
        await self._emit(StageEvent(kind="start", stage=node.stage, tool=node.tool, done=0, total=1))
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
            timeout=self.settings.stage_timeout,
        )

    async def _fan_out(
        self, adapter: BaseTool, ctx: ToolContext, node: Node, *, parse: bool = True
    ) -> list[ToolRecord]:
        targets = ctx.inputs or ([ctx.target] if ctx.target else [])
        semaphore = asyncio.Semaphore(self.settings.concurrency)
        failures: list[tuple[str, ExecutionError]] = []
        finished = 0
        await self._emit(StageEvent(kind="start", stage=node.stage, tool=node.tool, done=0, total=len(targets)))

        async def report_progress() -> None:
            nonlocal finished
            finished += 1
            await self._emit(
                StageEvent(kind="progress", stage=node.stage, tool=node.tool, done=finished, total=len(targets))
            )

        async def run_target(target: str) -> list[ToolRecord]:
            async with semaphore:
                cmd = adapter.build_cmd(ToolContext(target=target, extra_input=ctx.extra_input))
                try:
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
                        timeout=self.settings.stage_timeout,
                    )
                except ExecutionError as exc:
                    # One unreachable host must not throw away every other
                    # host's results: record it and let the siblings finish.
                    LOG.warning(
                        "%s failed for %s: %s (stderr tail: %s)", node.tool, target, exc, exc.stderr_tail
                    )
                    failures.append((target, exc))
                    return []
                finally:
                    await report_progress()

        batches = await asyncio.gather(*(run_target(target) for target in targets))
        if targets and len(failures) == len(targets):
            first = failures[0][1]
            raise ExecutionError(
                f"{node.tool} failed for all {len(targets)} target(s); first error: {first}",
                exit_code=first.exit_code,
                stderr_tail=first.stderr_tail,
            )
        return [record for batch in batches for record in batch]

    def _materialize(self, stage_id: str, inputs: list[str]) -> Path:
        """Write ``inputs`` one per line and return the file the tool's list flag should point at.

        Lives in the session directory when there is one; an ad-hoc ``run --list``
        without ``--save`` has no session, so fall back to the system temp dir
        rather than refusing to run the tool.
        """
        if self.context is not None:
            path = self.context.session_dir / f"{stage_id}.input"
        else:
            path = Path(tempfile.gettempdir()) / f"cyberfw-{os.getpid()}-{stage_id}.input"
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
