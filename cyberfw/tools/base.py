"""BaseTool — ABC every tool adapter implements.

Each adapter is declaratively configured by a :class:`ToolSpec` from
``registry.yaml`` (repo, archive patterns, static CLI flags) and supplies two
things the framework cannot derive from YAML:

* ``build_cmd(ctx)`` — turn a validated cross-tool context into the concrete
  argv for this utility,
* ``parse_line`` — delegate JSONL validation to the per-tool Pydantic schema
  (``validate_record``), which is the shape-specific part of "adding a tool".

Adding a brand-new tool normally means: an entry in ``registry.yaml`` plus, when
its JSONL schema is novel, a model in ``pipeline/schemas.py`` — no changes to the
engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from cyberfw.manager.registry import ToolSpec
from cyberfw.pipeline.schemas import ToolRecord, validate_record

__all__ = ["ToolContext", "BaseTool"]


@dataclass
class ToolContext:
    """Net-new, cross-stage inputs a stage runs with.

    .. attribute:: target
       The explicit ``-d`` style seed for the first stage (e.g. a domain).

    .. attribute:: inputs
       Targets passed through from the previous stage (hosts / URLs).

    .. attribute:: input_file
       Engine-materialised file with the ``inputs`` (one per line) when the
       tool accepts a host list (``-l`` / ``-iL``).

    .. attribute:: extra_input
       Optional secondary path (e.g. a fuzz wordlist) supplied by the user.
    """

    target: str | None = None
    inputs: list[str] = field(default_factory=list)
    input_file: Path | None = None
    extra_input: str | None = None


class BaseTool(ABC):
    """Thin adapter over one external, precompiled binary."""

    #: True when this tool scans one target per invocation (fan-out per input),
    #: False when it can consume the whole input list in one process.
    per_target: bool = False

    #: True for tools that emit a single JSON document (not JSONL), so the whole
    #: stdout is collected and parsed once via :meth:`parse_output` (e.g. gitleaks).
    buffered: bool = False

    def __init__(self, spec: ToolSpec, binary: Path) -> None:
        self.spec: ToolSpec = spec
        self.binary: Path = binary

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def input_flag(self) -> str | None:
        """The ``-l`` / ``-iL``/other flag this tool uses for a host list."""
        return None

    @abstractmethod
    def build_cmd(self, ctx: ToolContext) -> list[str]:
        """Return the full argv (including the binary path) to run this tool."""

    def parse_line(self, line: str, lineno: int) -> ToolRecord:
        """Validate one JSONL stdout line for this tool."""
        return validate_record(self.name, line, lineno)

    def parse_output(self, text: str) -> list[ToolRecord]:
        """Parse a whole-document stdout at once (only used when ``buffered``)."""
        return []

    # -- shared flag helpers --------------------------------------------------
    def _static_flags(self) -> list[str]:
        """Flatten ``spec.interactive_input`` ({flag: value}) into argv args.

        A flag with an empty value is emitted alone (a switch); a flag with a
        value emits ``[flag, value]``. Order follows the YAML mapping order.
        """
        flags: list[str] = []
        for flag, value in (self.spec.interactive_input or {}).items():
            flags.append(flag)
            if value:
                flags.append(str(value))
        return flags

    @staticmethod
    def _u(inputs: list[str]) -> list[str]:
        """Deduplicate while preserving order."""
        seen: set[str] = set()
        out: list[str] = []
        for item in inputs:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out
