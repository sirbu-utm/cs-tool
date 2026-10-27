"""The contract a tool adapter is written against — cyberfw's own tools and plugins alike.

A plugin is a Python package that declares each of its tools as an entry point
in the ``cyberfw.tools`` group, pointing at a :class:`ToolPlugin`::

    [project.entry-points."cyberfw.tools"]
    foo = "cyberfw_foo:PLUGIN"

The entry point's name is the tool's name. The adapter subclasses
:class:`BaseTool`: ``build_cmd`` turns the stage's :class:`ToolContext` into the
command line, and ``parse_line`` — or ``parse_output``, for a tool that prints
one document — turns what the tool prints into records: a :class:`ToolRecord`,
or a :class:`Finding` for a problem the tool found, which the reports, SARIF,
the run comparison and triage then treat like a nuclei finding. A line that is
not the tool's output raises :class:`ParseError` and is skipped. ``install`` is
the recipe for the tool's binary — the same :class:`ToolSpec` as an entry in
``registry.yaml``.

Everything in ``__all__`` is the contract, versioned by :data:`CONTRACT` rather
than by cyberfw's own version. Adding something optional — a hook with a
default, a context field with a default — keeps the version; removing, renaming
or changing the meaning of anything bumps it, and cyberfw goes on loading the
previous version for a while (:data:`SUPPORTED_CONTRACTS`). The rest of cyberfw
is internal.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from cyberfw.exceptions import ParseError
from cyberfw.manager.registry import ToolSpec
from cyberfw.pipeline.schemas import Finding, ToolRecord, validate_record

__all__ = [
    "CONTRACT",
    "SUPPORTED_CONTRACTS",
    "BaseTool",
    "Finding",
    "ParseError",
    "ScanControls",
    "ToolContext",
    "ToolPlugin",
    "ToolRecord",
    "ToolSpec",
]

#: The contract version this cyberfw writes for.
CONTRACT = 1
#: The contract versions this cyberfw loads.
SUPPORTED_CONTRACTS = frozenset({1})


@dataclass(frozen=True)
class ScanControls:
    """Optional per-run knobs the CLI/settings pass to the tools that honour them.

    Each is off by default; an unset control adds no flag, so a command is
    unchanged from today when nothing is configured. ``rate_limit`` maps to each
    tool's own rate flag; ``severity`` / ``tags`` are nuclei's template filters.
    """

    rate_limit: int | None = None
    severity: str = ""
    tags: str = ""


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

    .. attribute:: output_dir
       The session directory, for a tool that writes files of its own (gowitness
       screenshots) — so they live and die with the session's reports.
       ``None`` when the run has no session (an unsaved ``cyberfw run``).
    """

    target: str | None = None
    inputs: list[str] = field(default_factory=list)
    input_file: Path | None = None
    extra_input: str | None = None
    output_dir: Path | None = None
    #: Optional scan controls (rate limit, nuclei severity/tags); the engine
    #: fills this from settings and every stage receives it.
    controls: ScanControls = field(default_factory=ScanControls)


class BaseTool(ABC):
    """Thin adapter over one external, precompiled binary.

    Configured by its :class:`ToolSpec` (repo, archive patterns, static CLI
    flags), it supplies what cannot be derived from that: ``build_cmd`` — the
    concrete argv for a stage — and how to read the tool's output.
    """

    #: True when this tool scans one target per invocation (fan-out per input),
    #: False when it can consume the whole input list in one process.
    per_target: bool = False

    #: True for tools that emit a single JSON document (not JSONL), so the whole
    #: stdout is collected and parsed once via :meth:`parse_output` (e.g. gitleaks).
    buffered: bool = False

    #: What the launcher asks for as this tool's single target.
    target_prompt: ClassVar[str] = "Target (domain, URL or host)"

    #: Prompt for a secondary input (e.g. a wordlist); ``None`` = nothing to ask.
    extra_input_prompt: ClassVar[str | None] = None

    def __init__(self, spec: ToolSpec, binary: Path) -> None:
        self.spec: ToolSpec = spec
        self.binary: Path = binary

    @classmethod
    def missing_requirement(cls, tools_dir: Path | None = None) -> str | None:
        """Why this tool cannot run at all right now, or ``None`` when it can.

        ``tools_dir`` lets an adapter honour a dependency the framework itself
        provisions there (gowitness's portable Chromium under ``tools_bin/``).
        For something the framework cannot ship and the tool cannot work
        without — gowitness's headless Chrome. Returned as a finished,
        user-facing sentence so the pre-flight can print it before a scan and
        the adapter can raise the same words if it gets that far. A *soft*
        dependency (RustScan's Nmap, which only adds version detection) belongs
        in ``check_deps`` in registry.yaml instead: it warns, it never blocks.
        """
        return None

    @classmethod  # noqa: B027 - intentional no-op default, not an abstract method
    def validate_target(cls, target: str) -> None:
        """Reject a target this tool cannot use, with a user-facing message.

        A classmethod so the CLI can check the *kind* of target (a URL handed
        to gitleaks, say) before it even looks for the binary — a usage error,
        not a crashed process. Raises :class:`ValueError`; accepts anything by
        default.
        """

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def input_flag(self) -> str | None:
        """The ``-l`` / ``-iL``/other flag this tool uses for a host list."""
        return None

    def prepare_inputs(self, inputs: list[str]) -> list[str]:
        """Normalise upstream targets before the engine hands them to this tool.

        Called on ``ctx.inputs`` ahead of materialising the ``input_flag`` file,
        so a tool that only understands bare hosts can strip schemes/ports from
        URLs or ``host:port`` records produced by an earlier stage. Identity by
        default; the engine deduplicates afterwards.
        """
        return inputs

    @abstractmethod
    def build_cmd(self, ctx: ToolContext) -> list[str]:
        """Return the full argv (including the binary path) to run this tool."""

    def parse_line(self, line: str, lineno: int) -> ToolRecord:
        """Validate one JSONL stdout line for this tool."""
        return validate_record(self.name, line, lineno)

    def parse_output(self, text: str) -> list[ToolRecord]:
        """Parse a whole-document stdout at once (only used when ``buffered``)."""
        return []

    # -- helpers for build_cmd -------------------------------------------------
    def rate_args(self, ctx: ToolContext, flag: str = "-rate-limit") -> list[str]:
        """``[flag, N]`` when a rate limit is set, else ``[]`` — most tools spell
        the flag ``-rate-limit``; naabu/ffuf use ``-rate``."""
        limit = ctx.controls.rate_limit
        return [flag, str(limit)] if limit else []

    def static_flags(self) -> list[str]:
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
    def unique(inputs: list[str]) -> list[str]:
        """Deduplicate while preserving order."""
        seen: set[str] = set()
        out: list[str] = []
        for item in inputs:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out


@dataclass(frozen=True)
class ToolPlugin:
    """One tool as cyberfw sees it: what a plugin's entry point points at, and how
    cyberfw describes each of its own tools."""

    #: The contract version the tool is written for, as the number itself (``1``) —
    #: never :data:`CONTRACT`, which is whatever version the running cyberfw writes
    #: for and so would pass any check.
    contract: int
    #: How to build the command and read the output.
    adapter: type[BaseTool]
    #: The model the tool's records validate against.
    record: type[ToolRecord]
    #: The recipe for the tool's binary. Required for a plugin; cyberfw's own tools
    #: leave it ``None``, their recipe being their entry in ``registry.yaml``.
    install: ToolSpec | None = None
