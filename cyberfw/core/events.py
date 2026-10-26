"""What a run tells its caller as it goes, through a :class:`RunObserver`.

Stage and record events come from the engine as they happen; raw tool output
when a caller wants it; :class:`StepEvent` for the scan itself and each step
after it, with the step's result object on ``done``; :class:`Note` for every
other line worth showing — a skipped step, a warning, a hint.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, TypeAlias

from cyberfw.pipeline.engine import PipelineResult, StageEvent
from cyberfw.pipeline.schemas import ToolRecord
from cyberfw.report.diff import RunDiff
from cyberfw.threatintel import IntelSummary

if TYPE_CHECKING:
    from cyberfw.core.scan import Plan

#: The scan itself, then each step after it, in the order they run.
StepName: TypeAlias = Literal["scan", "tls", "mail", "takeover", "intel", "vt", "compare"]
#: Which of a tool's streams a raw output line came from.
Stream: TypeAlias = Literal["stdout", "stderr"]


@dataclass(frozen=True)
class TlsSummary:
    """Certificate health from what httpx's ``-tls-grab`` collected."""

    certificates: int
    expired: int
    #: Still valid, but expiring within ``posture.tls.SOON_DAYS``.
    soon: int
    #: Self-signed, or issued for another name.
    untrusted: int


@dataclass(frozen=True)
class MailSummary:
    """Whether mail can be forged as the seed domain."""

    domain: str
    verdict: str
    #: The name of the worst finding, when there is one.
    worst: str | None


@dataclass(frozen=True)
class TakeoverSummary:
    """Subdomains with a dangling CNAME to an unclaimed third-party service."""

    checked: int
    possible: int
    #: Up to three of the hosts concerned, sorted.
    hosts: tuple[str, ...]


@dataclass(frozen=True)
class VtSummary:
    """VirusTotal reputation lookups."""

    looked_up: int
    flagged: int


#: A step's result, sent with its ``done`` event: the scan's own is its
#: :class:`~cyberfw.pipeline.engine.PipelineResult`, the comparison with an earlier
#: run a :class:`~cyberfw.report.diff.RunDiff`, threat intel a
#: :class:`~cyberfw.threatintel.IntelSummary`.
StepSummary: TypeAlias = (
    PipelineResult | TlsSummary | MailSummary | TakeoverSummary | IntelSummary | VtSummary | RunDiff
)


@dataclass(frozen=True)
class StepEvent:
    """The scan, or a step after it, starting, advancing or done.

    ``step`` is ``scan``, ``tls``, ``mail``, ``takeover``, ``intel``, ``vt`` or
    ``compare``. A step with nothing to do sends no events; one that starts
    always ends with ``done``, after its notes — also when it fails or is
    interrupted.
    """

    kind: Literal["start", "advance", "done"]
    step: StepName
    #: Units of work, when known (takeover hosts, VirusTotal lookups).
    total: int | None = None
    #: Units finished so far, on ``advance``.
    completed: int = 0
    #: What the step is about, on ``start`` (the mail domain).
    subject: str | None = None
    #: The step's result on ``done``, when it has one.
    summary: StepSummary | None = None


@dataclass(frozen=True)
class Note:
    """A line for the user that is not a step's result."""

    level: Literal["info", "warn"]
    text: str


class RunObserver:
    """Receives a run's events. Every method does nothing: override what you need."""

    def on_plan(self, plan: Plan) -> None:
        """The pipeline as prepared — its stages, their tools' states, what blocks — before anything runs."""

    def on_stage(self, event: StageEvent) -> None:
        """A pipeline stage started, progressed or finished."""

    def on_record(self, record: ToolRecord) -> None:
        """A tool produced a record."""

    def on_output(self, line: str, stream: Stream) -> None:
        """A tool printed ``line`` on ``stream`` (``stdout`` or ``stderr``)."""

    def on_step(self, event: StepEvent) -> None:
        """The scan or a step after it started, advanced or finished."""

    def on_note(self, note: Note) -> None:
        """Something worth telling the user."""
