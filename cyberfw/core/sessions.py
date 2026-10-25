"""A run's session: its id, its directory under ``reports/``, and whether this run made it."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from time import strftime

from cyberfw.pipeline.context import SessionContext


@dataclass
class Session:
    """Where a run keeps its records and reports."""

    id: str
    dir: Path
    #: True when this run made ``dir``: declining to save may then remove it.
    created: bool
    #: The store records stream into as they arrive; ``None`` when they are kept in memory.
    context: SessionContext | None = None


def session_tag(kind: str, name: str) -> str:
    """A fresh session id: ``<kind>-<name>-<YYYYmmdd-HHMMSS>``."""
    return f"{kind}-{name}-{strftime('%Y%m%d-%H%M%S')}"


def checked_session(session: str) -> str:
    """Accept a session only as a plain directory name under ``reports/``.

    It is joined onto the reports directory, and a session this run created is
    removed when the user declines to save — so ``../x``, ``a/b`` or ``C:x``
    must never get as far as a path. Anything else raises :class:`ValueError`.
    """
    if session in {".", ".."} or any(ch in session for ch in "/\\:"):
        raise ValueError(f"a session must be a plain directory name under reports/, got {session!r}")
    return session


def open_session(reports_dir: Path, *, kind: str, name: str, session: str | None, stream: bool) -> Session:
    """The run's session: the id given, else a fresh one. With ``stream`` its
    records go to disk as they arrive (crash-safe); without, nothing is written yet.

    A given id must be a plain directory name (:func:`checked_session`, else
    :class:`ValueError` before anything touches the disk): a session this run
    made is removed when the run is not saved."""
    if session:
        checked_session(session)
    session_id = session or session_tag(kind, name)
    session_dir = reports_dir / session_id
    created = not session_dir.exists()
    context = SessionContext(reports_dir, session_id) if stream else None
    return Session(id=session_id, dir=session_dir, created=created, context=context)


def discard_session(session_dir: Path, *, created: bool) -> bool:
    """Remove a session directory this run created; never touch a pre-existing one.
    True when it was removed."""
    if not created:
        return False
    shutil.rmtree(session_dir, ignore_errors=True)
    return True
