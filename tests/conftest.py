"""Pytest bootstrap: importable package, a colour-neutral console, no live DNS.

The package is not pip-installed during tests, and pytest rootdir resolution
alone does not guarantee the repo root is on ``sys.path``.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from prompt_toolkit.application import create_app_session
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput, Output

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Rich picks colour support from the ambient environment, and cyberfw.logging
# builds its Console at import time. A terminal (or CI runner) exporting
# FORCE_COLOR/COLORTERM would therefore inject ANSI codes into the CliRunner
# output the assertions read, splitting substrings like "target: example.com"
# apart. Pin colour off here — before any cyberfw module is imported — so the
# suite behaves the same on a developer's coloured terminal and on CI.
# Tests that check styling render through their own Console instead.
os.environ.pop("FORCE_COLOR", None)
os.environ.pop("COLORTERM", None)
os.environ["NO_COLOR"] = "1"
os.environ["TERM"] = "dumb"


@pytest.fixture(autouse=True)
def _offline_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never reach a real DNS-over-HTTPS resolver (or a takeover HTTP probe) from a test.

    ``cyberfw pipeline`` checks the seed domain's SPF/DMARC and the subdomains'
    dangling CNAMEs after every scan; in a test those would query Cloudflare and
    fetch live hosts. Here both are simply down, which the checks report and
    skip. Tests of a check itself hand it a fake resolver / fetcher instead.
    """
    from cyberfw.posture import mail, takeover

    async def no_dns(*_args: object, **_kwargs: object) -> list[str]:
        raise mail.DnsError("live DNS is disabled in tests")

    monkeypatch.setattr(mail, "doh_query", no_dns)
    monkeypatch.setattr(takeover, "doh", no_dns)


@pytest.fixture
def keyboard() -> Callable[..., str]:
    """Type into a prompt_toolkit question the way a person does.

    ``keyboard(ask, "nu", "\\t", "\\r")`` runs ``ask()`` with prompt_toolkit
    reading keys from a pipe and sends the batches one after another. Tab
    completion runs as a background task, so an Enter read together with the
    Tab before it would win the race. Each non-final batch therefore waits for
    the line (its text or its list of completions) to change **and then settle**
    — stop changing for a few polls — before the next batch, so a completion is
    fully applied before the key that acts on it. When ``ask()`` never starts
    prompt_toolkit (it fell back to plain input), nothing is typed. ``output=``
    captures what the question draws; by default it is discarded.
    """

    def type_into(ask: Callable[[], str], *batches: str, output: Output | None = None) -> str:
        done = threading.Event()
        with create_pipe_input() as pipe, create_app_session(input=pipe, output=output or DummyOutput()) as session:

            def line() -> tuple[object, object] | None:
                app = session.app
                if app is None or not app.is_running:
                    return None
                return app.current_buffer.text, app.current_buffer.complete_state

            def wait_until(landed: Callable[[], bool]) -> None:
                deadline = time.monotonic() + 5
                while not landed() and not done.is_set() and time.monotonic() < deadline:
                    time.sleep(0.004)

            def wait_settled(before: object) -> None:
                """Wait for the line to change from ``before``, then stop changing.

                The change alone can be a half-applied completion (the menu opens
                a tick before its text lands); requiring several identical polls
                lets the async completer finish, so the next key acts on the
                settled line rather than racing it."""
                wait_until(lambda: line() != before)
                last = line()
                stable = 0
                deadline = time.monotonic() + 5
                while stable < 4 and not done.is_set() and time.monotonic() < deadline:
                    time.sleep(0.004)
                    now = line()
                    if now == last:
                        stable += 1
                    else:
                        stable, last = 0, now

            def feed() -> None:
                wait_until(lambda: line() is not None)
                for index, batch in enumerate(batches):
                    if done.is_set():
                        return
                    before = line()
                    pipe.send_text(batch)
                    if index < len(batches) - 1:
                        wait_settled(before)

            feeder = threading.Thread(target=feed, daemon=True)
            feeder.start()
            try:
                return ask()
            finally:
                done.set()
                feeder.join()

    return type_into
