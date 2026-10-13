"""Terminal motion: the timing, easing and small effects the UI shares.

Every animation is decoration over a final frame that is printed either way.
On a pipe, in CI, on a dumb terminal or with ``animations: false`` only that
final frame appears — exactly the output the command had before it moved.

Glyphs stay inside code page 437, which is what the classic Windows console
fonts (Consolas, Lucida Console) are guaranteed to carry; see ``cyberfw.ui``.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from rich.console import Console, RenderableType
from rich.live import Live
from rich.text import Text

__all__ = [
    "BAR_EMPTY", "BAR_FULL", "FADE", "NOISE", "SPINNER", "Activity", "bar", "decode", "ease_out",
    "enabled", "fade_mark", "phase", "play", "scanner", "spinner",
]

#: A half block walking round its cell.
SPINNER = "▀▐▄▌"
#: Shades a fresh mark fades through, newest first.
FADE = "█▓▒░"
#: What a wordmark cell flickers through before it settles.
NOISE = "░▒▓"

#: Filled and empty cells of a bar: a thick stroke over a thin track. Full
#: blocks would fuse the bars of adjacent rows into one solid slab.
BAR_FULL, BAR_EMPTY = "▬", "─"


def enabled(console: Console, wanted: bool = True) -> bool:
    """Animate only when asked to and there is a real terminal to redraw."""
    return wanted and console.is_terminal and not console.is_dumb_terminal


def ease_out(progress: float) -> float:
    """Cubic ease-out: quick start, gentle landing."""
    progress = min(max(progress, 0.0), 1.0)
    return 1 - (1 - progress) ** 3


def phase(progress: float, start: float, end: float) -> float:
    """``progress`` rescaled to one act of an animation: 0 before ``start``, 1 from ``end``."""
    return min(max((progress - start) / (end - start), 0.0), 1.0)


def spinner(now: float, fps: float = 8.0) -> str:
    """The spinner frame for monotonic time ``now``."""
    return SPINNER[int(now * fps) % len(SPINNER)]


def fade_mark(age: float, span: float = 1.0) -> str:
    """``█`` → ``▓`` → ``▒`` → ``░`` → blank as ``age`` runs over ``span`` seconds."""
    if age < 0 or age >= span:
        return " "
    return FADE[int(age / span * len(FADE))]


def bar(fraction: float, width: int, *, style: str, track: str = "muted", shine: float | None = None) -> Text:
    """A ``width``-cell bar filled to ``fraction``.

    ``shine`` (0..1, usually derived from the clock) sends one bright cell
    along the filled part, so a bar that is waiting still looks alive.
    """
    filled = round(min(max(fraction, 0.0), 1.0) * width)
    glint = int(shine * filled) if shine is not None and filled else -1
    text = Text()
    for index in range(width):
        if index < filled:
            text.append(BAR_FULL, style="bold bright_white" if index == glint else style)
        else:
            text.append(BAR_EMPTY, style=track)
    return text


def scanner(now: float, width: int, *, style: str, track: str = "muted", period: float = 1.4) -> Text:
    """An indeterminate bar: a three-cell stroke sweeping end to end and back,
    brightest in the middle."""
    span = max(width - 3, 1)
    travel = (now % period) / period * 2 * span
    head = round(travel if travel <= span else 2 * span - travel)
    text = Text()
    for index in range(width):
        offset = index - head
        if offset == 1:
            text.append(BAR_FULL, style="bold bright_white")
        elif offset in (0, 2):
            text.append(BAR_FULL, style=style)
        else:
            text.append(BAR_EMPTY, style=track)
    return text


def decode(text: str, progress: float, *, style: str = "", noise_style: str = "accent", seed: int = 0) -> Text:
    """``text`` resolving out of noise, left to right, as ``progress`` runs 0 → 1.

    Settled characters keep ``style``; the rest flicker through :data:`NOISE`.
    Spaces stay spaces, so the shape of the words shows from the first frame.
    At 1.0 it is exactly ``text`` — the frame a non-animated run prints.
    """
    settled = int(len(text) * min(max(progress, 0.0), 1.0))
    tick = int(progress * 40) + seed
    out = Text()
    for index, char in enumerate(text):
        if index < settled or char == " ":
            out.append(char, style=style)
        else:
            out.append(NOISE[(index + tick) % len(NOISE)], style=noise_style)
    return out


class Activity:
    """A one-line live indicator for a step that blocks: spinner, label, a
    sweeping bar (or, with ``total``, a filling one and ``done/total``) and the
    seconds elapsed.

    Used as a context manager around the blocking call; ``advance()`` moves the
    count from inside it (a callback is fine — the line is redrawn from a
    timer, not by the caller). The line is transient: when the step ends it
    vanishes and the caller prints its usual result line, so with animation off
    — no terminal, a pipe, ``animations: false`` — nothing is printed for it at
    all and the output is exactly what it was before.
    """

    def __init__(
        self,
        console: Console,
        label: str,
        *,
        animate: bool = True,
        total: int | None = None,
        detail: str = "",
        width: int = 16,
    ) -> None:
        self.console = console
        self.label = label
        self.total = total
        self.done = 0
        self.detail = detail
        self.width = width
        self.animated = enabled(console, animate)
        self._live: Live | None = None
        self._start = time.perf_counter()

    def advance(self, done: int | None = None, *, detail: str | None = None) -> None:
        """Set (or bump by one) the count of finished items, optionally the detail."""
        self.done = self.done + 1 if done is None else done
        if detail is not None:
            self.detail = detail

    def __rich__(self) -> Text:
        now = time.perf_counter()
        line = Text()
        line.append(spinner(now, fps=10), style="accent")
        line.append(" ")
        line.append(self.label, style="bold white")
        line.append("  ")
        if self.total:
            fraction = min(self.done / self.total, 1.0)
            line.append_text(bar(fraction, self.width, style="accent", shine=(now % 1.2) / 1.2))
            line.append(f" {self.done}/{self.total}", style="white")
        else:
            line.append_text(scanner(now, self.width, style="accent"))
        line.append(f"  {now - self._start:4.1f}s", style="muted")
        if self.detail:
            line.append(f"  {self.detail}", style="muted")
        return line

    def __enter__(self) -> Activity:
        self._start = time.perf_counter()
        if self.animated:
            self._live = Live(self, console=self.console, refresh_per_second=12, transient=True)
            self._live.__enter__()
        return self

    def __exit__(self, *exc: object) -> None:
        if self._live is not None:
            self._live.__exit__(None, None, None)
            self._live = None


def play(
    console: Console,
    frame: Callable[[float], RenderableType],
    *,
    duration: float,
    animate: bool = True,
    fps: int = 30,
) -> None:
    """Show ``frame(p)`` for ``p`` running 0 → 1 over ``duration``; ``frame(1.0)`` stays.

    Without animation — not asked for, no terminal, or a frame taller than the
    window (Live would crop it to an ellipsis) — ``frame(1.0)`` is printed once.
    """
    final = frame(1.0)
    if not enabled(console, animate) or len(console.render_lines(final, pad=False)) >= console.size.height:
        console.print(final)
        return
    frames = max(1, round(duration * fps))
    with Live(frame(0.0), console=console, auto_refresh=False, transient=False) as live:
        start = time.perf_counter()
        for index in range(1, frames):
            delay = start + index / fps - time.perf_counter()
            if delay > 0:
                time.sleep(delay)
            live.update(frame(index / frames), refresh=True)
        live.update(final, refresh=True)
