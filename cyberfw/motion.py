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

__all__ = ["BAR_EMPTY", "BAR_FULL", "FADE", "NOISE", "SPINNER", "bar", "ease_out", "enabled", "fade_mark", "phase", "play", "scanner", "spinner"]

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
