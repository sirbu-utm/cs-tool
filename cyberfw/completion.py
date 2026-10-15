"""Tab completion for the launcher's questions.

Rich reads an answer with plain ``input()``, which on Windows has no line
editing at all (there is no ``readline``): Tab just types a tab. A question
with a known set of answers — the launcher's tools and actions, the pipeline
names — offers them with :func:`offering`, and at a terminal its answer is
then read through prompt_toolkit instead: Tab completes the word typed so far
or opens the list of answers, Tab / Shift+Tab / the arrows walk it, Enter
sends the line. The list opens only on Tab, never while typing, so a hotkey
and Enter stay as quiet as before.

Without a person on both ends — a pipe, CI, a test — the question reads its
answer exactly as before.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from prompt_toolkit import prompt as _prompt_toolkit_read
from prompt_toolkit.completion import CompleteEvent, Completer, Completion
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.text import TextType

__all__ = ["Option", "OptionCompleter", "available", "offered", "offering", "read_line"]


@dataclass(frozen=True)
class Option:
    """One answer a question offers: the word Tab puts on the line, and the
    hint shown beside it in the list."""

    name: str
    hint: str = ""


class OptionCompleter(Completer):
    """Completes the line to the options whose name starts with it, ignoring
    case, in the order they were given."""

    def __init__(self, options: Sequence[Option]) -> None:
        self.options = tuple(options)

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterator[Completion]:
        typed = document.text_before_cursor
        start = typed.strip().lower()
        for option in self.options:
            if option.name.lower().startswith(start):
                # Replace everything typed so far: "NU" becomes "nuclei", not "NUclei".
                yield Completion(option.name, start_position=-len(typed), display_meta=option.hint)


_OFFERED: ContextVar[tuple[Option, ...]] = ContextVar("cyberfw_offered_options", default=())


@contextmanager
def offering(options: Iterable[Option]) -> Iterator[None]:
    """Offer ``options`` on Tab to the questions asked inside the block."""
    token = _OFFERED.set(tuple(options))
    try:
        yield
    finally:
        _OFFERED.reset(token)


def offered() -> tuple[Option, ...]:
    """The options on offer to the question being asked; empty outside :func:`offering`."""
    return _OFFERED.get()


def available(console: Console) -> bool:
    """True when a person is at both ends: ``console`` draws on a terminal and
    the keys come from a keyboard.

    Answers piped in (``echo 1 | cyberfw``) must be read from that pipe, so a
    redirected stdin keeps plain input even when the output is a terminal.
    """
    if not console.is_interactive:
        return False
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except (OSError, ValueError):  # a closed or detached stdin
        return False


#: The list in the HUD's colours: a dark ground, the current answer on the
#: brand ramp's green, its hint on the ramp's cyan, other hints muted grey.
_STYLE = Style.from_dict(
    {
        "completion-menu.completion": "bg:#262626 #d0d0d0",
        "completion-menu.completion.current": "bg:#2ed573 #000000",
        "completion-menu.meta.completion": "bg:#262626 #949494",
        "completion-menu.meta.completion.current": "bg:#2ec5d5 #000000",
        "scrollbar.background": "bg:#3a3a3a",
        "scrollbar.button": "bg:#2ec5d5",
    }
)

#: The most rows the list shows at once; prompt_toolkit's own menu stops at 16.
_LIST_ROWS = 16


def read_line(console: Console, prompt: TextType, options: Sequence[Option]) -> str:
    """Read one line at the terminal, with ``options`` on Tab.

    The question looks as Rich would print it: ``console`` renders it to ANSI
    and prompt_toolkit draws that in front of the line.
    """
    with console.capture() as capture:
        console.print(prompt, end="")
    return _prompt_toolkit_read(
        ANSI(capture.get()),
        completer=OptionCompleter(options),
        complete_while_typing=False,
        # Room for the whole list under the line (the screen scrolls up if it
        # must), rather than a few rows of it to scroll through.
        reserve_space_for_menu=min(len(options), _LIST_ROWS) + 1,
        style=_STYLE,
    )
