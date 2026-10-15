"""Tab completion for the launcher's questions (``cyberfw.completion``).

The reading tests drive a real prompt_toolkit session through the ``keyboard``
fixture: keys go in from a pipe the way a person types them, and the line that
comes back is what the launcher acts on.
"""

from __future__ import annotations

import io
import re
import sys
from collections.abc import Callable

import pytest
from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.data_structures import Size
from prompt_toolkit.document import Document
from prompt_toolkit.output.vt100 import Vt100_Output
from rich.console import Console
from rich.text import Text

from cyberfw import completion
from cyberfw.completion import Option

TOOLS = [
    Option("naabu", "5 · Port scanning"),
    Option("nuclei", "6 · Vulnerability scanning"),
    Option("ffuf", "1 · Web fuzzing"),
]

Keyboard = Callable[..., str]


def _completions(typed: str) -> list[tuple[str, str]]:
    """What Tab offers after ``typed``, as (name, hint) pairs."""
    found = completion.OptionCompleter(TOOLS).get_completions(Document(typed), CompleteEvent(completion_requested=True))
    return [(item.text, item.display_meta_text) for item in found]


def _ask(console: Console | None = None, prompt: Text | str = "» Pick: ") -> Callable[[], str]:
    return lambda: completion.read_line(console or Console(), prompt, TOOLS)


class TestOptionCompleter:
    def test_offers_the_names_that_start_with_what_was_typed(self) -> None:
        assert _completions("n") == [("naabu", "5 · Port scanning"), ("nuclei", "6 · Vulnerability scanning")]
        assert _completions("nu") == [("nuclei", "6 · Vulnerability scanning")]

    def test_a_letter_inside_a_name_is_not_its_start(self) -> None:
        assert _completions("u") == []

    def test_an_empty_line_offers_every_option_in_order(self) -> None:
        assert [name for name, _hint in _completions("")] == ["naabu", "nuclei", "ffuf"]


class TestReadLine:
    def test_tab_completes_a_name_from_its_start(self, keyboard: Keyboard) -> None:
        assert keyboard(_ask(), "nu", "\t", "\r") == "nuclei"

    def test_tab_completes_whatever_the_case(self, keyboard: Keyboard) -> None:
        assert keyboard(_ask(), "NU", "\t", "\r") == "nuclei"

    def test_tab_walks_the_list_when_several_names_match(self, keyboard: Keyboard) -> None:
        # The first Tab opens the list of n-names, the second picks the first of them.
        assert keyboard(_ask(), "n", "\t", "\t\r") == "naabu"

    def test_tab_on_an_empty_line_lists_every_option(self, keyboard: Keyboard) -> None:
        # Tab opens the list, Tab picks the first option, Tab moves on to the second.
        assert keyboard(_ask(), "\t", "\t\t\r") == "nuclei"

    def test_enter_sends_the_line_as_typed(self, keyboard: Keyboard) -> None:
        assert keyboard(_ask(), "6\r") == "6"

    def test_the_question_is_drawn_in_its_rich_style(self, keyboard: Keyboard) -> None:
        # Rich renders the styled question as ANSI; prompt_toolkit must draw it
        # styled, not print the escape codes as text in the middle of it.
        screen = io.StringIO()
        output = Vt100_Output(screen, lambda: Size(rows=24, columns=80), enable_cpr=False)
        styled = Text.assemble(("» ", "bold green"), "Pick: ")
        terminal = Console(force_terminal=True, color_system="truecolor", file=io.StringIO())

        keyboard(_ask(terminal, styled), "6\r", output=output)

        visible = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", screen.getvalue())
        assert "» Pick: 6" in visible


class _Stdin(io.StringIO):
    """A stdin that is, or is not, a keyboard."""

    def __init__(self, *, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


class TestAvailable:
    """Tab completion needs a person on both ends: a terminal to draw on, a keyboard to read."""

    def test_a_terminal_with_a_keyboard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "stdin", _Stdin(tty=True))

        assert completion.available(Console(force_terminal=True, force_interactive=True)) is True

    @pytest.mark.parametrize("stdin", [_Stdin(tty=False), None], ids=["answers-piped-in", "no-stdin"])
    def test_not_without_a_keyboard(self, monkeypatch: pytest.MonkeyPatch, stdin: _Stdin | None) -> None:
        # `echo 1 | cyberfw`: the answers come from the pipe and must be read from it.
        monkeypatch.setattr(sys, "stdin", stdin)

        assert completion.available(Console(force_terminal=True, force_interactive=True)) is False

    def test_not_without_a_terminal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "stdin", _Stdin(tty=True))

        assert completion.available(Console(force_interactive=False)) is False


class TestOffering:
    def test_options_are_offered_only_inside_the_block(self) -> None:
        assert completion.offered() == ()
        with completion.offering(TOOLS):
            assert completion.offered() == tuple(TOOLS)
        assert completion.offered() == ()

    def test_an_interrupted_question_leaves_no_options_behind(self) -> None:
        # Ctrl+C at a question that offered a list: the next question must not inherit it.
        with pytest.raises(KeyboardInterrupt), completion.offering(TOOLS):
            raise KeyboardInterrupt

        assert completion.offered() == ()
