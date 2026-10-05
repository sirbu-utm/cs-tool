"""Rich presentation helpers for the command-line interface.

The startup banner follows the classic OSINT-tool convention (Sherlock,
theHarvester, recon-ng, ...): a big pre-rendered ANSI/block-art wordmark
printed straight to the terminal, followed by a green-to-cyan gradient rule
and a one-line status strip (a pip per tool, then the ready count, platform
and version). ``CS_TOOL_LOGO`` and ``UNIV_LOGO`` are exported verbatim from a
terminal capture — the escape codes are restored at import time because the
literal ``ESC`` control byte does not survive a plain-text paste.
"""

from __future__ import annotations

import functools
from collections.abc import Iterator, Sequence

from rich.cells import cell_len
from rich.color import Color, blend_rgb
from rich.color_triplet import ColorTriplet
from rich.console import Console, ConsoleOptions, Group, RenderableType, RenderResult
from rich.measure import Measurement
from rich.segment import Segment
from rich.style import Style
from rich.table import Table
from rich.text import Text

from cyberfw import __version__
from cyberfw.hud import EdgeRule, Flow, HudFrame, Pane, join
from cyberfw.motion import NOISE, phase
from cyberfw.pipeline.schemas import ToolRecord

CS_TOOL_LOGO = "\x1b[0m" """\x1b[0;37m  \x1b[0;90m▄\x1b[0;37m▄\x1b[0;97m▄▄▄▄▄\x1b[0;37m▄\x1b[0;90m▄\x1b[0;37m   \x1b[0;90m▄\x1b[0;37m▄\x1b[0;97m▄▄▄▄▄\x1b[0;37m▄      \x1b[0;97m▄▄▄▄▄▄▄▄▄▄▄\x1b[0;37m   \x1b[0;90m▄\x1b[0;37m▄\x1b[0;97m▄▄▄▄\x1b[0;37m▄\x1b[0;90m▄\x1b[0;37m     \x1b[0;90m▄\x1b[0;37m▄\x1b[0;97m▄▄▄▄\x1b[0;37m▄\x1b[0;90m▄\x1b[0;37m   \x1b[0;97m▄▄▄▄▄\x1b[0;37m      \x1b[0m
\x1b[0;37m \x1b[0;97;47m▄\x1b[0;97;46m▀▀\x1b[0;36m█████\x1b[0;97;46m▀\x1b[0;97;47m▄\x1b[0;37m \x1b[0;90;47m▀\x1b[0;97;47m▄\x1b[0;97;46m▀▀\x1b[0;36m█████\x1b[0;97;47m░\x1b[0;37m      \x1b[0;97m█\x1b[0;36m█████████\x1b[0;97m▓\x1b[0;37m \x1b[0;90m▄\x1b[0;97;47m▄\x1b[0;97;46m▀▀\x1b[0;36m████\x1b[0;97;46m▀▀\x1b[0;97;47m▄\x1b[0;90m▄\x1b[0;37m \x1b[0;90m▄\x1b[0;97;47m▄\x1b[0;97;46m▀▀\x1b[0;36m████\x1b[0;97;46m▀▀\x1b[0;97;47m▄\x1b[0;90m▄\x1b[0;37m \x1b[0;97m▓\x1b[0;36m███\x1b[0;97m▓\x1b[0;37m      \x1b[0m
\x1b[0;97m▐\x1b[0;36m███\x1b[0;97;46m░\x1b[0;97m▀▀\x1b[0;97;46m▒\x1b[0;36m██\x1b[0;97m▓\x1b[0;37m \x1b[0;97;47m▀\x1b[0;36m██\x1b[0;97;46m▄\x1b[0;90;47m▄\x1b[0;37m▀\x1b[0;36m▀▀▀\x1b[0;90m▀\x1b[0;37m      ▀▀▀\x1b[0;97m▓\x1b[0;36m███\x1b[0;37m▓▀▀▀ \x1b[0;90;47m▌\x1b[0;36m███\x1b[0;37;46m▄\x1b[0;97m▀▀\x1b[0;37;46m▄\x1b[0;36m███\x1b[0;90;47m▐\x1b[0;37m \x1b[0;90;47m▌\x1b[0;36m███\x1b[0;37;46m▄\x1b[0;97m▀▀\x1b[0;37;46m▄\x1b[0;36m███\x1b[0;90;47m▐\x1b[0;37m \x1b[0;97m▒\x1b[0;36m███\x1b[0;97;42m▒\x1b[0;37m      \x1b[0m
\x1b[0;37;42m▒\x1b[0;36m███\x1b[0;37m▓  ▀▀▀▀ \x1b[0;90m▀\x1b[0;90;46m▄\x1b[0;36m█\x1b[0;90;46m▀▀▀▀▀\x1b[0;90m▄\x1b[0;37m          \x1b[0;37;42m▓\x1b[0;36m███\x1b[0;37m▒    \x1b[0;37;42m▓\x1b[0;36m███▌\x1b[0;37m  \x1b[0;36m▐███\x1b[0;37;42m▓\x1b[0;37m \x1b[0;37;42m▓\x1b[0;36m███▌\x1b[0;37m  \x1b[0;36m▐███\x1b[0;37;42m▓\x1b[0;37m \x1b[0;37;42m▒\x1b[0;36m███\x1b[0;97;42m░\x1b[0;37m      \x1b[0m
\x1b[0;37;42m░\x1b[0;36m▓▓▓\x1b[0;32m▒\x1b[0;37m  ▄\x1b[0;36m▄▄▄\x1b[0;37m   \x1b[0;90m▀▀▀▀\x1b[0;37;42m░\x1b[0;36m▓▓\x1b[0;90;42m▀\x1b[0;37m         \x1b[0;37;42m▒\x1b[0;36m▓▓▓\x1b[0;32m░\x1b[0;37m    \x1b[0;90;47m▌\x1b[0;36m▓▓▓\x1b[0;32m▌\x1b[0;37m  \x1b[0;32m▐\x1b[0;36m▓▓▓\x1b[0;37;42m▒\x1b[0;37m \x1b[0;90;47m▌\x1b[0;36m▓▓▓\x1b[0;32m▌\x1b[0;37m  \x1b[0;32m▐\x1b[0;36m▓▓▓\x1b[0;37;42m▒\x1b[0;37m \x1b[0;37;42m░\x1b[0;36m▓▓▓\x1b[0;32m█\x1b[0;37m  \x1b[0;36m▄▄▄▄\x1b[0m
\x1b[0;90;42m▌\x1b[0;36;42m▌\x1b[0;36m▒▒\x1b[0;32m▓▄▄\x1b[0;37m▓\x1b[0;36m▒▒\x1b[0;37;42m▓\x1b[0;37m \x1b[0;37;42m░\x1b[0;36m▒▒\x1b[0;37;42m▓\x1b[0;36m▄▄\x1b[0;37;42m▓\x1b[0;36m▒▒\x1b[0;37;42m░\x1b[0;37m         \x1b[0;37;42m░\x1b[0;36m▒▒▒\x1b[0;32m▒\x1b[0;37m    \x1b[0;90;42m▌\x1b[0;36m▒▒▒\x1b[0;90;42m▄\x1b[0;32m▄▄\x1b[0;90;42m▄\x1b[0;36m▒▒▒\x1b[0;90;42m▐\x1b[0;37m \x1b[0;90;42m▌\x1b[0;36m▒▒▒\x1b[0;90;42m▄\x1b[0;32m▄▄\x1b[0;90;42m▄\x1b[0;36m▒▒▒\x1b[0;90;42m▐\x1b[0;37m \x1b[0;90;42m▌\x1b[0;36m▒▒▒\x1b[0;32;46m▀\x1b[0;32m▄▄▓\x1b[0;36m▒▒\x1b[0;37;42m▓\x1b[0m
\x1b[0;90m▀\x1b[0;90;42m▄\x1b[0;90;46m▀\x1b[0;36m░░░░░░\x1b[0;90;46m▀\x1b[0;90;42m▄\x1b[0;37m \x1b[0;32m█\x1b[0;36m░░░░░░\x1b[0;90;42m▀▀▄\x1b[0;37m         \x1b[0;32m█\x1b[0;36m░░░\x1b[0;32m▓\x1b[0;37m    \x1b[0;90m▀\x1b[0;90;42m▄▀\x1b[0;36m░░░░░░\x1b[0;90;42m▀▄\x1b[0;90m▀\x1b[0;37m \x1b[0;90m▀\x1b[0;90;42m▄▀\x1b[0;36m░░░░░░\x1b[0;90;42m▀▄\x1b[0;90m▀\x1b[0;37m \x1b[0;90m▀\x1b[0;90;42m▄▀\x1b[0;36m░░░░░░░\x1b[0;32m▓\x1b[0m
\x1b[0;37m  \x1b[0;90m▀\x1b[0;32m▀▀▀▀▀▀\x1b[0;90m▀\x1b[0;37m  \x1b[0;32m▀▀▀▀▀▀▀\x1b[0;90m▀\x1b[0;37m           \x1b[0;32m▀▀▀▀▀\x1b[0;37m       \x1b[0;90m▀\x1b[0;32m▀▀▀▀\x1b[0;90m▀\x1b[0;37m       \x1b[0;90m▀\x1b[0;32m▀▀▀▀\x1b[0;90m▀\x1b[0;37m       \x1b[0;90m▀\x1b[0;32m▀▀▀▀▀▀▀\x1b[0m"""

UNIV_LOGO = "\x1b[0m" """\x1b[0;37m▄\x1b[0;97m▄▄▄\x1b[0;37m▄  ▄\x1b[0;97m▄▄▄\x1b[0;37m▄ \x1b[0;97m▄▄▄▄▄▄▄▄▄▄▄\x1b[0;37m \x1b[0;97m▄▄▄▄▄▄\x1b[0;37m▄\x1b[0;90m▄\x1b[0;37m ▄\x1b[0;97m▄▄\x1b[0;37m▄\x1b[0;90m▄\x1b[0;37m  \x1b[0m
\x1b[0;97;47m░\x1b[0;36m███\x1b[0;97;47m░\x1b[0;37m  \x1b[0;97;47m░\x1b[0;36m███\x1b[0;97m▓\x1b[0;37m \x1b[0;97m█\x1b[0;36m█████████\x1b[0;97m▓\x1b[0;37m \x1b[0;97m▓\x1b[0;36m██████\x1b[0;97;46m▀\x1b[0;90;47m▀\x1b[0;97;46m▀\x1b[0;36m███\x1b[0;97;46m▀\x1b[0;97;47m▄\x1b[0;90;47m▀\x1b[0m
\x1b[0;37m▓\x1b[0;36m███\x1b[0;37;42m▓\x1b[0;37m  \x1b[0;37;42m▓\x1b[0;36m███\x1b[0;37m▓ ▀▀▀\x1b[0;97m▓\x1b[0;36m███\x1b[0;37m▓▀▀▀ \x1b[0;97m▒\x1b[0;36m██\x1b[0;97m▒\x1b[0;97;46m▀\x1b[0;97;47m▀▄\x1b[0;36m██\x1b[0;97m▓\x1b[0;97;46m▀\x1b[0;97;47m▀\x1b[0;97;46m▄\x1b[0;36m██\x1b[0;97;47m▌\x1b[0m
\x1b[0;37;42m▓\x1b[0;36m███\x1b[0;37;42m▒\x1b[0;37m  \x1b[0;37;42m▒\x1b[0;36m███\x1b[0;37;42m▓\x1b[0;37m    \x1b[0;37;42m▓\x1b[0;36m███\x1b[0;37m▒    \x1b[0;37;42m▓\x1b[0;36m██\x1b[0;37m▓ \x1b[0;90m▐\x1b[0;37m▒\x1b[0;36m██\x1b[0;37;42m▓\x1b[0;37m \x1b[0;90m▐\x1b[0;37m▒\x1b[0;36m██\x1b[0;37;42m▓\x1b[0m
\x1b[0;37;42m▒\x1b[0;36m▓▓▓\x1b[0;37;42m░\x1b[0;37m  \x1b[0;37;42m░\x1b[0;36m▓▓▓\x1b[0;37;42m▒\x1b[0;37m    \x1b[0;37;42m▒\x1b[0;36m▓▓▓\x1b[0;32m░\x1b[0;37m    \x1b[0;37;42m▒\x1b[0;36m▓▓\x1b[0;32m░\x1b[0;37m  \x1b[0;32m░\x1b[0;36m▓▓\x1b[0;37;42m▒\x1b[0;37m  \x1b[0;32m░\x1b[0;36m▓▓\x1b[0;37;42m▒\x1b[0m
\x1b[0;90;42m▌\x1b[0;36m▒▒▒\x1b[0;90;42m▄▀▀▄\x1b[0;36m▒▒▒\x1b[0;90;42m▐\x1b[0;37m    \x1b[0;37;42m░\x1b[0;36m▒▒▒\x1b[0;32m▒\x1b[0;37m    \x1b[0;37;42m░\x1b[0;36m▒▒\x1b[0;32m▒\x1b[0;37m  \x1b[0;32m▒\x1b[0;36m▒▒\x1b[0;37;42m░\x1b[0;37m  \x1b[0;32m▒\x1b[0;36m▒▒\x1b[0;37;42m░\x1b[0m
\x1b[0;37m \x1b[0;90;42m▄▀\x1b[0;36m░░░░░░\x1b[0;90;42m▀▄\x1b[0;37m     \x1b[0;32m█\x1b[0;36m░░░\x1b[0;32m▓\x1b[0;37m    \x1b[0;32m█\x1b[0;36m░░\x1b[0;32m▓\x1b[0;37m  \x1b[0;32m▓\x1b[0;36m░░\x1b[0;32m▓\x1b[0;37m  \x1b[0;32m▓\x1b[0;36m░░\x1b[0;32m▓\x1b[0m
\x1b[0;37m   \x1b[0;90m▀\x1b[0;32m▀▀▀▀\x1b[0;90m▀\x1b[0;37m       \x1b[0;32m▀▀▀▀▀\x1b[0;37m    \x1b[0;32m▀▀▀▀\x1b[0;37m  \x1b[0;32m▀▀▀▀\x1b[0;37m  \x1b[0;32m▀▀▀▀\x1b[0m"""

TOOL_GUIDES: dict[str, tuple[str, str, str]] = {
    "ffuf": (
        "Web fuzzing",
        "Searches hidden directories, files and parameters on a web server.",
        "ffuf -u https://example.com/FUZZ -w wordlist.txt",
    ),
    "gitleaks": (
        "Secret scanning",
        "Finds passwords, API keys and other secrets in a local repository.",
        "gitleaks dir C:\\Projects\\app",
    ),
    "gowitness": (
        "Web screenshots",
        "Captures screenshots of web pages and helps review live hosts visually.",
        "gowitness scan single --url https://example.com",
    ),
    "httpx": (
        "HTTP probing",
        "Checks live web services and reports status, title and technologies.",
        "httpx -u https://example.com -json",
    ),
    "naabu": (
        "Port scanning",
        "Finds open TCP ports on a host or a list of hosts.",
        "naabu -host example.com -json",
    ),
    "nuclei": (
        "Vulnerability scanning",
        "Runs templates to detect known vulnerabilities and misconfigurations.",
        "nuclei -u https://example.com -jsonl",
    ),
    "rustscan": (
        "Fast port discovery",
        "Rapidly discovers open ports. Run Nmap separately when service/version detection is needed.",
        "rustscan --addresses example.com --greppable",
    ),
    "subfinder": (
        "Subdomain discovery",
        "Collects subdomains from passive OSINT sources.",
        "subfinder -d example.com -json",
    ),
}


def tool_guide(
    name: str, *, state: str | None = None, version: str | None = None, repo: str | None = None
) -> HudFrame:
    """The card shown after picking a tool: what it does, where it stands and
    how it is called. ``state`` / ``version`` / ``repo`` come from the
    launcher's inventory pass; without a state the facts pane is left out."""
    title, description, example = TOOL_GUIDES.get(
        name,
        ("Security utility", "Runs the selected registered security tool.", f"cs-tool run {name} -t example.com"),
    )
    about = Group(Text(title, style="accent"), Text(description, style="white"))
    top = [Pane(about, title=Text(name))]
    if state is not None:
        facts = Table.grid(padding=(0, 2))
        facts.add_column(style="muted", no_wrap=True)
        facts.add_column(no_wrap=True, overflow="ellipsis")
        facts.add_row("state", pip_word(state, state_style(state)))
        facts.add_row("version", Text(version or "—"))
        if repo:
            facts.add_row("source", Text(repo, style="muted"))
        top.append(Pane(facts, title="Tool", width=max(26, 10 + len(repo or ""))))
    command, _, rest = example.partition(" ")
    call = Text.assemble(("$ ", "muted"), (command, "bold bright_cyan"), (f" {rest}", "white"))
    return HudFrame([top, Pane(call, title="Example")])


def pip_word(word: str, style: str) -> Text:
    """``■ ready`` — the banner's pip in the state's colour, then the word.

    The style is the Text's own rather than a span's, so a table cell holding
    it still reports the state's style.
    """
    return Text(f"{PIP} {word}", style=style)


# Glyphs are limited to what both classic Windows console fonts carry (checked
# against the cmaps of consola.ttf and lucon.ttf): U+25B0 ▰ is in neither, and
# U+2501 ━ and the rounded box corners are missing from Lucida Console, so a
# conhost window drew empty boxes in their place. The wordmark itself is built
# from the same half blocks, which is why it always rendered.

#: One square per registered tool in the banner's status strip.
PIP = "■"

#: The character the gradient rule is drawn with.
RULE_CHAR = "▀"

#: The rule is exactly as wide as the wordmark above it, never wider.
_RULE_MAX_WIDTH = max(cell_len(line) for line in Text.from_ansi(CS_TOOL_LOGO).plain.splitlines())

#: Ends of the truecolor ramp.
_RULE_FROM = ColorTriplet(0x2E, 0xD5, 0x73)  # green
_RULE_TO = ColorTriplet(0x2E, 0xC5, 0xD5)  # cyan

#: Stand-ins for terminals that cannot show the ramp. Downgraded cell by cell,
#: it collapsed on a 16-colour terminal into 10 green cells and 68 cyan ones,
#: so those palettes get even bands of colours they really have.
_RULE_BANDS_256 = tuple(Color.from_ansi(number) for number in (40, 41, 42, 43, 44))  # green3 .. dark turquoise
_RULE_BANDS_16 = tuple(Color.parse(name) for name in ("green", "bright_green", "bright_cyan", "cyan"))

#: How each tool state reads — the one map the banner's pips, the inventory
#: table and the launcher all use. ``blocked`` means the file is on disk but
#: cannot be read or run (an antivirus quarantine, not a missing download).
STATE_STYLES: dict[str, str] = {"ready": "ok", "blocked": "err", "not installed": "warn"}

#: An unrecognised state must not pass for ready.
_UNKNOWN_STATE_STYLE = "warn"


def state_style(state: str) -> str:
    """Theme style for one tool state (``ready`` / ``blocked`` / ``not installed``)."""
    return STATE_STYLES.get(state, _UNKNOWN_STATE_STYLE)


def readiness(states: Sequence[str]) -> Text:
    """``3/8 ready`` — the one number that answers "can I run a pipeline?".

    Green when everything can run, yellow when some can, red when none can —
    including an empty registry, where there is nothing to run at all.
    """
    ready = sum(1 for state in states if state == "ready")
    if states and ready == len(states):
        style = "ok"
    elif ready:
        style = "warn"
    else:
        style = "err"
    return Text(f"{ready}/{len(states)} ready", style=style)


class GradientRule:
    """A horizontal rule whose colour slides from green to cyan.

    A renderable rather than a pre-coloured string, so it follows the terminal:
    a smooth per-cell ramp in truecolor, even bands from the palette the
    terminal really has otherwise, and a plain line when there is no colour.

    ``progress`` below 1 draws only the leading part of the rule, tipped with a
    bright cell — the banner's intro draws the line from left to right.
    """

    def __init__(self, progress: float = 1.0) -> None:
        self.progress = progress

    def __rich_measure__(self, console: Console, options: ConsoleOptions) -> Measurement:
        width = min(options.max_width, _RULE_MAX_WIDTH)
        return Measurement(width, width)

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        width = max(1, min(options.max_width, _RULE_MAX_WIDTH))
        if self.progress >= 1:
            yield from self._cells(console, width)
        else:
            drawn = int(width * max(self.progress, 0.0))
            cells = [(char, segment.style) for segment in self._cells(console, width) for char in segment.text]
            for index, (char, style) in enumerate(cells[:drawn]):
                yield Segment(char, _RULE_TIP if index == drawn - 1 else style)
        yield Segment.line()

    @staticmethod
    def _cells(console: Console, width: int) -> Iterator[Segment]:
        if console.color_system == "256":
            yield from _bands(_RULE_BANDS_256, width)
        elif console.color_system in ("standard", "windows"):
            yield from _bands(_RULE_BANDS_16, width)
        else:
            # truecolor, or no colour at all (the styles are dropped then).
            last = max(width - 1, 1)
            for index in range(width):
                colour = Color.from_triplet(blend_rgb(_RULE_FROM, _RULE_TO, index / last))
                yield Segment(RULE_CHAR, Style(color=colour))


#: The bright leading cell of a rule that is still being drawn.
_RULE_TIP = Style(color="bright_white", bold=True)


def _bands(colours: Sequence[Color], width: int) -> Iterator[Segment]:
    """``width`` rule cells split into near-equal runs, one per colour, in order."""
    for index, colour in enumerate(colours):
        start = width * index // len(colours)
        end = width * (index + 1) // len(colours)
        if end > start:
            yield Segment(RULE_CHAR * (end - start), Style(color=colour))


def gradient_rule() -> GradientRule:
    """The banner's rule, in the framework's green-to-cyan palette."""
    return GradientRule()


def attention(states: Sequence[str]) -> Text:
    """``1 blocked · 2 not installed`` in the states' colours; empty when all run."""
    counts = {state: sum(1 for s in states if s == state) for state in ("blocked", "not installed")}
    return Text(" · ").join(
        Text(f"{count} {state}", style=state_style(state)) for state, count in counts.items() if count
    )


def _pips(states: Sequence[str], progress: float = 1.0) -> tuple[Text, Text]:
    """One pip per tool and the ready count. Below ``progress`` 1 the pips light
    up one by one (the newest flashes) and the counter counts those lit so far."""
    lit = len(states) if progress >= 1 else int(len(states) * max(progress, 0.0))
    pips = Text()
    for index, state in enumerate(states):
        if index >= lit:
            pips.append(PIP, style="muted")
        else:
            pips.append(PIP, style="bold bright_white" if progress < 1 and index == lit - 1 else state_style(state))
    if progress >= 1:
        counter = readiness(states)
    else:
        counter = Text(f"{sum(1 for state in states[:lit] if state == 'ready')}/{len(states)} ready", style="muted")
    return pips, counter


def _status_strip(states: Sequence[str], platform: str, progress: float = 1.0) -> HudFrame:
    """The plate under the wordmark: one pip per tool, how many can run, what
    needs attention, the platform and the version — in the frame language."""
    pips, counter = _pips(states, progress)
    parts = [pips, counter, attention(states), Text(platform, style="muted"), Text(f"v{__version__}", style="muted")]
    return HudFrame([Pane(join(parts), pad=2)], expand=False)


def banner(states: Sequence[str], platform: str, progress: float = 1.0) -> RenderableType:
    """The startup banner: wordmarks, a gradient rule and the status strip.

    ``states`` is one ``ready`` / ``blocked`` / ``not installed`` per registered
    tool — the same states the inventory table shows — so the strip answers
    "is this thing ready to run" without a separate command.

    ``progress`` (0..1) is a frame of the intro: the wordmark materialises out
    of noise left to right, the rule draws itself, the pips light up. Every
    frame has the final banner's size, so nothing below it jumps. At 1 it is
    the banner.
    """
    return Group(
        _materialise(CS_TOOL_LOGO, phase(progress, 0.0, 0.6)),
        Text(""),
        GradientRule(phase(progress, 0.3, 0.7)),
        _status_strip(states, platform, phase(progress, 0.55, 0.95)),
        Text(""),
        _materialise(UNIV_LOGO, phase(progress, 0.4, 0.95)),
        Text(""),
    )


#: A two-row wordmark font, built from the same half blocks as the big one.
_MINI_FONT: dict[str, tuple[str, str]] = {
    "C": ("█▀▀", "█▄▄"),
    "S": ("█▀▀", "▄▄█"),
    "T": ("▀█▀", " █ "),
    "O": ("█▀█", "█▄█"),
    "L": ("█  ", "█▄▄"),
    "U": ("█ █", "█▄█"),
    "M": ("█▀▄▀█", "█ ▀ █"),
    " ": (" ", " "),
}


def _mini_wordmark(word: str, styles: tuple[str, str], progress: float = 1.0) -> list[Text]:
    """``word`` two rows tall. Below ``progress`` 1 the letters resolve left to
    right out of ``░▒▓``, the way the big wordmark does."""
    rows = [" ".join(_MINI_FONT[char][row] for char in word) for row in (0, 1)]
    width = max(len(row) for row in rows)
    lines = []
    for row_index, (chars, style) in enumerate(zip(rows, styles, strict=True)):
        line = Text()
        for column, char in enumerate(chars):
            settles = 0.8 * column / width
            if progress >= 1 or char == " ":
                line.append(char, style)
            elif progress >= settles:
                line.append(char, "bold bright_white" if progress - settles < 0.08 else style)
            elif progress > 0 and progress >= settles - _FLICKER:
                line.append(NOISE[(column + row_index + int(progress * 60)) % len(NOISE)], "accent")
            else:
                line.append(" ")
        lines.append(line)
    return lines


class Masthead:
    """The banner in three rows, for a terminal too short for the big one and
    for inner screens (``status``): ``CS TOOL │ UTM`` two rows tall, the
    readiness readout beside it, the ramp underneath.

    ``progress`` below 1 plays the big banner's intro in miniature. The
    attention words (``1 blocked``) are shown only when the line has room.
    """

    def __init__(
        self, states: Sequence[str], platform: str, *, subtitle: str | None = None, progress: float = 1.0
    ) -> None:
        self.states = list(states)
        self.platform = platform
        self.subtitle = subtitle
        self.progress = progress

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        progress = self.progress
        cs = _mini_wordmark("CS TOOL", ("bold bright_cyan", "bold green"), phase(progress, 0.0, 0.55))
        utm = _mini_wordmark("UTM", ("bold white", "bold white"), phase(progress, 0.25, 0.7))
        pips, counter = _pips(self.states, phase(progress, 0.45, 0.9))
        issues = attention(self.states)
        width = options.max_width
        # Flow, not one Text: a wrap moves "10/20 ready" down whole.
        top = Flow([pips, counter, issues if width >= 100 else Text()])
        bottom = Flow(
            [
                Text(self.platform, style="muted"),
                Text(f"v{__version__}", style="muted"),
                Text(self.subtitle or "", style="accent"),
            ]
        )
        # The art is never cut: drop UTM, then the wordmark, as the window
        # narrows; the readout comes last and wraps between its parts.
        art = [cs, [Text("│", style="muted")] * 2, utm]
        while True:
            grid = Table.grid(padding=(0, 2))
            for _ in art:
                grid.add_column(no_wrap=True)
            grid.add_column()
            grid.add_row(*(column[0] for column in art), top)
            grid.add_row(*(column[1] for column in art), bottom)
            natural = Measurement.get(console, options.update_width(10_000), grid).maximum
            if not art or natural <= width:
                break
            art = art[:-2]
        yield grid
        yield EdgeRule("▄", progress=phase(progress, 0.2, 0.75))


#: How far ahead of a wordmark cell settling it starts to flicker.
_FLICKER = 0.18
#: How long a cell that just settled stays bright: the decoding edge.
_EDGE = 0.06
_EDGE_STYLE = Style(color="bright_white", bold=True)


@functools.lru_cache(maxsize=4)
def _wordmark_cells(ansi: str) -> tuple[tuple[str, Style, float], ...]:
    """Each character of a wordmark with its style and the moment (0..1) it settles.

    Left to right with a little scatter, so the art resolves like a scan
    rather than a wipe; the scatter is a fixed hash, so every run looks alike.
    """
    text = Text.from_ansi(ansi)
    styles = [Style.null()] * len(text.plain)
    for span in text.spans:
        style = span.style if isinstance(span.style, Style) else Style.parse(span.style)
        for index in range(span.start, min(span.end, len(styles))):
            styles[index] = styles[index] + style
    width = max(cell_len(line) for line in text.plain.splitlines()) or 1
    cells: list[tuple[str, Style, float]] = []
    column = row = 0
    for char, style in zip(text.plain, styles, strict=True):
        if char == "\n":
            cells.append((char, style, 0.0))
            column, row = 0, row + 1
            continue
        scatter = (column * 7919 + row * 104729) % 997 / 997
        cells.append((char, style, (1 - _FLICKER) * (0.75 * column / width + 0.25 * scatter)))
        column += 1
    return tuple(cells)


def _materialise(ansi: str, progress: float) -> Text:
    """A wordmark at ``progress``: settled cells as drawn (the newest ones bright),
    the next ones flickering through shades, the rest still blank."""
    if progress >= 1:
        return Text.from_ansi(ansi)
    frame = Text()
    for index, (char, style, settles) in enumerate(_wordmark_cells(ansi)):
        if char in "\n " or progress <= 0:
            frame.append(char if char == "\n" else " ")
        elif progress >= settles:
            frame.append(char, _EDGE_STYLE if progress - settles < _EDGE else style)
        elif progress >= settles - _FLICKER:
            frame.append(NOISE[(index + int(progress * 60)) % len(NOISE)], "accent")
        else:
            frame.append(" ")
    return frame


#: How a finding's severity reads at a glance. Unlisted values (including
#: nuclei's "unknown") fall through to the neutral style — an unfamiliar
#: severity must not be dressed up as critical.
SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "dim cyan",
    "info": "dim cyan",
}

#: HTTP status classes, by leading digit.
STATUS_STYLES: dict[int, str] = {
    2: "green",
    3: "cyan",
    4: "yellow",
    5: "bold red",
}

#: Neutral style for a record that carries neither signal.
NEUTRAL_STYLE = "white"

#: Per-tool fields worth surfacing as a one-line "detail", in priority order.
#: Checked with ``getattr``: each is absent on the other tools' record types,
#: so one list serves every schema in ``pipeline/schemas.py``.
_DETAIL_FIELDS: tuple[str, ...] = (
    "severity",     # nuclei
    "ports_list",   # rustscan
    "rule_id",      # gitleaks
    "description",  # gitleaks
    "title",        # httpx / gowitness
    "status_code",  # httpx / gowitness
    "status",       # ffuf
    "length",       # ffuf
    "source",       # subfinder
    "protocol",     # naabu
)


def record_style(record: ToolRecord) -> str:
    """Rich style for one finding: severity first, then HTTP status, else neutral.

    Severity outranks the status code because a finding is about the finding,
    not about the page it was found on.
    """
    severity = str(getattr(record, "severity", "") or "").lower()
    if severity in SEVERITY_STYLES:
        return SEVERITY_STYLES[severity]
    status = getattr(record, "status_code", 0) or getattr(record, "status", 0)
    try:
        leading = int(status) // 100
    except (TypeError, ValueError):  # pragma: no cover - defensive
        leading = 0
    return STATUS_STYLES.get(leading, NEUTRAL_STYLE)


def record_detail(record: ToolRecord) -> str:
    """Short human detail for a records table (severity / ports / title / ...)."""
    for key in _DETAIL_FIELDS:
        value = getattr(record, key, None)
        if value:
            return str(value)
    return ""
