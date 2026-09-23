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

from collections.abc import Sequence

from rich import box
from rich.cells import cell_len
from rich.color import Color, blend_rgb
from rich.color_triplet import ColorTriplet
from rich.console import Console, ConsoleOptions, Group, RenderableType, RenderResult
from rich.measure import Measurement
from rich.panel import Panel
from rich.segment import Segment
from rich.style import Style
from rich.text import Text

from cyberfw import __version__
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


def tool_guide(name: str) -> Panel:
    """Render a compact usage guide for one registered tool."""
    title, description, example = TOOL_GUIDES.get(
        name,
        ("Security utility", "Runs the selected registered security tool.", f"cs-tool run {name} -t example.com"),
    )
    content = Text.assemble(
        (f"{title}\n", "accent"),
        (f"{description}\n\n", "white"),
        ("example  ", "muted"),
        (example, "bold white"),
    )
    return Panel(
        content,
        title=f"[bold]{name}[/bold]",
        border_style="accent",
        box=box.ROUNDED,
        padding=(1, 2),
        expand=False,
    )


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
    """

    def __rich_measure__(self, console: Console, options: ConsoleOptions) -> Measurement:
        width = min(options.max_width, _RULE_MAX_WIDTH)
        return Measurement(width, width)

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        width = max(1, min(options.max_width, _RULE_MAX_WIDTH))
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
        yield Segment.line()


def _bands(colours: Sequence[Color], width: int) -> RenderResult:
    """``width`` rule cells split into near-equal runs, one per colour, in order."""
    for index, colour in enumerate(colours):
        start = width * index // len(colours)
        end = width * (index + 1) // len(colours)
        if end > start:
            yield Segment(RULE_CHAR * (end - start), Style(color=colour))


def gradient_rule() -> GradientRule:
    """The banner's rule, in the framework's green-to-cyan palette."""
    return GradientRule()


def _status_strip(states: Sequence[str], platform: str) -> Panel:
    """The HUD under the wordmark: one pip per tool, then how many can run."""
    pips = Text()
    for state in states:
        pips.append(PIP, style=state_style(state))
    parts = [pips, readiness(states), Text(platform, style="muted"), Text(f"v{__version__}", style="muted")]
    # An unstyled separator: Text.join takes the joiner as the base style of the
    # result, so a styled one would tint every pip and the counter with it.
    line = Text("   ").join(part for part in parts if part.plain)
    return Panel(line, border_style="accent", box=box.SQUARE, padding=(0, 2), expand=False)


def banner(states: Sequence[str], platform: str) -> RenderableType:
    """The startup banner: wordmarks, a gradient rule and the status strip.

    ``states`` is one ``ready`` / ``blocked`` / ``not installed`` per registered
    tool — the same states the inventory table shows — so the strip answers
    "is this thing ready to run" without a separate command.
    """
    return Group(
        Text.from_ansi(CS_TOOL_LOGO),
        Text(""),
        gradient_rule(),
        _status_strip(states, platform),
        Text(""),
        Text.from_ansi(UNIV_LOGO),
        Text(""),
    )


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
