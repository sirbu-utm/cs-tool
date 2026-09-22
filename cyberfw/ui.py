"""Rich presentation helpers for the command-line interface.

The startup banner follows the classic OSINT-tool convention (Sherlock,
theHarvester, recon-ng, ...): a big pre-rendered ANSI/block-art wordmark
printed straight to the terminal, no box around it, followed by a short
byline. ``CS_TOOL_LOGO`` and ``UNIV_LOGO`` are exported verbatim from a
terminal capture — the escape codes are restored at import time because the
literal ``ESC`` control byte does not survive a plain-text paste.
"""

from __future__ import annotations

from collections.abc import Sequence

from rich import box
from rich.color import Color
from rich.console import Console, ConsoleOptions, Group, RenderableType, RenderResult
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


#: One square per registered tool in the banner's status strip.
PIP = "▰"

#: The character the gradient rule is drawn with.
RULE_CHAR = "━"

#: Ends of the rule's gradient, and the widest it is ever drawn (the wordmark's width).
_RULE_FROM = (0x2E, 0xD5, 0x73)  # green
_RULE_TO = (0x2E, 0xC5, 0xD5)  # cyan
_RULE_MAX_WIDTH = 78

#: A pip's colour answers "can this tool run"; anything unrecognised reads as
#: unavailable rather than being dressed up as ready.
_PIP_STYLES = {"ready": "ok", "blocked": "err"}
_PIP_UNAVAILABLE = "muted"


def pip_style(state: str) -> str:
    """Theme style for one tool state (``ready`` / ``blocked`` / anything else)."""
    return _PIP_STYLES.get(state, _PIP_UNAVAILABLE)


class GradientRule:
    """A horizontal rule whose colour slides from one end to the other.

    Written as a renderable rather than a pre-coloured string so it follows the
    terminal's width, and so a console without colour still gets the line.
    """

    def __init__(self, start: tuple[int, int, int], end: tuple[int, int, int]) -> None:
        self.start = start
        self.end = end

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        width = max(1, min(options.max_width, _RULE_MAX_WIDTH))
        last = max(width - 1, 1)
        for index in range(width):
            ratio = index / last
            colour = Color.from_rgb(
                *(begin + (finish - begin) * ratio for begin, finish in zip(self.start, self.end, strict=True))
            )
            yield Segment(RULE_CHAR, Style(color=colour))
        yield Segment("\n")


def gradient_rule() -> GradientRule:
    """The banner's rule, in the framework's green-to-cyan palette."""
    return GradientRule(_RULE_FROM, _RULE_TO)


def _status_strip(states: Sequence[str] | None, platform: str | None) -> Panel:
    """The HUD under the wordmark: one pip per tool, then how many can run."""
    parts: list[Text] = []
    if states:
        pips = Text()
        for state in states:
            pips.append(PIP, style=pip_style(state))
        ready = sum(1 for state in states if state == "ready")
        overall = "ok" if ready == len(states) else ("warn" if ready else "err")
        parts += [pips, Text(f"{ready}/{len(states)} ready", style=overall)]
    if platform:
        parts.append(Text(platform, style="muted"))
    parts.append(Text(f"v{__version__}", style="muted"))

    line = Text("   ", style="muted").join(parts)
    return Panel(line, border_style="accent", box=box.ROUNDED, padding=(0, 2), expand=False)


def banner(states: Sequence[str] | None = None, platform: str | None = None) -> RenderableType:
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
