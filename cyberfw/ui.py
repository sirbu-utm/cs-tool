"""Rich presentation helpers for the command-line interface.

The startup banner follows the classic OSINT-tool convention (Sherlock,
theHarvester, recon-ng, ...): a big pre-rendered ANSI/block-art wordmark
printed straight to the terminal, no box around it, followed by a short
byline. ``CS_TOOL_LOGO`` and ``UNIV_LOGO`` are exported verbatim from a
terminal capture — the escape codes are restored at import time because the
literal ``ESC`` control byte does not survive a plain-text paste.
"""

from __future__ import annotations

from rich import box
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.text import Text

from cyberfw import __version__

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


def banner(tool_count: int | None = None) -> RenderableType:
    """Return the classic OSINT-tool startup banner: wordmarks + status line."""
    byline = Text.assemble(
        ("  Integrated Cybersecurity Framework", "tool"),
        (f"  ·  v{__version__}", "muted"),
    )

    status = "  workspace ready"
    if tool_count is not None:
        noun = "tool" if tool_count == 1 else "tools"
        status += f"  ·  {tool_count} {noun} registered"

    return Group(
        Text.from_ansi(CS_TOOL_LOGO),
        byline,
        Text(""),
        Text.from_ansi(UNIV_LOGO),
        Text(""),
        Text(status, style="accent"),
    )
