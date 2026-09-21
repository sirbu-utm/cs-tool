"""Gowitness adapter — headless-browser screenshots of web pages.

Screenshots ``ctx.target`` URLs one by one (``per_target``). Targets gowitness
v3, whose command is ``scan single -u <url>`` (v2's bare ``single`` no longer
exists); ``--write-stdout`` streams one JSON result line per URL so the pipeline
can validate it, while images still land in ``--screenshot-path``.

gowitness drives a headless Chrome/Chromium. Chrome is not a portable binary,
so — following the same graceful-degradation rule as RustScan's optional Nmap —
the adapter checks for it up front and raises a clear, actionable error when it
is absent, instead of letting gowitness fail with a cryptic exit code and a
wall of usage text.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from cyberfw.exceptions import ToolNotFoundError
from cyberfw.tools.base import BaseTool, ToolContext

#: Executable names gowitness / chromedp look for on PATH.
_CHROME_NAMES = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome")

#: Common install locations that are not usually on PATH (Windows/macOS).
_CHROME_PATHS = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Chromium\Application\chrome.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
)


def _find_chrome() -> str | None:
    """Return a Chrome/Chromium executable path, or ``None`` if none is found."""
    for name in _CHROME_NAMES:
        found = shutil.which(name)
        if found:
            return found
    local = os.environ.get("LOCALAPPDATA")
    extra = [Path(local) / r"Google\Chrome\Application\chrome.exe"] if local else []
    for candidate in [Path(p) for p in _CHROME_PATHS] + extra:
        if candidate.is_file():
            return str(candidate)
    return None


class GowitnessTool(BaseTool):
    per_target = True

    def build_cmd(self, ctx: ToolContext) -> list[str]:
        targets = ctx.inputs if ctx.inputs else ([ctx.target] if ctx.target else [])
        if not targets:
            raise ToolNotFoundError("Gowitness needs at least one target URL.")
        chrome = _find_chrome()
        if chrome is None:
            raise ToolNotFoundError(
                "Gowitness needs a headless Chrome/Chromium, which was not found. "
                "Install Google Chrome (winget install Google.Chrome / brew install --cask "
                "google-chrome / apt install chromium) and run again."
            )
        base = targets[0]
        if not base.startswith(("http://", "https://")):
            base = f"https://{base}"
        return [
            str(self.binary),
            "scan",
            "single",
            "-u",
            base,
            "--chrome-path",
            chrome,
            "--screenshot-path",
            "screenshots",
            "--write-stdout",
            "-q",
            *self._static_flags(),
        ]

    @property
    def input_flag(self) -> str | None:
        return None
