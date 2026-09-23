"""OS/Architecture → GitHub asset naming.

ProjectDiscovery-style tools publish archives named
``<tool>_<version>_<os>_<arch>(-suffix).zip``. This module normalises
:func:`platform.system()` / :func:`platform.machine()` into the tokens those
archives use, and returns a list of ``fnmatch``-style patterns for the asset
pool so we accept every published spelling (e.g. ``*linux*amd64*``).

The table mirrors the one in the technical specification.
"""

from __future__ import annotations

import platform
from dataclasses import dataclass

__all__ = ["Mapping", "get_target", "asset_patterns"]


@dataclass(frozen=True)
class Mapping:
    """Normalised OS + arch pair.

    .. attribute:: os_name
       ``linux`` / ``darwin`` / ``windows``

    .. attribute:: arch
       ``amd64`` / ``arm64`` — represented as the umbrella ``arch64`` where the
       registry defines arm-only assets (e.g. RustScan).
    """

    os_name: str
    arch: str

    @property
    def label(self) -> str:
        """``windows/amd64`` — how the platform is named on screen and in reports."""
        return f"{self.os_name}/{self.arch}"

    @property
    def arch_umbrella(self) -> str:
        """Return ``arm64`` if this is any 64-bit ARM, else the raw arch."""
        return "arm64" if self.arch == "arm64" else self.arch


def get_target() -> Mapping:
    """Return the normalised mapping for the current interpreter/OS."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if "darwin" in system or system == "macos":
        os_name = "darwin"
    elif "windows" in system or "mingw" in system or "msys" in system:
        os_name = "windows"
    elif "linux" in system:
        os_name = "linux"
    else:  # pragma: no cover - unusual host
        os_name = system

    if "aarch64" in machine or "arm64" in machine:
        arch = "arm64"
    elif machine in ("x86_64", "amd64", "x64"):
        arch = "amd64"
    elif machine == "armv7l":  # pragma: no cover - rare lower-end hosts
        arch = "armv7"
    elif "386" in machine or machine in ("i386", "i686"):
        arch = "386"
    else:  # pragma: no cover - exotic architecture
        arch = machine

    return Mapping(os_name=os_name, arch=arch)


def asset_patterns(mapping: Mapping) -> list[str]:
    """Return every fnmatch pattern a released asset may match for ``mapping``.

    Patterns are ordered coarse → specific; the installer tries them in order.
    """
    os_name, arch = mapping.os_name, mapping.arch
    if os_name == "darwin":
        os_tokens = [os_name, "macos"]
    else:
        os_tokens = [os_name]
    if arch == "amd64":
        arch_tokens = ["amd64", "x86_64"]
    elif arch == "arm64":
        arch_tokens = ["arm64", "aarch64", "arm64v8"]
    else:
        arch_tokens = [arch]

    patterns: list[str] = []
    for ot in os_tokens:
        for at in arch_tokens:
            patterns.append(f"*{ot}*{at}*")
            if ot in ("darwin", "macos", "windows"):
                patterns.append(f"*{at}*{ot}*")  # arch-os hosting
    if os_name == "windows":
        patterns.append("*windows*")
    return patterns
