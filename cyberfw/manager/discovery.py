"""Plugin packages, as their metadata describes them — nothing of theirs is imported.

A plugin package declares each of its tools as an entry point: in
``cyberfw.manifests`` for a tool its manifest describes, in ``cyberfw.tools``
for one whose adapter is Python. :func:`discover` reads those from the
installed distributions' metadata alone, with each package's name, version and
kind — ``manifest`` only when the files its installation recorded hold no
Python and it declares no code tool, so a package cannot claim to be data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib.metadata import Distribution, entry_points
from typing import Literal

__all__ = ["CODE_GROUP", "MANIFEST_GROUP", "Declared", "Kind", "discover", "normalize", "package_kind"]

#: Tools whose adapter is Python: each entry point names a ``ToolPlugin``.
CODE_GROUP = "cyberfw.tools"
#: Tools a manifest describes: each entry point names the package that holds it.
MANIFEST_GROUP = "cyberfw.manifests"
#: Files that are Python or run it — a package that installed any is a code package.
_CODE_FILES = (".py", ".pyc", ".pth", ".so", ".pyd")

Kind = Literal["manifest", "code"]


def normalize(name: str) -> str:
    """A package name as PEP 503 compares it: case-insensitive, ``-``, ``_`` and ``.`` alike."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class Declared:
    """One tool an installed package declares."""

    tool: str
    #: The package's name, normalised.
    package: str
    version: str
    #: :data:`MANIFEST_GROUP` or :data:`CODE_GROUP`.
    group: str
    #: What the entry point names: the manifest's package, or the ``module:attribute`` of a ``ToolPlugin``.
    value: str
    #: The package's kind, verified from its files.
    kind: Kind


def package_kind(dist: Distribution) -> Kind:
    """``manifest`` when the files ``dist`` installed hold no Python and it declares
    no code tool; ``code`` otherwise — and when its files cannot be listed."""
    files = dist.files
    if files is None:
        return "code"
    if any(str(file).lower().endswith(_CODE_FILES) for file in files):
        return "code"
    return "code" if dist.entry_points.select(group=CODE_GROUP) else "manifest"


def discover() -> list[Declared]:
    """Every tool the installed packages declare, by package, then tool."""
    found: list[Declared] = []
    kinds: dict[str, Kind] = {}
    for group in (MANIFEST_GROUP, CODE_GROUP):
        for point in entry_points(group=group):
            dist = point.dist
            if dist is None:
                continue
            package = normalize(dist.name)
            if package not in kinds:
                kinds[package] = package_kind(dist)
            found.append(
                Declared(
                    tool=point.name, package=package, version=dist.version, group=group, value=point.value,
                    kind=kinds[package],
                )
            )
    return sorted(found, key=lambda declared: (declared.package, declared.tool, declared.group))
