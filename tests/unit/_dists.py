"""Plugin packages for tests: real distributions, not mocks.

:func:`install` writes a package's files and a ``*.dist-info`` — its metadata,
its entry points and the ``RECORD`` of what it installed — into the directory
the ``site`` fixture (``tests/conftest.py``) puts on ``sys.path``, where
``importlib.metadata`` finds it like any installed package.
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from pathlib import Path

from cyberfw.manager.discovery import CODE_GROUP, MANIFEST_GROUP


def install(
    site: Path,
    name: str,
    *,
    version: str = "1.0",
    manifests: Mapping[str, str] | None = None,
    tools: Mapping[str, str] | None = None,
    files: Mapping[str, str] | None = None,
    record: bool = True,
) -> None:
    """Install the package ``name`` into ``site``: ``files`` (path → text), and a
    dist-info declaring ``manifests`` and ``tools`` (tool → entry point value).
    Without ``record`` its files cannot be listed, as with some installers."""
    files = dict(files or {})
    for relative, text in files.items():
        path = site / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    info = site / f"{name.replace('-', '_')}-{version}.dist-info"
    info.mkdir()
    (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8")
    points = ""
    for group, entries in ((MANIFEST_GROUP, manifests), (CODE_GROUP, tools)):
        if entries:
            points += f"[{group}]\n" + "".join(f"{tool} = {value}\n" for tool, value in entries.items()) + "\n"
    (info / "entry_points.txt").write_text(points, encoding="utf-8")
    if record:
        listed = [*files, f"{info.name}/METADATA", f"{info.name}/entry_points.txt", f"{info.name}/RECORD"]
        (info / "RECORD").write_text("".join(f"{path},,\n" for path in listed), encoding="utf-8")
    importlib.invalidate_caches()
