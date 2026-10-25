"""Where cyberfw finds its registry and lock, and whether each registered tool can run."""

from __future__ import annotations

from pathlib import Path

from cyberfw.config import Settings
from cyberfw.exceptions import CyberfwError, RegistryError
from cyberfw.manager import ToolManager, load_registry
from cyberfw.manager.lock import LOCK_NAME
from cyberfw.resources import packaged_data


def registry_candidates() -> list[Path]:
    """Where ``registry.yaml`` may live, most specific first.

    The current directory (a workspace the user may have edited), then the
    checkout root next to the package (running from a clone elsewhere), then
    the copy the wheel ships as ``cyberfw/data/registry.yaml``.
    """
    candidates = [Path.cwd() / "registry.yaml", Path(__file__).resolve().parents[2] / "registry.yaml"]
    packaged = packaged_data("registry.yaml")
    if packaged is not None:
        candidates.append(packaged)
    return candidates


def registry_path() -> Path:
    """Locate ``registry.yaml`` or raise a :class:`RegistryError` naming the places tried."""
    candidates = registry_candidates()
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    tried = ", ".join(str(path) for path in candidates)
    raise RegistryError(f"registry.yaml not found (tried: {tried}). Run cyberfw from the project root.")


def open_manager(settings: Settings) -> ToolManager:
    """A :class:`ToolManager` over the registry in use, with ``tools.lock`` next to it."""
    path = registry_path()
    return ToolManager(settings, load_registry(path), lock_path=path.with_name(LOCK_NAME))


def is_packaged(path: Path) -> bool:
    """True for a file next to the wheel's packaged registry: an installed copy
    in site-packages, with no repository to commit it to."""
    packaged = packaged_data("registry.yaml")
    return packaged is not None and path.resolve().parent == packaged.resolve().parent


def tool_state(manager: ToolManager, name: str, tools_dir: Path) -> str:
    """``ready`` / ``blocked`` / ``not installed`` for one registered tool.

    Readiness is "can this run", so a binary that resolves is ready even
    without an install record (the record only carries the version, shown in
    its own column). ``blocked`` is the narrow case the user must act on: the
    file is on disk but cannot be read or executed — typically an antivirus
    quarantine.
    """
    # binary_path and binary_on_disk both rglob tools_dir; a directory that
    # lists but cannot be entered raises PermissionError (OSError) there on
    # Python 3.10-3.13 (3.14 swallows it). Treat an unreadable tree as "not on
    # disk" rather than letting a traceback replace the banner. OSError around
    # binary_path is the same net is_installed already casts.
    try:
        manager.binary_path(name)
    except (CyberfwError, OSError):
        try:
            on_disk = binary_on_disk(tools_dir, name, manager.spec(name).binary)
        except OSError:
            on_disk = False
        return "blocked" if on_disk else "not installed"
    return "ready"


def binary_on_disk(tools_dir: Path, name: str, binary_hint: str | None) -> bool:
    """True if a binary file for ``name`` exists at all (runnable or not).

    Lets status tell a Defender-blocked/unreadable download (present but broken)
    apart from one that was never fetched.
    """
    search = binary_hint or name
    for candidate in (tools_dir / search, tools_dir / f"{search}.exe"):
        if candidate.is_file():
            return True
    if tools_dir.is_dir():
        for candidate in tools_dir.rglob("*"):
            if candidate.is_file() and (candidate.name == search or candidate.stem == search):
                return True
    return False
