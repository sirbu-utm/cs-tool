"""Tool registry loader.

``registry.yaml`` is the single declarative source of truth describing every
tool the framework can orchestrate: its GitHub repository, which archived asset
to fetch (with fnmatch-style name patterns and archive type), the name/path of
the inner binary, and a command template. Adding a new tool should require only
an entry here (plus, when its JSONL schema is novel, a parser in ``tools/``).
"""

from __future__ import annotations

from collections.abc import Collection, Iterator, Mapping
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, model_validator

from cyberfw.exceptions import RegistryError
from cyberfw.logging import get_logger

__all__ = ["ToolSpec", "ToolRegistry", "load_registry"]

LOG = get_logger("manager.registry")

#: 1.x integrity keys that ``tools.lock`` replaced: still accepted, but ignored.
_LEGACY_KEYS = ("sha256", "needs_checksum")
#: The keys an entry may hold when it only adjusts a plugin's recipe — never a recipe of its own.
_OVERLAY_KEYS = frozenset({"version", "env", "interactive_input", "check_deps"})
#: (registry file, tool) pairs already warned about — the launcher reloads the
#: registry for every frame, and one warning per tool per process is enough.
_LEGACY_WARNED: set[tuple[str, str]] = set()


class ToolSpec(BaseModel):
    """Declarative metadata for one external tool."""

    name: str = ""  # injected from the YAML key
    #: ``github`` (downloaded from GitHub Releases) or ``local`` (already on the
    #: machine — found on PATH or at ``path`` — never downloaded).
    source: str = "github"
    repo: str = ""  # required for a github tool; unused for a local one
    asset_patterns: list[str] = Field(default_factory=list)
    archive: str = "auto"  # auto | zip | tar | raw
    binary: str | None = None  # file to chmod +x inside the archive, else guessed
    #: An explicit binary path for a ``local`` tool; without it the binary is
    #: found on PATH by ``binary`` (or the tool name).
    path: str | None = None
    #: Release tag (``v2.6.6``) or ``latest``: the constraint ``cyberfw lock``
    #: resolves within. The release that actually installs — and its SHA-256 on
    #: every platform — is recorded in ``tools.lock``.
    version: str = "latest"
    check_deps: list[str] = Field(default_factory=list)  # e.g. ["nmap"]
    interactive_input: dict[str, str] = Field(
        default_factory=dict,
        description="Static CLI flags injected by the tool adapter (e.g. JSON output).",
    )
    env: list[str] = Field(
        default_factory=list,
        description="Environment variables the tool's process is given beyond the fixed set any "
        "program needs (e.g. an API key of its own); cyberfw's own secrets are never passed otherwise.",
    )

    @model_validator(mode="after")
    def _check_source(self) -> ToolSpec:
        if self.source not in ("github", "local"):
            raise ValueError(f"source must be 'github' or 'local', got {self.source!r}")
        if self.source == "github" and not self.repo:
            raise ValueError("repo is required for a github tool (owner/name)")
        return self

    @property
    def is_local(self) -> bool:
        """True for a tool the framework does not download (found on PATH / ``path``)."""
        return self.source == "local"

    @property
    def pinned_version(self) -> str | None:
        """``2.6.6`` for ``version: v2.6.6``; ``None`` when tracking ``latest``."""
        return None if self.version == "latest" else self.version.lstrip("vV")

    @property
    def repo_owner(self) -> str:
        return self.repo.split("/", 1)[0]

    @property
    def repo_name(self) -> str:
        return self.repo.split("/", 1)[1]


class ToolRegistry:
    """Typed accessor over a parsed ``registry.yaml``."""

    def __init__(self, tools: dict[str, ToolSpec]) -> None:
        self._tools = tools

    def __iter__(self) -> Iterator[str]:
        return iter(self._tools)

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def require(self, name: str) -> ToolSpec:
        tool = self._tools.get(name)
        if tool is None:
            raise RegistryError(f"Unknown tool: {name!r}. Known tools: {', '.join(sorted(self._tools))}")
        return tool

    def names(self) -> list[str]:
        return sorted(self._tools)


#: Overlay-only entries already warned about, per registry file.
_OVERLAYS_WARNED: set[tuple[str, str]] = set()


def _warn_overlay_only(registry_path: Path, name: str) -> None:
    key = (str(registry_path.resolve()), name)
    if key not in _OVERLAYS_WARNED:
        _OVERLAYS_WARNED.add(key)
        LOG.warning(
            "registry entry %s has no repo or source: it only overlays a plugin's recipe, "
            "and no installed plugin declares %s — left out",
            name,
            name,
        )


def load_registry(
    path: Path | str, *, overlays: Mapping[str, ToolSpec] | None = None, plugin_tools: Collection[str] = ()
) -> ToolRegistry:
    """Parse a registry file into a :class:`ToolRegistry`.

    ``overlays`` are the install recipes of the plugin tools in use, by name: an
    entry of the same name in the file is laid over its recipe key by key (to pin
    a version, or point at a local binary), and a plugin tool the file does not
    name keeps its recipe as it is. An entry that only overlays — nothing but
    ``version``, ``env``, ``interactive_input`` or ``check_deps``: a version pin,
    say — is no recipe without its plugin, so it is left out when no plugin in use
    provides the tool: quietly for a tool of an installed plugin (``plugin_tools``)
    that is merely not in use, with a warning otherwise. An entry with recipe keys
    is checked as a recipe, as before: a mistake in one stays an error.
    """
    overlays = overlays or {}
    registry_path = Path(path)
    if not registry_path.exists():
        raise RegistryError(f"registry file not found: {registry_path}")

    try:
        payload = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RegistryError(f"malformed registry {registry_path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise RegistryError(f"registry {registry_path} must be a mapping of tool entries")

    tools: dict[str, ToolSpec] = {}
    for name, block in payload.items():
        if not isinstance(block, dict):
            raise RegistryError(f"registry entry {name!r} must be a mapping")
        legacy = [key for key in _LEGACY_KEYS if key in block]
        if legacy:
            warned = (str(registry_path.resolve()), str(name))
            if warned not in _LEGACY_WARNED:
                _LEGACY_WARNED.add(warned)
                LOG.warning(
                    "registry entry %s: %s no longer used — integrity now comes from tools.lock "
                    "(run `cyberfw lock`)",
                    name,
                    " and ".join(f"`{key}`" for key in legacy),
                )
            block = {key: value for key, value in block.items() if key not in _LEGACY_KEYS}
        base = overlays.get(str(name))
        if base is None and block and set(block) <= _OVERLAY_KEYS:
            if str(name) not in plugin_tools:
                _warn_overlay_only(registry_path, str(name))
            continue
        fields = {**base.model_dump(), **block} if base is not None else dict(block)
        try:
            tools[name] = ToolSpec(**{**fields, "name": str(name)})
        except Exception as exc:  # pydantic.ValidationError → RegistryError
            raise RegistryError(f"invalid registry entry {name!r}: {exc}") from exc
    for name, spec in overlays.items():
        tools.setdefault(name, spec)
    return ToolRegistry(tools)
