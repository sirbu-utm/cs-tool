"""Tool registry loader.

``registry.yaml`` is the single declarative source of truth describing every
tool the framework can orchestrate: its GitHub repository, which archived asset
to fetch (with fnmatch-style name patterns and archive type), the name/path of
the inner binary, and a command template. Adding a new tool should require only
an entry here (plus, when its JSONL schema is novel, a parser in ``tools/``).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, model_validator

from cyberfw.exceptions import RegistryError
from cyberfw.logging import get_logger

__all__ = ["ToolSpec", "ToolRegistry", "load_registry"]

LOG = get_logger("manager.registry")

#: 1.x integrity keys that ``tools.lock`` replaced: still accepted, but ignored.
_LEGACY_KEYS = ("sha256", "needs_checksum")


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


def load_registry(path: Path | str) -> ToolRegistry:
    """Parse a registry file into a :class:`ToolRegistry`."""
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
            LOG.warning(
                "registry entry %s: %s no longer used — integrity now comes from tools.lock "
                "(run `cyberfw lock`)",
                name,
                " and ".join(f"`{key}`" for key in legacy),
            )
            block = {key: value for key, value in block.items() if key not in _LEGACY_KEYS}
        try:
            tools[name] = ToolSpec(**block, name=str(name))
        except Exception as exc:  # pydantic.ValidationError → RegistryError
            raise RegistryError(f"invalid registry entry {name!r}: {exc}") from exc
    return ToolRegistry(tools)
