"""Tool registry loader.

``registry.yaml`` is the single declarative source of truth describing every
tool the framework can orchestrate: its GitHub repository, which archived asset
to fetch (with fnmatch-style name patterns and archive type), the name/path of
the inner binary, and a command template. Adding a new tool should require only
an entry here (plus, when its JSONL schema is novel, a parser in ``tools/``).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from cyberfw.exceptions import RegistryError

__all__ = ["ToolSpec", "ToolRegistry", "load_registry"]


class ToolSpec(BaseModel):
    """Declarative metadata for one external tool."""

    name: str = ""  # injected from the YAML key
    repo: str
    asset_patterns: list[str]
    archive: str = "auto"  # auto | zip | tar | raw
    binary: str | None = None  # file to chmod +x inside the archive, else guessed
    #: Release tag to install (``v2.6.6``) or ``latest``. Pin it for reproducible
    #: installs: a tool that changes its output format under you is otherwise
    #: only noticed as "N lines did not match the schema".
    version: str = "latest"
    needs_checksum: bool = True
    #: ``asset name -> SHA-256`` for releases whose upstream publishes no
    #: checksums file (only meaningful together with a pinned ``version``).
    sha256: dict[str, str] = Field(default_factory=dict)
    check_deps: list[str] = Field(default_factory=list)  # e.g. ["nmap"]
    interactive_input: dict[str, str] = Field(
        default_factory=dict,
        description="Static CLI flags injected by the tool adapter (e.g. JSON output).",
    )

    @field_validator("sha256")
    @classmethod
    def _hex_digests(cls, value: dict[str, str]) -> dict[str, str]:
        for asset, digest in value.items():
            if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
                raise ValueError(f"sha256 for {asset!r} must be 64 hex characters")
        return {asset: digest.lower() for asset, digest in value.items()}

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
        try:
            tools[name] = ToolSpec(**block, name=str(name))
        except Exception as exc:  # pydantic.ValidationError → RegistryError
            raise RegistryError(f"invalid registry entry {name!r}: {exc}") from exc
    return ToolRegistry(tools)
