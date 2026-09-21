"""Dependency-management subsystem (ToolManager): install and verify tools.

Public surface is the :class:`ToolManager`, which ties together the GitHub
client, OS/Arch mapping and installer to fetch precompiled binaries from
GitHub Releases with zero user friction.
"""

from __future__ import annotations

import json
from pathlib import Path

from cyberfw.config import Settings
from cyberfw.exceptions import CyberfwError
from cyberfw.manager.github_client import GitHubClient
from cyberfw.manager.installer import InstallResult, ToolInstaller
from cyberfw.manager.platform_map import Mapping, asset_patterns, get_target
from cyberfw.manager.registry import ToolRegistry, ToolSpec, load_registry
from cyberfw.manager.verify import ensure_binary

__all__ = [
    "ToolManager",
    "InstallResult",
    "ToolInstaller",
    "GitHubClient",
    "ToolRegistry",
    "ToolSpec",
    "Mapping",
    "load_registry",
    "ensure_binary",
    "get_target",
    "asset_patterns",
]


class ToolManager:
    """Facade over install/verify for the CLI and pipeline engine."""

    def __init__(
        self, settings: Settings, registry: ToolRegistry, mapping: Mapping | None = None
    ) -> None:
        self.settings = settings
        self.registry = registry
        self.mapping = mapping or get_target()
        self._client: GitHubClient | None = None

    @property
    def client(self) -> GitHubClient:
        if self._client is None:
            self._client = GitHubClient(
                token=self.settings.github_token,
                cache_dir=self.settings.cache_dir if self.settings.github_rate_fallback else None,
                timeout=self.settings.request_timeout,
            )
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def spec(self, name: str) -> ToolSpec:
        return self.registry.require(name)

    def binary_path(self, name: str) -> Path:
        """Return the installed binary path for ``name`` or raise ``ToolNotFoundError``."""
        return ensure_binary(self.settings.tools_dir, name, self.spec(name).binary)

    def install_state(self, name: str) -> dict[str, str] | None:
        """Return the recorded install metadata (binary/version/os/arch) or ``None``."""
        state_path = self.settings.tools_dir / f".{name}.install.json"
        if not state_path.is_file():
            return None
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return state if isinstance(state, dict) else None

    def is_installed(self, name: str) -> bool:
        """Return true only for a binary recorded after a successful install."""
        state = self.install_state(name)
        if state is None:
            return False
        try:
            binary = self.binary_path(name)
        except (CyberfwError, OSError, ValueError, TypeError):
            return False
        return (
            state.get("binary") == str(binary.resolve())
            and state.get("os") == self.mapping.os_name
            and state.get("arch") == self.mapping.arch
        )

    def install(self, name: str, *, force: bool = False) -> InstallResult:
        """Install one tool; returns where its binary lives.

        Nothing is downloaded when the wanted version is already installed and
        runnable: a pinned ``version`` is compared against the install record
        without touching the network, ``latest`` after one (cached) API call.
        ``force`` re-downloads regardless.
        """
        spec = self.registry.require(name)
        installer = ToolInstaller(
            self.client,
            self.settings.tools_dir,
            self.mapping,
            max_archive_size=self.settings.max_archive_size,
        )
        state = self.install_state(name) if not force else None
        installed = state.get("version") if state is not None and self.is_installed(name) else None
        release = None
        if installed is not None:
            wanted = spec.pinned_version
            if wanted is None:
                release = installer.resolve_release(spec)
                wanted = release.version
            if installed == wanted:
                return InstallResult(spec, self.binary_path(name), installed, up_to_date=True)

        state_path = self.settings.tools_dir / f".{name}.install.json"
        state_path.unlink(missing_ok=True)
        result = installer.install(spec, release)
        state_path.write_text(
            json.dumps(
                {
                    "binary": str(result.binary.resolve()),
                    "version": result.version,
                    "os": self.mapping.os_name,
                    "arch": self.mapping.arch,
                }
            ),
            encoding="utf-8",
        )
        return result

    def install_all(self) -> list[InstallResult]:
        """Install every registered tool in name order."""
        return [self.install(name) for name in self.registry.names()]
