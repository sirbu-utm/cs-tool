"""Dependency-management subsystem (ToolManager): install and verify tools.

Public surface is the :class:`ToolManager`, which ties together the GitHub
client, OS/Arch mapping and installer to fetch precompiled binaries from
GitHub Releases with zero user friction.
"""

from __future__ import annotations

import json
from pathlib import Path

from cyberfw.config import Settings
from cyberfw.exceptions import CyberfwError, ToolNotFoundError
from cyberfw.manager.chromium import ChromiumInstallResult
from cyberfw.manager.github_client import GitHubClient
from cyberfw.manager.installer import InstallResult, ToolInstaller
from cyberfw.manager.platform_map import Mapping, asset_patterns, get_target
from cyberfw.manager.registry import ToolRegistry, ToolSpec, load_registry
from cyberfw.manager.verify import ensure_binary, find_in_path

__all__ = [
    "ToolManager",
    "InstallResult",
    "ChromiumInstallResult",
    "ToolInstaller",
    "GitHubClient",
    "ToolRegistry",
    "ToolSpec",
    "Mapping",
    "load_registry",
    "ensure_binary",
    "find_in_path",
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
        """Return the binary path for ``name`` or raise ``ToolNotFoundError``.

        A ``source: local`` tool is resolved from its configured ``path`` or
        from PATH (it is never downloaded); a github tool from ``tools_dir``."""
        spec = self.spec(name)
        if spec.is_local:
            if spec.path:
                candidate = Path(spec.path)
                if candidate.is_file():
                    return candidate
                raise ToolNotFoundError(f"{name}: configured path does not exist: {spec.path}")
            found = find_in_path(spec.binary or name)
            if found:
                return Path(found)
            raise ToolNotFoundError(
                f"{name} is a local tool and is not on PATH — install it with your package manager (apt/brew/winget)"
            )
        return ensure_binary(self.settings.tools_dir, name, spec.binary)

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
        """Return true when the tool is available to run.

        A ``source: local`` tool counts as installed when its binary resolves
        (there is no install record for something we did not download); a github
        tool only after a successful install matching this OS/arch."""
        if self.spec(name).is_local:
            try:
                self.binary_path(name)
            except (CyberfwError, OSError):
                return False
            return True
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
        if spec.is_local:
            raise CyberfwError(
                f"{name} is a local tool — install it with your package manager (apt/brew/winget), not via cyberfw"
            )
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
        """Install every downloadable (github) tool in name order; local tools
        are the user's to install and are skipped."""
        return [self.install(name) for name in self.registry.names() if not self.spec(name).is_local]

    def install_chromium(self, *, force: bool = False) -> ChromiumInstallResult:
        """Download the portable Chromium gowitness needs into ``tools_bin/``.

        Reuses the same HTTP client as tool installs. Skips the download when the
        recorded version is already on disk unless ``force``. Raises
        :class:`ChromiumUnsupportedError` on a platform Chrome for Testing does
        not build for.
        """
        from cyberfw.manager.chromium import ChromiumInstaller

        installer = ChromiumInstaller(self.client, self.settings.tools_dir, self.mapping)
        return installer.install(force=force)
