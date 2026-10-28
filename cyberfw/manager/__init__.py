"""Dependency-management subsystem (ToolManager): install and verify tools.

Public surface is the :class:`ToolManager`, which ties together the GitHub
client, OS/Arch mapping, installer and ``tools.lock`` to fetch precompiled
binaries from GitHub Releases — exactly the releases the lock pins, each archive
verified against its locked SHA-256.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from cyberfw.config import Settings
from cyberfw.exceptions import (
    CyberfwError,
    DownloadError,
    LockError,
    RegistryError,
    ToolNotFoundError,
)
from cyberfw.manager.chromium import ChromiumInstallResult
from cyberfw.manager.github_client import GitHubClient
from cyberfw.manager.installer import InstallResult, ToolInstaller
from cyberfw.manager.lock import (
    LOCK_NAME,
    ChangeKind,
    LockChange,
    LockedTool,
    LockUpdate,
    ToolLock,
    read_lock,
    replaced_files,
    reselected_platforms,
    resolve_tool,
    stale_reason,
    write_lock,
)
from cyberfw.manager.platform_map import Mapping, asset_patterns, get_target
from cyberfw.manager.registry import ToolRegistry, ToolSpec, load_registry
from cyberfw.manager.verify import ensure_binary, find_in_path

if TYPE_CHECKING:  # cyberfw.plugin and the tools import this package's registry module
    from cyberfw.manager.plugins import PluginSet
    from cyberfw.plugin import BaseTool, ToolPlugin

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
        self,
        settings: Settings,
        registry: ToolRegistry,
        mapping: Mapping | None = None,
        *,
        lock_path: Path | None = None,
        plugins: PluginSet | None = None,
    ) -> None:
        self.settings = settings
        self.registry = registry
        #: The plugin tools in use and every declared one's state; ``None`` without plugins.
        self.plugins = plugins
        self.mapping = mapping or get_target()
        #: The ``tools.lock`` installs come from: next to the registry in use (the
        #: CLI passes that); ``<root_dir>/tools.lock`` when not given.
        self.lock_path = lock_path if lock_path is not None else settings.root_dir / LOCK_NAME
        #: Tools this manager added to the lock while installing, in order — so
        #: ``init`` and the launcher can say what they pinned.
        self.added_to_lock: list[str] = []
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
        if name not in self.registry:
            reason = self.unavailable(name)
            if reason is not None:
                raise RegistryError(reason)
        return self.registry.require(name)

    # -- the tools in use ---------------------------------------------------------
    @property
    def tools(self) -> dict[str, ToolPlugin]:
        """Every usable tool's description, by name: the built-in ones and the plugins' in use."""
        from cyberfw.tools import BUILTIN  # the tools import this package's registry module

        return {**BUILTIN, **(self.plugins.tools if self.plugins is not None else {})}

    def unavailable(self, name: str) -> str | None:
        """Why a plugin tool cannot be used, as a sentence; ``None`` for any other name."""
        return self.plugins.unavailable(name) if self.plugins is not None else None

    def adapter_class(self, name: str) -> type[BaseTool]:
        """``name``'s adapter class — for what it knows before a binary exists (prompts,
        target validation). :class:`RegistryError` when no usable tool has the name."""
        tool = self.tools.get(name)
        if tool is None:
            raise RegistryError(self.unavailable(name) or f"no adapter registered for tool {name!r}")
        return tool.adapter

    def adapter_for(self, name: str, binary: Path) -> BaseTool:
        """``name``'s adapter on its recipe and installed ``binary``, reading its lines
        with the record model its description names."""
        adapter = self.adapter_class(name)(self.spec(name), binary)
        adapter._record = self.tools[name].record
        return adapter

    # -- tools.lock -----------------------------------------------------------
    def load_lock(self) -> ToolLock:
        """The lock on disk, or an empty one when there is no file yet."""
        return read_lock(self.lock_path) or ToolLock()

    def _resolve(self, spec: ToolSpec) -> LockedTool:
        # A file Windows Defender is still scanning must not fail the cleanup.
        with tempfile.TemporaryDirectory(prefix="cyberfw-lock-", ignore_cleanup_errors=True) as work:
            return resolve_tool(self.client, spec, work_dir=Path(work))

    def locked(self, name: str) -> LockedTool:
        """``name``'s entry in ``tools.lock``, adding it (and writing the lock) when
        the tool is not locked yet. An entry the registry no longer matches is a
        :class:`LockError`: installing never rewrites a pin — ``cyberfw lock`` does."""
        spec = self.spec(name)
        lock = self.load_lock()
        entry = lock.tools.get(name)
        if entry is None:
            entry = self._resolve(spec)
            write_lock(self.lock_path, ToolLock(tools={**lock.tools, name: entry}))
            self.added_to_lock.append(name)
        reason = stale_reason(spec, entry)
        if reason is not None:
            raise LockError(f"{LOCK_NAME} is out of date for {name}: {reason} — run `cyberfw lock`")
        return entry

    def update_lock(self, names: list[str] | None = None, *, upgrade: bool = False) -> LockUpdate:
        """Bring ``tools.lock`` in line with the registry; write it if anything changed.

        Tools missing from the lock are added and stale entries (a changed
        ``repo`` / ``version:``) re-resolved; without ``names``, entries for tools
        gone from the registry (or now ``local``) are dropped. ``upgrade`` also
        re-resolves the entries that still match, moving them to the newest
        release the registry allows — but a release whose already-locked files
        changed under the same tag is refused and its entry kept. ``names``
        limits which tools are considered; an unknown one is a RegistryError.
        """
        lock = self.load_lock()
        tools = dict(lock.tools)
        downloadable = [name for name in self.registry.names() if not self.spec(name).is_local]
        changes: list[LockChange] = []
        if names is None:
            # A disabled plugin's tool is not gone: its pin stays for when it is enabled again.
            declared = self.plugins.declared() if self.plugins is not None else frozenset()
            for gone in sorted(set(tools) - set(downloadable) - declared):
                changes.append(LockChange(gone, tools.pop(gone).tag, None, "removed"))
        for name in downloadable if names is None else names:
            spec = self.spec(name)
            if spec.is_local:
                continue
            entry = tools.get(name)
            before = entry.tag if entry is not None else None
            stale = entry is not None and stale_reason(spec, entry) is not None
            if entry is not None and not stale and not upgrade:
                changes.append(LockChange(name, before, before, "unchanged", entry.sources))
                continue
            try:
                fresh = self._resolve(spec)
            except CyberfwError as exc:
                changes.append(LockChange(name, before, None, "failed", error=str(exc)))
                continue
            if entry is not None and entry.repo.lower() == fresh.repo.lower() and entry.tag == fresh.tag:
                # The same release as locked: a file it already published must not
                # change — and unless our own selection changed (a stale entry),
                # neither may which file a platform gets.
                suspicious = replaced_files(entry, fresh) or ([] if stale else reselected_platforms(entry, fresh))
                if suspicious:
                    error = (
                        f"{entry.tag} changed upstream after it was locked ({', '.join(suspicious)}); "
                        f"kept the locked files — to accept the new ones, remove {name} from "
                        f"{LOCK_NAME} and run `cyberfw lock {name}`"
                    )
                    changes.append(LockChange(name, before, before, "failed", error=error))
                    continue
            change: ChangeKind
            if entry is None:
                change = "added"
            elif stale:
                change = "re-resolved"
            elif fresh.tag != entry.tag:
                change = "upgraded"
            else:
                change = "unchanged" if fresh == entry else "updated"
            tools[name] = fresh
            changes.append(LockChange(name, before, fresh.tag, change, fresh.sources))
        updated = ToolLock(tools=tools)
        written, error = updated != lock, ""
        if written:
            try:
                write_lock(self.lock_path, updated)
            except LockError as exc:
                # Keep the computed changes: the caller still shows what would
                # have been pinned, then why it could not be saved.
                written, error = False, str(exc)
        return LockUpdate(changes=changes, written=written, path=self.lock_path, error=error)

    def binary_path(self, name: str) -> Path:
        """Return the binary path for ``name`` or raise ``ToolNotFoundError``.

        A ``source: local`` tool is resolved from its configured ``path`` or
        from PATH (it is never downloaded); a github tool from ``tools_dir``.
        A relative configured ``path`` is resolved against ``settings.root_dir``.
        """
        spec = self.spec(name)
        if spec.is_local:
            if spec.path:
                candidate = Path(spec.path)
                if not candidate.is_absolute():
                    candidate = (self.settings.root_dir / candidate).resolve()
                if candidate.is_file():
                    return candidate
                raise ToolNotFoundError(f"{name}: configured path does not exist: {candidate}")
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
        """Install one tool exactly as ``tools.lock`` pins it.

        A tool missing from the lock is added to it first. Nothing is downloaded —
        and no network is touched — when the locked version is already installed
        from the locked archive (the install state records both). A pre-lock
        install has no recorded hash, so it is re-downloaded once and verified.
        ``force`` re-downloads (and re-verifies) regardless.
        """
        spec = self.registry.require(name)
        if spec.is_local:
            raise CyberfwError(
                f"{name} is a local tool — install it with your package manager (apt/brew/winget), not via cyberfw"
            )
        entry = self.locked(name)
        asset = entry.assets.get(self.mapping.label)
        if asset is None:
            raise DownloadError(f"{name} {entry.tag} has no locked asset for {self.mapping.label}")
        state = None if force else self.install_state(name)
        if (
            state is not None
            and state.get("version") == entry.version
            and state.get("sha256") == asset.sha256
            and self.is_installed(name)
        ):
            return InstallResult(spec, self.binary_path(name), entry.version, up_to_date=True)

        state_path = self.settings.tools_dir / f".{name}.install.json"
        state_path.unlink(missing_ok=True)
        installer = ToolInstaller(
            self.client,
            self.settings.tools_dir,
            self.mapping,
            max_archive_size=self.settings.max_archive_size,
        )
        result = installer.install_locked(spec, entry.version, asset)
        state_path.write_text(
            json.dumps(
                {
                    "binary": str(result.binary.resolve()),
                    "version": result.version,
                    "sha256": asset.sha256,
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
