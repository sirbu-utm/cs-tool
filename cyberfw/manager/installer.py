"""Safe download / verify / extract / permission handling for tool binaries — each
archive checked against its ``tools.lock`` hash.

Guards against `Zip Slip` (any member path escaping ``tools_bin/``), enforces an
upper bound on archive size, and makes extracted binaries executable on Unix.

Layout: each tool is unpacked into its own ``tools_bin/<tool>/`` directory, which
is wiped on re-install; the downloaded archive is deleted once extracted. The
top level of ``tools_bin/`` therefore only holds those directories plus the
``.<tool>.install.json`` state files written by :class:`ToolManager`.
"""

from __future__ import annotations

import fnmatch
import os
import shutil
import stat
import tarfile
import uuid
import zipfile
import zlib
from pathlib import Path
from typing import TYPE_CHECKING

from cyberfw.exceptions import ChecksumError, DownloadError
from cyberfw.logging import get_logger
from cyberfw.manager.archive import assert_extract_size, normalize, safe_extract_zip, safe_member
from cyberfw.manager.github_client import GitHubClient, GitHubRelease, ReleaseAsset
from cyberfw.manager.platform_map import Mapping, asset_patterns
from cyberfw.manager.registry import ToolSpec
from cyberfw.manager.verify import sha256_hex

if TYPE_CHECKING:  # lock.py imports select_asset from here
    from cyberfw.manager.lock import LockedAsset

__all__ = ["InstallResult", "ToolInstaller", "DEFAULT_MAX_ARCHIVE_SIZE", "select_asset"]

LOG = get_logger("manager.installer")

#: Upper bound on what an archive may extract to; ``Settings.max_archive_size``
#: overrides it (``CYBERFW_MAX_ARCHIVE_SIZE`` / ``config.local.yaml``).
DEFAULT_MAX_ARCHIVE_SIZE = 512 * 1024 * 1024

#: What the stdlib raises for a damaged or forged archive (bad CRC / size
#: headers, truncated gzip stream, invalid DEFLATE data).
_CORRUPT_ARCHIVE_ERRORS: tuple[type[BaseException], ...] = (
    zipfile.BadZipFile,
    tarfile.TarError,
    zlib.error,
    EOFError,
)


def _os_patterns(spec: ToolSpec, mapping: Mapping) -> list[str]:
    """The registry patterns that name ``mapping``'s OS (``macos`` counts as darwin)."""
    os_tokens = {mapping.os_name}
    if mapping.os_name == "darwin":
        os_tokens.add("macos")
    return [pattern for pattern in spec.asset_patterns if any(token in pattern.lower() for token in os_tokens)]


def select_asset(release: GitHubRelease, spec: ToolSpec, mapping: Mapping) -> ReleaseAsset | None:
    """The asset of ``release`` that ``spec`` installs on ``mapping``'s platform, or ``None``.

    The platform's own spellings come first (without the bare ``*windows*``
    catch-all), then the registry patterns naming this OS, and only then the
    catch-all. Registry patterns for *other* OSes are never eligible: a Linux
    build must never be picked as a fallback on macOS just because it is listed
    first. Shared by the installer and ``tools.lock`` so they cannot disagree.
    """
    platform_patterns = asset_patterns(mapping)
    exact = [pattern for pattern in platform_patterns if pattern != "*windows*"]
    asset = release.find_asset(*exact)
    if asset is None:
        os_patterns = _os_patterns(spec, mapping)
        if os_patterns:
            asset = release.find_asset(*os_patterns)
    if asset is None:
        asset = release.find_asset(*platform_patterns)
    return asset


class InstallResult:
    """Outcome of a successful install (or of finding the wanted version in place)."""

    def __init__(self, spec: ToolSpec, binary: Path, version: str, *, up_to_date: bool = False) -> None:
        self.spec = spec
        self.binary = binary
        self.version = version
        #: True when nothing was downloaded because this version was already installed.
        self.up_to_date = up_to_date

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"InstallResult(binary={self.binary}, version={self.version}, up_to_date={self.up_to_date})"


class ToolInstaller:
    """Installs one tool into ``tools_dir`` from GitHub Releases."""

    def __init__(
        self,
        client: GitHubClient,
        tools_dir: Path,
        mapping: Mapping,
        *,
        max_archive_size: int = DEFAULT_MAX_ARCHIVE_SIZE,
    ) -> None:
        self.client = client
        self.tools_dir = tools_dir
        self.mapping = mapping
        self.max_archive_size = max_archive_size

    # -- public --------------------------------------------------------------
    def install_locked(self, spec: ToolSpec, version: str, asset: LockedAsset) -> InstallResult:
        """Install one platform's entry of a locked release, verified against the lock.

        The archive's SHA-256 must equal the lock's *before* anything of the
        previous install is touched, so a replaced or corrupted download leaves
        the working tool in place. The downloaded archive is always removed.
        """
        tool_dir = self.tools_dir / spec.name
        archive_path = self.tools_dir / asset.name
        try:
            self.client.download(asset.url, archive_path)
            actual = sha256_hex(archive_path)
            if actual != asset.sha256:
                raise ChecksumError(
                    f"SHA-256 mismatch for {asset.name}: tools.lock has {asset.sha256}, got {actual}"
                )
            self._remove_existing_binary(spec)
            self._remove_stale_downloads(spec, keep=archive_path)
            self._reset_tool_dir(tool_dir)
            binary = self._extract(spec, archive_path, tool_dir)
        finally:
            archive_path.unlink(missing_ok=True)
        self._make_executable(binary)
        LOG.debug("%s: installed %s from %s -> %s", spec.name, version, asset.name, binary)
        return InstallResult(spec=spec, binary=binary.resolve(), version=version)

    # -- pipeline ------------------------------------------------------------
    def _extract(self, spec: ToolSpec, archive_path: Path, tool_dir: Path) -> Path:
        kind = _archive_kind(spec.archive, archive_path.name)
        try:
            self._extract_kind(kind, spec, archive_path, tool_dir)
        except _CORRUPT_ARCHIVE_ERRORS as exc:
            # Truncated download, forged size/CRC headers, bad DEFLATE stream.
            # The stdlib already bounds each member to its declared size, so a
            # header-forged bomb cannot inflate past the limit checked above —
            # but the failure must read as a clean install error, not a traceback.
            raise DownloadError(f"corrupt archive {archive_path.name}: {exc}") from exc
        # Ensure everything is executable *before* locating, because just-unpacked
        # zip members carry no exec bit and ensure_binary refuses non-executables.
        self._make_tree_executable(tool_dir)
        return self._locate_binary(spec, tool_dir)

    def _extract_kind(self, kind: str, spec: ToolSpec, archive_path: Path, tool_dir: Path) -> None:
        if kind == "zip":
            self._extract_zip(archive_path, tool_dir)
        elif kind == "tar":
            self._extract_tar(archive_path, tool_dir)
        elif kind == "raw":
            if spec.binary is None:
                raise DownloadError(f"Raw asset for {spec.name} requires a binary name")
            binary_name = spec.binary
            if os.name == "nt" and not binary_name.lower().endswith(".exe"):
                binary_name += ".exe"
            # The download *is* the binary: move it under its tool name rather
            # than leaving a second copy behind under the release asset name.
            shutil.move(str(archive_path), str(tool_dir / binary_name))
        else:
            raise DownloadError(f"Unsupported archive format for {archive_path.name}")

    # -- extraction ----------------------------------------------------------
    def _extract_zip(self, archive_path: Path, dest: Path) -> None:
        safe_extract_zip(archive_path, dest, max_size=self.max_archive_size)

    def _extract_tar(self, archive_path: Path, dest: Path) -> None:
        with tarfile.open(archive_path, "r:*") as tf:
            total = sum(m.size for m in tf.getmembers() if m.isfile())
            assert_extract_size(total, archive_path.name, self.max_archive_size)
            for member in tf.getmembers():
                target = safe_member(normalize(member.name), dest)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    continue  # skip symlinks/devices — defence in depth
                target.parent.mkdir(parents=True, exist_ok=True)
                src = tf.extractfile(member)
                if src is None:
                    continue
                with open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
                os.chmod(target, member.mode | stat.S_IRWXU)

    # -- helpers -------------------------------------------------------------
    def _make_tree_executable(self, root: Path) -> None:
        """Set the exec bit on every regular file under ``root`` (Unix only)."""
        if os.name == "nt":
            return
        for path in root.rglob("*"):
            if path.is_file():
                path.chmod(path.stat().st_mode | stat.S_IEXEC)

    def _locate_binary(self, spec: ToolSpec, tool_dir: Path) -> Path:
        from cyberfw.manager.verify import ensure_binary

        return ensure_binary(tool_dir, spec.name, spec.binary)

    def _reset_tool_dir(self, tool_dir: Path) -> None:
        """Empty ``tool_dir`` so nothing from the previous version survives the re-install.

        A file Windows still holds open is parked under a ``.stale-*`` name (see
        :meth:`_unlink_or_park`); ``rmtree`` then leaves it in place and the fresh
        extraction happens around it.
        """
        if tool_dir.is_dir():
            for path in list(tool_dir.rglob("*")):
                if path.is_file():
                    self._unlink_or_park(path)
            shutil.rmtree(tool_dir, ignore_errors=True)
        tool_dir.mkdir(parents=True, exist_ok=True)

    def _remove_stale_downloads(self, spec: ToolSpec, *, keep: Path) -> None:
        """Delete archives of *this* tool that earlier installs left at the top level.

        Only files matching the tool's own asset patterns are touched; other tools'
        files and the archive being installed right now are left alone.
        """
        patterns = [pattern.lower() for pattern in spec.asset_patterns]
        for path in list(self.tools_dir.iterdir()):
            if path == keep or not path.is_file():
                continue
            if any(fnmatch.fnmatch(path.name.lower(), pattern) for pattern in patterns):
                self._unlink_or_park(path)

    def _remove_existing_binary(self, spec: ToolSpec) -> None:
        """Remove stale copies of the binary anywhere under ``tools_dir``.

        Covers the pre-per-tool-directory layout, where binaries sat at the top
        level. The ``.exe`` variant is stale on every OS (a checkout shared between
        Windows and WSL otherwise keeps both ``httpx`` and ``httpx.exe`` forever).
        """
        if spec.binary is None:
            return
        names = {spec.binary}
        if not spec.binary.lower().endswith(".exe"):
            names.add(spec.binary + ".exe")
        wanted = {name.lower() for name in names}
        for path in list(self.tools_dir.rglob("*")):
            if path.is_file() and path.name.lower() in wanted:
                self._unlink_or_park(path)

    @staticmethod
    def _unlink_or_park(path: Path) -> None:
        """Delete ``path``; if Windows holds it open (running exe, AV scan), rename it aside.

        Windows refuses to delete a mapped executable but does allow renaming
        it, so parking the stale file frees its name for the fresh extract; the
        parked copy is removed if possible and otherwise left as harmless clutter.
        """
        try:
            path.unlink()
            return
        except PermissionError:
            pass
        parked = path.with_name(f"{path.name}.stale-{uuid.uuid4().hex[:8]}")
        path.replace(parked)
        try:
            parked.unlink()
        except OSError:  # still locked — a different name, so it no longer shadows the new binary
            pass

    def _make_executable(self, binary: Path) -> None:
        if os.name == "nt":
            return
        mode = binary.stat().st_mode | stat.S_IEXEC
        binary.chmod(mode)


def _archive_kind(declared: str, name: str) -> str:
    if declared == "raw":
        return "raw"
    if declared == "zip" or name.lower().endswith(".zip"):
        return "zip"
    if declared == "tar" or name.lower().endswith((".tar.gz", ".tgz", ".tar", ".tar.xz", ".tar.bz2")):
        return "tar"
    return "unknown"  # pragma: no cover - defensive
