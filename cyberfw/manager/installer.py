"""Safe download / extract / permission handling for tool binaries.

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

from cyberfw.exceptions import ArchiveSafetyError, DownloadError
from cyberfw.manager.github_client import GitHubClient, GitHubRelease, ReleaseAsset
from cyberfw.manager.platform_map import Mapping, asset_patterns
from cyberfw.manager.registry import ToolSpec
from cyberfw.manager.verify import verify_checksum

__all__ = ["InstallResult", "ToolInstaller", "DEFAULT_MAX_ARCHIVE_SIZE"]

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


class InstallResult:
    """Outcome of a successful install."""

    def __init__(self, spec: ToolSpec, binary: Path, version: str) -> None:
        self.spec = spec
        self.binary = binary
        self.version = version

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"InstallResult(binary={self.binary}, version={self.version})"


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
    def install(self, spec: ToolSpec) -> InstallResult:
        release = self.client.latest(spec.repo_owner, spec.repo_name)
        platform_patterns = asset_patterns(self.mapping)
        exact_platform_patterns = [pattern for pattern in platform_patterns if pattern != "*windows*"]
        asset = release.find_asset(*exact_platform_patterns)
        # Registry patterns cover every OS; only the ones naming *this* OS are
        # eligible — a Linux/Windows build must never be picked as a fallback
        # on macOS just because it is listed first.
        os_tokens = {self.mapping.os_name}
        if self.mapping.os_name == "darwin":
            os_tokens.add("macos")
        os_patterns = [
            pattern
            for pattern in spec.asset_patterns
            if any(token in pattern.lower() for token in os_tokens)
        ]
        if asset is None and os_patterns:
            asset = release.find_asset(*os_patterns)
        if asset is None:
            asset = release.find_asset(*platform_patterns)
        patterns = [*platform_patterns, *os_patterns]
        if asset is None:
            raise DownloadError(
                f"No released asset for {spec.repo} matches OS={self.mapping.os_name}, "
                f"arch={self.mapping.arch}. Release tag: {release.tag}. "
                f"Tried patterns: {patterns or '<none>'}."
            )
        tool_dir = self.tools_dir / spec.name
        archive_path = self.tools_dir / asset.name
        try:
            self._download_checked(asset, archive_path, release, spec)
            # Only touch the previous install once the new archive is safely on
            # disk, so a failed download leaves a working tool in place.
            self._remove_existing_binary(spec)
            self._remove_stale_downloads(spec, keep=archive_path)
            self._reset_tool_dir(tool_dir)
            binary = self._extract(spec, archive_path, tool_dir)
        finally:
            archive_path.unlink(missing_ok=True)
        self._make_executable(binary)
        return InstallResult(spec=spec, binary=binary.resolve(), version=release.version)

    # -- pipeline ------------------------------------------------------------
    def _download_checked(self, asset: ReleaseAsset, dst: Path, release: GitHubRelease, spec: ToolSpec) -> None:
        self.client.download(asset.url, dst, expected_size=asset.size)
        if spec.needs_checksum and release.checksums_url:
            body = self.client.fetch_text(release.checksums_url)
            verify_checksum(body, asset.name, dst)

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
        with zipfile.ZipFile(archive_path) as zf:
            self._assert_extract_size(sum(i.file_size for i in zf.infolist()), archive_path)
            for info in zf.infolist():
                target = self._safe_member(_normalize(info.filename), dest)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)

    def _extract_tar(self, archive_path: Path, dest: Path) -> None:
        with tarfile.open(archive_path, "r:*") as tf:
            total = sum(m.size for m in tf.getmembers() if m.isfile())
            self._assert_extract_size(total, archive_path)
            for member in tf.getmembers():
                target = self._safe_member(_normalize(member.name), dest)
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

    def _safe_member(self, member_rel: str, dest: Path) -> Path:
        """Validate an archive member path stays inside ``dest`` (the tool's directory)."""
        target = (dest / member_rel).resolve()
        root = dest.resolve()
        if target != root and root not in target.parents:
            raise ArchiveSafetyError(f"Archive member escapes {dest.name}/: {member_rel!r}")
        return target

    def _assert_extract_size(self, total: int, archive_path: Path) -> None:
        limit = self.max_archive_size
        if total > limit:
            raise DownloadError(
                f"Archive {archive_path.name} would extract to {total} bytes (limit {limit})"
            )

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


def _normalize(name: str) -> str:
    return os.path.normpath(name.replace("\\", "/"))


def _archive_kind(declared: str, name: str) -> str:
    if declared == "raw":
        return "raw"
    if declared == "zip" or name.lower().endswith(".zip"):
        return "zip"
    if declared == "tar" or name.lower().endswith((".tar.gz", ".tgz", ".tar", ".tar.xz", ".tar.bz2")):
        return "tar"
    return "unknown"  # pragma: no cover - defensive
