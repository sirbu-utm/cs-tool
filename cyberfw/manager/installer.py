"""Safe download / extract / permission handling for tool binaries.

Guards against `Zip Slip` (any member path escaping ``tools_bin/``), enforces an
upper bound on archive size, and makes extracted binaries executable on Unix.
"""

from __future__ import annotations

import os
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path

from cyberfw.exceptions import ArchiveSafetyError, DownloadError
from cyberfw.manager.github_client import GitHubClient, GitHubRelease, ReleaseAsset
from cyberfw.manager.platform_map import Mapping, asset_patterns
from cyberfw.manager.registry import ToolSpec
from cyberfw.manager.verify import verify_checksum

__all__ = ["InstallResult", "ToolInstaller"]


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

    def __init__(self, client: GitHubClient, tools_dir: Path, mapping: Mapping) -> None:
        self.client = client
        self.tools_dir = tools_dir
        self.mapping = mapping

    # -- public --------------------------------------------------------------
    def install(self, spec: ToolSpec) -> InstallResult:
        release = self.client.latest(spec.repo_owner, spec.repo_name)
        platform_patterns = asset_patterns(self.mapping)
        exact_platform_patterns = [pattern for pattern in platform_patterns if pattern != "*windows*"]
        asset = release.find_asset(*exact_platform_patterns)
        os_patterns = [pattern for pattern in spec.asset_patterns if self.mapping.os_name in pattern.lower()]
        if asset is None and os_patterns:
            asset = release.find_asset(*os_patterns)
        if asset is None and spec.asset_patterns:
            asset = release.find_asset(*spec.asset_patterns)
        if asset is None:
            asset = release.find_asset(*platform_patterns)
        patterns = [*platform_patterns, *spec.asset_patterns]
        if asset is None and not patterns:
            asset = self._first_asset(release)
        if asset is None:
            raise DownloadError(
                f"No released asset for {spec.repo} matches OS={self.mapping.os_name}, "
                f"arch={self.mapping.arch}. Release tag: {release.tag}. "
                f"Tried patterns: {patterns or '<none>'}."
            )
        archive_path = self.tools_dir / asset.name
        self._download_checked(asset, archive_path, release, spec)
        self._remove_existing_binary(spec)
        binary = self._extract(spec, archive_path)
        self._make_executable(binary)
        return InstallResult(spec=spec, binary=binary.resolve(), version=release.version)

    @staticmethod
    def _first_asset(release: GitHubRelease) -> ReleaseAsset | None:
        return release.assets[0] if release.assets else None

    # -- pipeline ------------------------------------------------------------
    def _download_checked(self, asset: ReleaseAsset, dst: Path, release: GitHubRelease, spec: ToolSpec) -> None:
        self.client.download(asset.url, dst, expected_size=asset.size)
        if spec.needs_checksum and release.checksums_url:
            body = self.client.fetch_text(release.checksums_url)
            verify_checksum(body, asset.name, dst)

    def _extract(self, spec: ToolSpec, archive_path: Path) -> Path:
        kind = _archive_kind(spec.archive, archive_path.name)
        if kind == "zip":
            self._extract_zip(archive_path)
        elif kind == "tar":
            self._extract_tar(archive_path)
        elif kind == "raw":
            if spec.binary is None:
                raise DownloadError(f"Raw asset for {spec.name} requires a binary name")
            binary_name = spec.binary
            if os.name == "nt" and not binary_name.lower().endswith(".exe"):
                binary_name += ".exe"
            target = self.tools_dir / binary_name
            if target.name != spec.binary:
                (self.tools_dir / spec.binary).unlink(missing_ok=True)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(archive_path, target)
        else:
            raise DownloadError(f"Unsupported archive format for {archive_path.name}")
        # Ensure everything is executable *before* locating, because just-unpacked
        # zip members carry no exec bit and ensure_binary refuses non-executables.
        self._make_whole_tree_executable()
        return self._locate_binary(spec)

    # -- extraction ----------------------------------------------------------
    def _extract_zip(self, archive_path: Path) -> None:
        with zipfile.ZipFile(archive_path) as zf:
            self._assert_extract_size(sum(i.file_size for i in zf.infolist()), archive_path)
            for info in zf.infolist():
                target = self._safe_member(_normalize(info.filename))
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)

    def _extract_tar(self, archive_path: Path) -> None:
        with tarfile.open(archive_path, "r:*") as tf:
            total = sum(m.size for m in tf.getmembers() if m.isfile())
            self._assert_extract_size(total, archive_path)
            for member in tf.getmembers():
                target = self._safe_member(_normalize(member.name))
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

    def _safe_member(self, member_rel: str) -> Path:
        """Validate an archive member path stays inside ``tools_dir``."""
        target = (self.tools_dir / member_rel).resolve()
        root = self.tools_dir.resolve()
        if target != root and root not in target.parents:
            raise ArchiveSafetyError(f"Archive member escapes tools_dir: {member_rel!r}")
        return target

    def _assert_extract_size(self, total: int, archive_path: Path) -> None:
        limit = int(os.environ.get("CYBERFW_MAX_ARCHIVE", 512 * 1024 * 1024))
        if total > limit:
            raise DownloadError(
                f"Archive {archive_path.name} would extract to {total} bytes (limit {limit})"
            )

    # -- helpers -------------------------------------------------------------
    def _make_whole_tree_executable(self) -> None:
        """Set the exec bit on every regular file under ``tools_dir`` (Unix only)."""
        if os.name == "nt":
            return
        for path in self.tools_dir.rglob("*"):
            if path.is_file():
                path.chmod(path.stat().st_mode | stat.S_IEXEC)

    def _locate_binary(self, spec: ToolSpec) -> Path:
        from cyberfw.manager.verify import ensure_binary

        return ensure_binary(self.tools_dir, spec.name, spec.binary)

    def _remove_existing_binary(self, spec: ToolSpec) -> None:
        """Remove stale platform variants before locating the new binary."""
        if spec.binary is None:
            return
        names = {spec.binary}
        if os.name == "nt" and not spec.binary.lower().endswith(".exe"):
            names.add(spec.binary + ".exe")
        for path in self.tools_dir.rglob("*"):
            if path.is_file() and path.name.lower() in {name.lower() for name in names}:
                path.unlink()

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
