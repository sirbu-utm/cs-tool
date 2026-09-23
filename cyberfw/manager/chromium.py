"""Portable Chromium (Chrome for Testing) install for gowitness.

gowitness drives a headless Chrome/Chromium, which is not shipped as a portable
binary of its own — so on a machine without Chrome the screenshot stage cannot
run. Google publishes *Chrome for Testing* (CfT): per-platform builds hosted as
zips, listed in a public JSON manifest. This module downloads the Stable build
into ``tools_bin/chromium/`` using the same retrying HTTP client and the same
Zip-Slip-safe extraction as the tool installer, so gowitness gets a browser with
zero system-wide install.

The download is large (~150 MB, ~600 MB unpacked), so :meth:`ChromiumInstaller.install`
skips it when the recorded version already matches and the executable is on disk.
Platforms CfT does not build for (e.g. linux/arm64) raise
:class:`ChromiumUnsupportedError`; callers fall back to asking the user to
install a system Chrome.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path

from cyberfw.exceptions import ChromiumUnsupportedError, DownloadError
from cyberfw.logging import get_logger
from cyberfw.manager.archive import safe_extract_zip
from cyberfw.manager.github_client import GitHubClient
from cyberfw.manager.platform_map import Mapping

__all__ = ["ChromiumInstaller", "ChromiumInstallResult", "cft_platform", "find_chromium"]

LOG = get_logger("manager.chromium")

#: Where the portable browser is unpacked, under ``tools_dir``.
CHROMIUM_DIR_NAME = "chromium"
#: Install record (version/platform), a sibling of the tools' ``.<tool>.install.json``.
STATE_FILE = ".chromium.install.json"

_MANIFEST_URL = (
    "https://googlechromelabs.github.io/chrome-for-testing/"
    "last-known-good-versions-with-downloads.json"
)
_CHANNEL = "Stable"

#: Chromium unpacks to far more than a normal tool; give its extraction headroom.
DEFAULT_MAX_EXTRACT = 2 * 1024 * 1024 * 1024


def cft_platform(mapping: Mapping) -> str:
    """Map the current OS/arch onto a Chrome-for-Testing platform token.

    CfT publishes ``linux64``, ``win32``, ``win64``, ``mac-x64`` and
    ``mac-arm64`` only. Anything else (notably linux/arm64) raises
    :class:`ChromiumUnsupportedError`.
    """
    os_name, arch = mapping.os_name, mapping.arch_umbrella
    if os_name == "windows":
        # No arm64 CfT build for Windows; x64 runs under emulation on Win-ARM.
        return "win32" if arch == "386" else "win64"
    if os_name == "darwin":
        return "mac-arm64" if arch == "arm64" else "mac-x64"
    if os_name == "linux" and arch == "amd64":
        return "linux64"
    raise ChromiumUnsupportedError(
        f"Chrome for Testing publishes no portable build for {mapping.label}. "
        "Install a system Chrome/Chromium (winget install Google.Chrome / "
        "brew install --cask google-chrome / apt install chromium)."
    )


def _chrome_exe_names(os_name: str) -> tuple[str, ...]:
    """Executable file names to look for inside an unpacked CfT build."""
    if os_name == "windows":
        return ("chrome.exe",)
    if os_name == "darwin":
        return ("Google Chrome for Testing", "Google Chrome")
    return ("chrome",)


def _locate_chrome(base: Path, os_name: str) -> Path | None:
    """Find the Chrome executable somewhere under an unpacked CfT tree."""
    if not base.is_dir():
        return None
    wanted = _chrome_exe_names(os_name)
    for candidate in base.rglob("*"):
        if candidate.is_file() and candidate.name in wanted:
            return candidate
    return None


def find_chromium(tools_dir: Path, mapping: Mapping) -> str | None:
    """Return the managed Chromium executable path, or ``None`` if not installed."""
    found = _locate_chrome(tools_dir / CHROMIUM_DIR_NAME, mapping.os_name)
    return str(found) if found is not None else None


class ChromiumInstallResult:
    """Outcome of installing (or finding already installed) portable Chromium."""

    def __init__(self, binary: Path, version: str, *, up_to_date: bool = False) -> None:
        self.binary = binary
        self.version = version
        self.up_to_date = up_to_date

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"ChromiumInstallResult(binary={self.binary}, version={self.version}, up_to_date={self.up_to_date})"


class ChromiumInstaller:
    """Downloads the Stable Chrome-for-Testing build into ``tools_dir/chromium/``."""

    def __init__(
        self,
        client: GitHubClient,
        tools_dir: Path,
        mapping: Mapping,
        *,
        max_extract: int = DEFAULT_MAX_EXTRACT,
    ) -> None:
        self.client = client
        self.tools_dir = tools_dir
        self.mapping = mapping
        self.max_extract = max_extract

    # -- public --------------------------------------------------------------
    def resolve(self) -> tuple[str, str]:
        """Return ``(version, download_url)`` for this platform's Stable build."""
        platform = cft_platform(self.mapping)
        try:
            data = json.loads(self.client.fetch_text(_MANIFEST_URL))
            channel = data["channels"][_CHANNEL]
            version = str(channel["version"])
            downloads = channel["downloads"]["chrome"]
        except (ValueError, KeyError, TypeError) as exc:
            raise DownloadError(f"Unexpected Chrome for Testing manifest: {exc}") from exc
        for entry in downloads:
            if entry.get("platform") == platform:
                url = str(entry["url"])
                LOG.debug("chromium: %s Stable %s -> %s", platform, version, url)
                return version, url
        raise ChromiumUnsupportedError(
            f"Chrome for Testing manifest lists no '{platform}' build (version {version})."
        )

    def executable(self) -> str | None:
        """The installed Chromium executable path, or ``None``."""
        return find_chromium(self.tools_dir, self.mapping)

    def installed_version(self) -> str | None:
        """Version recorded by the last successful install, or ``None``."""
        state = self._read_state()
        return state.get("version") if state else None

    def install(self, *, force: bool = False) -> ChromiumInstallResult:
        """Ensure the Stable Chromium build is present; download it if missing.

        Skips the download when the recorded version already matches and the
        executable is on disk, unless ``force``.
        """
        version, url = self.resolve()
        existing = self.executable()
        if not force and existing is not None and self.installed_version() == version:
            LOG.debug("chromium: %s already installed at %s", version, existing)
            return ChromiumInstallResult(Path(existing), version, up_to_date=True)

        chromium_dir = self.tools_dir / CHROMIUM_DIR_NAME
        archive = self.tools_dir / f"chrome-{cft_platform(self.mapping)}.zip"
        self._state_path().unlink(missing_ok=True)
        try:
            self.client.download(url, archive)
            self._reset_dir(chromium_dir)
            safe_extract_zip(archive, chromium_dir, max_size=self.max_extract)
        finally:
            archive.unlink(missing_ok=True)

        binary = _locate_chrome(chromium_dir, self.mapping.os_name)
        if binary is None:
            raise DownloadError(
                f"Chromium archive for {self.mapping.label} contained no "
                f"{_chrome_exe_names(self.mapping.os_name)[0]} executable."
            )
        self._make_executable(binary)
        self._write_state(version, binary)
        LOG.debug("chromium: installed %s -> %s", version, binary)
        return ChromiumInstallResult(binary.resolve(), version)

    # -- state ---------------------------------------------------------------
    def _state_path(self) -> Path:
        return self.tools_dir / STATE_FILE

    def _read_state(self) -> dict[str, str] | None:
        path = self._state_path()
        if not path.is_file():
            return None
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return state if isinstance(state, dict) else None

    def _write_state(self, version: str, binary: Path) -> None:
        self._state_path().write_text(
            json.dumps(
                {
                    "binary": str(binary.resolve()),
                    "version": version,
                    "os": self.mapping.os_name,
                    "arch": self.mapping.arch,
                    "platform": cft_platform(self.mapping),
                }
            ),
            encoding="utf-8",
        )

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def _reset_dir(path: Path) -> None:
        """Empty ``path`` so nothing from a previous Chromium survives the reinstall."""
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        path.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _make_executable(binary: Path) -> None:
        if os.name == "nt":
            return
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
