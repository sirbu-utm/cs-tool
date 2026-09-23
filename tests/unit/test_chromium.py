"""Tests for portable Chromium (Chrome for Testing) resolution and install."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from cyberfw.exceptions import ChromiumUnsupportedError
from cyberfw.manager.chromium import ChromiumInstaller, cft_platform, find_chromium
from cyberfw.manager.platform_map import Mapping


def _manifest(version: str = "131.0.6778.85") -> str:
    def _dl(platform: str) -> dict[str, str]:
        return {"platform": platform, "url": f"https://cft.example/{version}/{platform}/chrome-{platform}.zip"}

    return json.dumps(
        {
            "channels": {
                "Stable": {
                    "channel": "Stable",
                    "version": version,
                    "downloads": {
                        "chrome": [
                            _dl("linux64"),
                            _dl("win64"),
                            _dl("mac-arm64"),
                        ]
                    },
                }
            }
        }
    )


def _chrome_zip(platform: str = "linux64", exe: str = "chrome") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"chrome-{platform}/{exe}", b"MZ" + b"\x00" * 64)
        zf.writestr(f"chrome-{platform}/README", b"portable chrome")
    return buffer.getvalue()


class _FakeClient:
    def __init__(self, manifest: str, archive: bytes) -> None:
        self.manifest = manifest
        self.archive = archive
        self.downloads: list[str] = []

    def fetch_text(self, url: str) -> str:
        return self.manifest

    def download(self, url: str, destination: Path, *, expected_size: int | None = None) -> None:
        self.downloads.append(url)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.archive)


def _installer(tmp_path: Path, client, mapping: Mapping | None = None) -> ChromiumInstaller:
    tools_dir = tmp_path / "tools_bin"
    tools_dir.mkdir(parents=True, exist_ok=True)
    return ChromiumInstaller(client, tools_dir, mapping or Mapping("linux", "amd64"))


class TestCftPlatform:
    @pytest.mark.parametrize(
        ("os_name", "arch", "expected"),
        [
            ("windows", "amd64", "win64"),
            ("windows", "386", "win32"),
            ("darwin", "arm64", "mac-arm64"),
            ("darwin", "amd64", "mac-x64"),
            ("linux", "amd64", "linux64"),
        ],
    )
    def test_supported(self, os_name: str, arch: str, expected: str) -> None:
        assert cft_platform(Mapping(os_name, arch)) == expected

    def test_linux_arm64_unsupported(self) -> None:
        with pytest.raises(ChromiumUnsupportedError):
            cft_platform(Mapping("linux", "arm64"))


class TestResolve:
    def test_picks_url_for_platform(self, tmp_path: Path) -> None:
        client = _FakeClient(_manifest(), _chrome_zip())
        version, url = _installer(tmp_path, client).resolve()
        assert version == "131.0.6778.85"
        assert url.endswith("/linux64/chrome-linux64.zip")

    def test_platform_absent_from_downloads_raises(self, tmp_path: Path) -> None:
        client = _FakeClient(_manifest(), _chrome_zip())
        inst = _installer(tmp_path, client, Mapping("darwin", "amd64"))  # mac-x64 not in manifest
        with pytest.raises(ChromiumUnsupportedError):
            inst.resolve()


class TestInstall:
    def test_downloads_extracts_and_records(self, tmp_path: Path) -> None:
        client = _FakeClient(_manifest(), _chrome_zip())
        inst = _installer(tmp_path, client)
        result = inst.install()
        assert client.downloads  # something was fetched
        assert result.version == "131.0.6778.85"
        assert Path(result.binary).is_file()
        assert Path(result.binary).name == "chrome"
        assert inst.installed_version() == "131.0.6778.85"

    def test_second_install_is_up_to_date_without_download(self, tmp_path: Path) -> None:
        client = _FakeClient(_manifest(), _chrome_zip())
        inst = _installer(tmp_path, client)
        inst.install()
        client.downloads.clear()
        result = inst.install()
        assert result.up_to_date is True
        assert client.downloads == []

    def test_force_redownloads(self, tmp_path: Path) -> None:
        client = _FakeClient(_manifest(), _chrome_zip())
        inst = _installer(tmp_path, client)
        inst.install()
        client.downloads.clear()
        result = inst.install(force=True)
        assert result.up_to_date is False
        assert client.downloads


class TestDebugDiagnostics:
    def test_install_logs_resolve_and_download(self, tmp_path: Path, caplog) -> None:  # type: ignore[no-untyped-def]
        import logging

        client = _FakeClient(_manifest(), _chrome_zip())
        inst = _installer(tmp_path, client)

        logger = logging.getLogger("cyberfw.manager.chromium")
        logger.addHandler(caplog.handler)
        logger.setLevel(logging.DEBUG)
        try:
            inst.install()
        finally:
            logger.removeHandler(caplog.handler)

        messages = " ".join(r.getMessage() for r in caplog.records)
        assert "linux64" in messages  # resolved CfT platform
        assert "131.0.6778.85" in messages  # resolved version


class TestFindChromium:
    def test_returns_none_when_absent(self, tmp_path: Path) -> None:
        assert find_chromium(tmp_path / "tools_bin", Mapping("linux", "amd64")) is None

    def test_returns_executable_after_install(self, tmp_path: Path) -> None:
        client = _FakeClient(_manifest(), _chrome_zip())
        inst = _installer(tmp_path, client)
        inst.install()
        found = find_chromium(inst.tools_dir, Mapping("linux", "amd64"))
        assert found is not None
        assert Path(found).name == "chrome"
