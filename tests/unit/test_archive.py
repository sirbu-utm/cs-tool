"""Tests for the shared safe-extraction guards (Zip Slip + extraction cap)."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from cyberfw.exceptions import ArchiveSafetyError, DownloadError
from cyberfw.manager.archive import (
    assert_extract_size,
    safe_extract_zip,
    safe_member,
)


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buffer.getvalue()


class TestSafeMember:
    def test_zip_slip_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ArchiveSafetyError):
            safe_member("../evil.txt", tmp_path / "subfinder")

    def test_member_escaping_into_a_sibling_dir_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ArchiveSafetyError):
            safe_member("../httpx/httpx", tmp_path / "subfinder")

    def test_nested_within_root_allowed(self, tmp_path: Path) -> None:
        dest = tmp_path / "subfinder"
        target = safe_member("subfinder_1.0/subfinder", dest)
        assert target.relative_to(dest) == Path("subfinder_1.0/subfinder")


class TestExtractSize:
    def test_over_limit_refused(self) -> None:
        with pytest.raises(DownloadError, match="limit"):
            assert_extract_size(2000, "chrome.zip", 1000)

    def test_within_limit_allowed(self) -> None:
        assert_extract_size(1000, "chrome.zip", 1000)  # exactly at the limit


class TestSafeExtractZip:
    def test_extracts_nested_tree(self, tmp_path: Path) -> None:
        archive = tmp_path / "a.zip"
        archive.write_bytes(_zip_bytes({"chrome-win64/chrome.exe": b"MZ binary"}))
        dest = tmp_path / "chromium"
        safe_extract_zip(archive, dest, max_size=1 << 20)
        assert (dest / "chrome-win64" / "chrome.exe").read_bytes() == b"MZ binary"

    def test_zip_slip_member_rejected(self, tmp_path: Path) -> None:
        archive = tmp_path / "evil.zip"
        archive.write_bytes(_zip_bytes({"../escape.txt": b"x"}))
        with pytest.raises(ArchiveSafetyError):
            safe_extract_zip(archive, tmp_path / "chromium", max_size=1 << 20)

    def test_bomb_refused_before_writing(self, tmp_path: Path) -> None:
        archive = tmp_path / "big.zip"
        archive.write_bytes(_zip_bytes({"chrome": b"A" * 4096}))
        dest = tmp_path / "chromium"
        with pytest.raises(DownloadError, match="limit"):
            safe_extract_zip(archive, dest, max_size=16)
        assert not dest.exists() or not any(dest.rglob("*"))
