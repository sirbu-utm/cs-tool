"""Unit tests for OS/arch → asset-name mapping."""

from __future__ import annotations

import os
from pathlib import Path

from cyberfw.manager.platform_map import Mapping, asset_patterns
from cyberfw.manager.verify import is_executable


class TestMapping:
    def test_get_target_arch_umbrella(self) -> None:
        assert Mapping("linux", "arm64").arch_umbrella == "arm64"
        assert Mapping("linux", "amd64").arch_umbrella == "amd64"

    def test_fields(self) -> None:
        mapping = Mapping(os_name="linux", arch="amd64")
        assert mapping.os_name == "linux"
        assert mapping.arch == "amd64"


class TestAssetPatterns:
    def test_linux_amd64(self) -> None:
        patterns = asset_patterns(Mapping("linux", "amd64"))
        assert "*linux*amd64*" in patterns
        assert "*linux*x86_64*" in patterns

    def test_linux_arm64(self) -> None:
        patterns = asset_patterns(Mapping("linux", "arm64"))
        assert "*linux*arm64*" in patterns
        assert "*linux*aarch64*" in patterns
        # amd64 is not offered for arm64 hosts
        assert "*linux*amd64*" not in patterns

    def test_darwin_amd64_has_reverse_order(self) -> None:
        patterns = asset_patterns(Mapping("darwin", "amd64"))
        assert "*darwin*amd64*" in patterns
        assert "*amd64*darwin*" in patterns

    def test_windows_has_fallback(self) -> None:
        patterns = asset_patterns(Mapping("windows", "amd64"))
        assert "*windows*" in patterns
        assert "*windows*amd64*" in patterns
        assert "*amd64*windows*" in patterns

    def test_darwin_accepts_macos_token(self) -> None:
        patterns = asset_patterns(Mapping("darwin", "arm64"))
        assert "*darwin*arm64*" in patterns
        assert "*macos*arm64*" in patterns

    def test_arches_are_fnmatch_usable(self) -> None:
        import fnmatch

        pattern = asset_patterns(Mapping("linux", "amd64"))[0]
        assert fnmatch.fnmatch("subfinder_2.6.0_linux_amd64.zip", pattern)


class TestExecutableValidation:
    def test_windows_accepts_pe_binary(self, tmp_path: Path, monkeypatch) -> None:
        path = tmp_path / "tool.exe"
        path.write_bytes(b"MZ" + b"\0" * 8)
        monkeypatch.setattr(os, "name", "nt")
        assert is_executable(path)

    def test_windows_rejects_elf_binary(self, tmp_path: Path, monkeypatch) -> None:
        path = tmp_path / "tool"
        path.write_bytes(b"\x7fELF" + b"\0" * 8)
        monkeypatch.setattr(os, "name", "nt")
        assert not is_executable(path)


def test_mapping_has_one_label_for_every_display() -> None:
    """The banner, the saved report and `status` all name the platform; one
    property keeps them from drifting apart."""
    from cyberfw.manager.platform_map import Mapping

    assert Mapping("windows", "amd64").label == "windows/amd64"
    assert Mapping("darwin", "arm64").label == "darwin/arm64"
