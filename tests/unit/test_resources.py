"""Tests for locating packaged data and per-user directories (installed-package mode)."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberfw import resources


class TestUserDataDir:
    def test_windows_uses_localappdata(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(resources.sys, "platform", "win32")
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))

        assert resources.user_data_dir() == tmp_path / "Local" / "cyberfw"

    def test_macos_uses_application_support(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(resources.sys, "platform", "darwin")
        monkeypatch.setattr(resources.Path, "home", classmethod(lambda cls: tmp_path))

        assert resources.user_data_dir() == tmp_path / "Library" / "Application Support" / "cyberfw"

    def test_linux_honours_xdg_data_home(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(resources.sys, "platform", "linux")
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))

        assert resources.user_data_dir() == tmp_path / "xdg" / "cyberfw"

    def test_linux_falls_back_to_local_share(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(resources.sys, "platform", "linux")
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        monkeypatch.setattr(resources.Path, "home", classmethod(lambda cls: tmp_path))

        assert resources.user_data_dir() == tmp_path / ".local" / "share" / "cyberfw"


class TestWorkspaceRoot:
    def test_a_directory_with_a_registry_is_a_workspace(self, tmp_path: Path) -> None:
        (tmp_path / "registry.yaml").write_text("{}\n", encoding="utf-8")
        assert resources.workspace_root(tmp_path) == tmp_path

    def test_anything_else_is_not(self, tmp_path: Path) -> None:
        assert resources.workspace_root(tmp_path) is None


class TestPackagedData:
    def test_missing_data_dir_yields_none(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(resources, "files", lambda package: tmp_path / "pkg")
        assert resources.packaged_data("registry.yaml") is None

    def test_existing_file_is_returned_as_a_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        data = tmp_path / "pkg" / "data"
        data.mkdir(parents=True)
        (data / "registry.yaml").write_text("{}\n", encoding="utf-8")
        monkeypatch.setattr(resources, "files", lambda package: tmp_path / "pkg")

        assert resources.packaged_data("registry.yaml") == data / "registry.yaml"

    def test_source_checkout_has_no_packaged_copy_but_the_repo_root_does(self) -> None:
        """In a checkout the data lives at the repo root; the wheel gets it via force-include."""
        repo_root = Path(__file__).resolve().parents[2]
        assert (repo_root / "registry.yaml").is_file()
        assert (repo_root / "pipelines").is_dir()
        assert resources.packaged_data("registry.yaml") is None
