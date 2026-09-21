"""Unit tests for pydantic-settings driven configuration."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from cyberfw.config import Settings, load_settings


class TestSettings:
    def test_defaults(self, tmp_path: Path) -> None:
        settings = Settings(root_dir=tmp_path)
        assert settings.cache_dir == Path.home() / ".cache" / "cyberfw"
        assert settings.concurrency == 4
        # New parsing / logging settings default to sensible values.
        assert settings.parse is True
        assert settings.log_level == "INFO"
        assert settings.log_to_file is True

    def test_relative_dirs_resolved_against_root(self, tmp_path: Path) -> None:
        settings = Settings(root_dir=tmp_path)
        # tools_dir defaults to "tools_bin" -> resolved against root_dir
        assert settings.tools_dir.is_absolute()
        assert str(settings.tools_dir).startswith(str(tmp_path))

    def test_ensure_dirs_creates_directories(self, tmp_path: Path) -> None:
        settings = Settings(root_dir=tmp_path, reports_dir=tmp_path / "reports", logs_dir=tmp_path / "logs")
        settings.ensure_dirs()
        assert (settings.reports_dir).is_dir()
        assert (settings.logs_dir).is_dir()

    def test_environment_overrides_yaml(self, tmp_path: Path, monkeypatch) -> None:
        yaml_file = tmp_path / "config.local.yaml"
        yaml_file.write_text("concurrency: 42\n", encoding="utf-8")
        monkeypatch.setenv("CYBERFW_CONCURRENCY", "7")
        settings = load_settings(root_dir=tmp_path, local_file=yaml_file)
        assert settings.concurrency == 7

    def test_yaml_relative_dir_is_resolved_and_validated(self, tmp_path: Path) -> None:
        """YAML overrides must go through the same validators as constructor kwargs."""
        yaml_file = tmp_path / "config.local.yaml"
        yaml_file.write_text("reports_dir: out\nlog_level: debug\n", encoding="utf-8")
        settings = load_settings(root_dir=tmp_path, local_file=yaml_file)
        assert settings.reports_dir == (tmp_path / "out").resolve()
        assert settings.log_level == "DEBUG"

    def test_yaml_invalid_value_is_rejected(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "config.local.yaml"
        yaml_file.write_text("concurrency: 0\n", encoding="utf-8")
        with pytest.raises(ValidationError):
            load_settings(root_dir=tmp_path, local_file=yaml_file)

    def test_yaml_beats_default(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "config.local.yaml"
        yaml_file.write_text("concurrency: 13\n", encoding="utf-8")
        settings = load_settings(root_dir=tmp_path, local_file=yaml_file)
        assert settings.concurrency == 13

    def test_unknown_yaml_keys_ignored(self, tmp_path: Path, monkeypatch) -> None:
        yaml_file = tmp_path / "config.local.yaml"
        yaml_file.write_text("not_a_setting: 1\n", encoding="utf-8")
        settings = load_settings(root_dir=tmp_path, local_file=yaml_file)
        assert not hasattr(settings, "not_a_setting")


    def test_parse_toggle_via_yaml(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "config.local.yaml"
        yaml_file.write_text("parse: false\n", encoding="utf-8")
        settings = load_settings(root_dir=tmp_path, local_file=yaml_file)
        assert settings.parse is False

    def test_log_level_is_case_insensitive(self, tmp_path: Path) -> None:
        assert Settings(root_dir=tmp_path, log_level="debug").log_level == "DEBUG"

    def test_invalid_log_level_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="invalid log_level"):
            Settings(root_dir=tmp_path, log_level="verbose")


class TestSettingsEnv:
    def test_env_prefix(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("CYBERFW_REQUEST_TIMEOUT", "12.5")
        settings = Settings(root_dir=tmp_path)
        assert settings.request_timeout == 12.5

    def test_parse_and_log_level_via_env(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("CYBERFW_PARSE", "false")
        monkeypatch.setenv("CYBERFW_LOG_LEVEL", "warning")
        settings = Settings(root_dir=tmp_path)
        assert settings.parse is False
        assert settings.log_level == "WARNING"


    def test_max_archive_size_via_env(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("CYBERFW_MAX_ARCHIVE_SIZE", "1024")
        assert Settings(root_dir=tmp_path).max_archive_size == 1024

    def test_zero_max_archive_size_rejected(self, tmp_path: Path) -> None:
        """A zero limit would reject every archive — misconfiguration, not a valid choice."""
        with pytest.raises(ValidationError):
            Settings(root_dir=tmp_path, max_archive_size=0)

    def test_stage_timeout_defaults_to_unlimited(self, tmp_path: Path) -> None:
        assert Settings(root_dir=tmp_path).stage_timeout is None

    def test_stage_timeout_via_env(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("CYBERFW_STAGE_TIMEOUT", "900")
        assert Settings(root_dir=tmp_path).stage_timeout == 900.0

    def test_zero_stage_timeout_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError):
            Settings(root_dir=tmp_path, stage_timeout=0)
