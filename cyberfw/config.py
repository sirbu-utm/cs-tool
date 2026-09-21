"""Configuration layer for cyberfw.

Loads settings from environment variables (``CYBERFW_*``) merged over a
``config.local.yaml`` file using ``pydantic-settings`` — a single consistent
source of truth for the whole framework.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["Settings", "load_settings"]


class Settings(BaseSettings):
    """Runtime configuration for the framework.

    Attribute precedence (highest first):

    1. ``CYBERFW_*`` environment variables
    2. ``config.local.yaml`` (gitignored, machine-specific)
    3. defaults below
    """

    model_config = SettingsConfigDict(
        env_prefix="CYBERFW_",
        env_file=".env",
        extra="ignore",
        validate_assignment=True,
    )

    # Directories.
    root_dir: Path = Field(default_factory=lambda: Path.cwd())
    tools_dir: Path = Field(default=Path("tools_bin"))
    reports_dir: Path = Field(default=Path("reports"))
    logs_dir: Path = Field(default=Path("logs"))
    pipelines_dir: Path = Field(
        default=Path("pipelines"), description="Directory of user-defined <name>.yaml pipelines."
    )
    cache_dir: Path = Field(default=Path.home() / ".cache" / "cyberfw")
    # Remote behaviour.
    github_token: str | None = Field(default=None, exclude=True)
    github_rate_fallback: bool = Field(default=True, description="Cache GitHub API responses to save rate limit.")
    # Pipeline behaviour.
    concurrency: int = Field(default=4, ge=1, description="Max parallel jobs across pipeline stages.")
    request_timeout: float = Field(
        default=60.0,
        gt=0,
        description="Network timeout (seconds) for GitHub API calls and asset downloads. Applies to each "
        "connect/read/write operation, not to the whole transfer, so a slow-but-alive download is not cut off.",
    )
    stage_timeout: float | None = Field(
        default=None,
        gt=0,
        description="Max seconds one tool process may run before it is stopped and the stage "
        "fails (each fan-out target is its own process). Unset = no limit.",
    )
    wordlist: str | None = Field(default=None, description="Custom fuzz wordlist path for Ffuf.")
    parse: bool = Field(
        default=True,
        description="Validate tool stdout against Pydantic schemas. Set false (or pass --no-parse) "
        "to stream every raw stdout/stderr line exactly as the tool prints it.",
    )
    # Logging.
    log_level: str = Field(default="INFO", description="Console/file log level (DEBUG/INFO/WARNING/ERROR).")
    log_to_file: bool = Field(default=True, description="Also write diagnostics to logs/cyberfw.log.")
    # Security.
    max_archive_size: int = Field(
        default=512 * 1024 * 1024,
        gt=0,
        description="Largest size (bytes) a downloaded tool archive may extract to.",
    )

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalise_log_level(cls, value: object) -> str:
        """Accept case-insensitive level names; reject unknown ones early."""
        name = str(value).upper()
        if isinstance(logging.getLevelName(name), int):
            return name
        raise ValueError(f"invalid log_level {value!r}; use DEBUG/INFO/WARNING/ERROR")

    @model_validator(mode="after")
    def _make_dirs_absolute(self) -> Settings:
        """Resolve relative paths against ``root_dir`` (the CWD)."""
        for name in ("tools_dir", "reports_dir", "logs_dir", "pipelines_dir"):
            value: Path = getattr(self, name)
            if not value.is_absolute():
                setattr(self, name, (self.root_dir / value).resolve())
        return self

    def ensure_dirs(self) -> None:
        """Create all directories referenced by the settings."""
        for name in ("tools_dir", "reports_dir", "logs_dir", "cache_dir"):
            getattr(self, name).mkdir(parents=True, exist_ok=True)


def load_settings(root_dir: Path | None = None, local_file: Path | None = None) -> Settings:
    """Build settings, merging an optional ``config.local.yaml`` override.

    YAML fields are injected as extra kwargs so pydantic-settings treats them
    with the same precedence as their ``CYBERFW_*`` alternatives — YAML beats
    code defaults, environment beats YAML.
    """
    cwd = root_dir or Path.cwd()
    candidate = local_file or cwd / "config.local.yaml"
    if candidate.exists():
        try:
            loaded = yaml.safe_load(candidate.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                raw = loaded
            else:
                raw = {}
        except yaml.YAMLError:  # pragma: no cover - defensive
            raw = {}
    else:
        raw = {}
    # Environment beats YAML; YAML beats file defaults.
    patches: dict[str, Any] = {}
    for key, value in raw.items():
        if key not in Settings.model_fields:
            continue
        if f"CYBERFW_{key.upper()}" in os.environ:
            continue
        patches[key] = value
    # Construct (not ``model_copy(update=...)``, which skips validation) so the
    # YAML values pass through the same field/model validators as kwargs do.
    return Settings(**{"root_dir": cwd, **patches})
