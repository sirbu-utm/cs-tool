"""Custom exception hierarchy for cyberfw.

Every failure mode the framework can hit (platform mismatch, tool missing,
network trouble, bad output, unsafe archive) maps to a dedicated exception so
callers can react precisely instead of catching bare ``OSError``/``ValueError``.
"""

from __future__ import annotations

from collections.abc import Sequence

__all__ = [
    "CyberfwError",
    "ConfigError",
    "RegistryError",
    "ToolNotFoundError",
    "UnsupportedPlatformError",
    "DownloadError",
    "ChecksumError",
    "ArchiveSafetyError",
    "ExecutionError",
    "ParseError",
    "ContextStoreError",
    "ReportError",
]


class CyberfwError(Exception):
    """Base class for all framework errors."""


class ConfigError(CyberfwError):
    """Invalid or unreadable configuration."""


class RegistryError(CyberfwError):
    """Malformed or missing tool registry (``registry.yaml``)."""


class ToolNotFoundError(CyberfwError):
    """Requested tool is not present in ``tools_bin`` or the registry."""


class UnsupportedPlatformError(CyberfwError):
    """A tool offers no asset for the current OS/arch combination."""


class DownloadError(CyberfwError):
    """Downloading a release asset from GitHub failed."""


class ChecksumError(CyberfwError):
    """SHA-256 verification failed for a downloaded archive."""


class ChromiumUnsupportedError(CyberfwError):
    """Chrome for Testing publishes no portable build for the current OS/arch."""


class ArchiveSafetyError(CyberfwError):
    """An archive tried to write outside the extraction directory (Zip Slip)."""


class ExecutionError(CyberfwError):
    """An external tool ran but failed (non-zero exit, crash, OOM)."""

    def __init__(self, message: str, *, exit_code: int | None = None, stderr_tail: Sequence[str] | None = None) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr_tail = list(stderr_tail or [])


class ParseError(CyberfwError):
    """A single output line could not be parsed into a typed record."""


class ContextStoreError(CyberfwError):
    """Reading or writing the JSONL context store failed."""


class ReportError(CyberfwError):
    """Generation of an HTML/JSON report failed."""
