"""Environment-driven configuration for the bot.

Everything the bot needs to run is read from environment variables (a ``.env``
file is loaded if ``python-dotenv`` is installed). Nothing here is secret at
rest except the token, which is never logged or persisted.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["BotConfig", "ConfigError", "load_config"]


class ConfigError(RuntimeError):
    """A required setting is missing or malformed."""


def _load_dotenv() -> None:
    """Best-effort ``.env`` loading; a no-op when python-dotenv is absent."""
    try:
        from dotenv import load_dotenv
    except ModuleNotFoundError:
        return
    load_dotenv()


def _parse_ids(raw: str) -> frozenset[int]:
    ids: set[int] = set()
    for token in raw.replace(",", " ").split():
        try:
            ids.add(int(token))
        except ValueError as exc:
            raise ConfigError(f"ALLOWED_USER_IDS holds a non-numeric id: {token!r}") from exc
    return frozenset(ids)


@dataclass(frozen=True)
class BotConfig:
    """Resolved runtime settings.

    .. attribute:: token
       Telegram bot token (``BOT_TOKEN``).

    .. attribute:: allowed_user_ids
       Telegram numeric user ids permitted to run scans. **Empty means nobody**
       — the bot fails closed so an unconfigured deployment never scans for a
       stranger.

    .. attribute:: cyberfw_cmd
       The argv prefix that invokes the CLI, e.g. ``["cyberfw"]`` or
       ``["uv", "run", "cyberfw"]``. Split on spaces from ``CYBERFW_CMD``.

    .. attribute:: workspace
       Directory cyberfw runs in — the one holding ``registry.yaml`` and
       ``tools_bin/``; its ``reports/`` is where the JSON reports land.
    """

    token: str
    allowed_user_ids: frozenset[int]
    cyberfw_cmd: tuple[str, ...]
    workspace: Path
    db_path: Path
    pipeline: str = "recon-to-vuln"
    max_concurrent: int = 2
    scan_timeout_s: float = 1800.0
    stage_timeout_s: float = 600.0
    block_private: bool = True
    max_findings_in_message: int = 10
    extra_pipeline_args: tuple[str, ...] = field(default_factory=tuple)
    log_path: Path | None = None

    @property
    def reports_dir(self) -> Path:
        return self.workspace / "reports"


def load_config(environ: dict[str, str] | None = None) -> BotConfig:
    """Build a :class:`BotConfig` from the environment, validating as we go."""
    if environ is None:
        _load_dotenv()
        environ = dict(os.environ)

    token = environ.get("BOT_TOKEN", "").strip()
    if not token:
        raise ConfigError("BOT_TOKEN is required (get one from @BotFather).")

    workspace = Path(environ.get("CYBERFW_WORKSPACE", ".")).expanduser().resolve()
    if not (workspace / "registry.yaml").is_file():
        raise ConfigError(
            f"CYBERFW_WORKSPACE={workspace} has no registry.yaml; point it at the CS-TOOL checkout."
        )

    cmd = tuple(environ.get("CYBERFW_CMD", "cyberfw").split()) or ("cyberfw",)
    db_path = Path(environ.get("BOT_DB", workspace / "bot-scans.sqlite3")).expanduser()
    log_path = Path(environ.get("BOT_LOG", workspace / "logs" / "bot.log")).expanduser()

    return BotConfig(
        token=token,
        allowed_user_ids=_parse_ids(environ.get("ALLOWED_USER_IDS", "")),
        cyberfw_cmd=cmd,
        workspace=workspace,
        db_path=db_path,
        pipeline=environ.get("BOT_PIPELINE", "recon-to-vuln").strip() or "recon-to-vuln",
        max_concurrent=int(environ.get("BOT_MAX_CONCURRENT", "2")),
        scan_timeout_s=float(environ.get("BOT_SCAN_TIMEOUT", "1800")),
        stage_timeout_s=float(environ.get("BOT_STAGE_TIMEOUT", "600")),
        block_private=environ.get("BOT_BLOCK_PRIVATE", "true").lower() not in {"0", "false", "no"},
        max_findings_in_message=int(environ.get("BOT_MAX_FINDINGS", "10")),
        extra_pipeline_args=tuple(environ.get("BOT_EXTRA_PIPELINE_ARGS", "").split()),
        log_path=log_path,
    )
