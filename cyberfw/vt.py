"""VirusTotal API v3 client, key resolution and reputation parsing.

The ``vt`` command and (later) the pipeline's reputation enrichment query
VirusTotal's public API with the *user's own* key (free tier: 500 lookups/day,
4/min). The key is never put in argv or logs — it travels in the ``x-apikey``
header and is resolved from, in order:

1. an explicit value (``--api-key`` / ``CYBERFW_VT_API_KEY`` setting),
2. the ``VT_API_KEY`` / ``VTCLI_APIKEY`` environment variables,
3. the official ``vt`` CLI config at ``~/.vt.toml`` (its ``apikey`` line).

When none is found and the console is interactive, :func:`resolve_or_prompt`
shows a short guide and asks for the key once, saving it to the workspace
``.env`` so later runs pick it up automatically. In a non-interactive run (the
bot's subprocess, CI, a pipe) it never prompts — enrichment is simply skipped.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

__all__ = [
    "VtError",
    "Reputation",
    "resolve_api_key",
    "resolve_or_prompt",
    "remember_prompt",
    "classify_target",
    "parse_reputation",
    "lookup",
    "enrich",
    "enrichment_targets",
    "API_KEY_URL",
    "GUIDE",
    "PROMPTED_VAR",
]

_API = "https://www.virustotal.com/api/v3"
_GUI = "https://www.virustotal.com/gui"
API_KEY_URL = "https://www.virustotal.com/gui/my-apikey"
#: Marker written to ``.env`` once the console has offered to save a key, so a
#: default (not ``--vt``) run asks only the first time, never on every scan.
PROMPTED_VAR = "CYBERFW_VT_PROMPTED"

GUIDE = (
    "VirusTotal API key not found.\n"
    "Get a free one (free tier: 500 lookups/day, 4/min):\n"
    "  1. Sign up / log in:  https://www.virustotal.com/gui/join-us\n"
    f"  2. Copy your API key: {API_KEY_URL}\n"
    "  3. Paste it below (or leave empty to skip VirusTotal)."
)

_HEX_HASH = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
    r"\.[A-Za-z]{2,63}$"
)


class VtError(RuntimeError):
    """A VirusTotal request failed (bad key, rate limit, network, bad target)."""


@dataclass
class Reputation:
    """A target's VirusTotal reputation, normalised for reports and messages."""

    target: str
    kind: str  # domain | ip | url | file
    found: bool
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int = 0
    categories: list[str] = field(default_factory=list)
    permalink: str = ""

    @property
    def flagged(self) -> bool:
        """True when any engine called it malicious or suspicious."""
        return bool(self.malicious or self.suspicious)

    def as_record(self) -> dict[str, Any]:
        """A JSONL row for the pipeline's reputation stage (Phase 2)."""
        return {
            "target": self.target,
            "vt_kind": self.kind,
            "found": self.found,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "harmless": self.harmless,
            "undetected": self.undetected,
            "reputation": self.reputation,
            "categories": self.categories,
            "permalink": self.permalink,
        }


# -- key resolution --------------------------------------------------------------
def _read_vt_toml(home: Path | None = None) -> str | None:
    """The ``apikey`` from the official vt CLI's ``~/.vt.toml``, if present."""
    path = (home or Path.home()) / ".vt.toml"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r'(?m)^\s*apikey\s*=\s*["\']?([A-Za-z0-9]+)["\']?', text)
    return match.group(1) if match else None


def resolve_api_key(
    explicit: str | None = None,
    *,
    environ: dict[str, str] | None = None,
    home: Path | None = None,
) -> str | None:
    """Find a VirusTotal key without prompting. ``None`` when nowhere set."""
    env = os.environ if environ is None else environ
    candidates = (
        explicit,
        env.get("CYBERFW_VT_API_KEY"),
        env.get("VT_API_KEY"),
        env.get("VTCLI_APIKEY"),
    )
    for value in candidates:
        if value and value.strip():
            return value.strip()
    return _read_vt_toml(home)


def _set_env_var(env_path: Path, name: str, value: str) -> None:
    """Add or replace ``name=value`` in ``env_path`` (best-effort, chmod 600)."""
    line = f"{name}={value}"
    try:
        existing = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
        if re.search(rf"(?m)^{re.escape(name)}=", existing):
            new = re.sub(rf"(?m)^{re.escape(name)}=.*$", line, existing)
        else:
            new = existing + ("" if existing.endswith("\n") or not existing else "\n") + line + "\n"
        env_path.parent.mkdir(parents=True, exist_ok=True)
        env_path.write_text(new, encoding="utf-8")
        try:
            env_path.chmod(0o600)
        except OSError:
            pass
    except OSError:
        pass


def _persist_to_env(env_path: Path, key: str) -> None:
    """Add or replace ``CYBERFW_VT_API_KEY`` in ``env_path``."""
    _set_env_var(env_path, "CYBERFW_VT_API_KEY", key)


def remember_prompt(env_path: Path) -> None:
    """Record in ``.env`` that the console has already offered to save a key.

    A default pipeline run reads this back (as the ``vt_prompted`` setting) and
    skips the prompt, so VirusTotal is offered once, not before every scan.
    """
    _set_env_var(env_path, PROMPTED_VAR, "1")


def resolve_or_prompt(
    explicit: str | None = None,
    *,
    interactive: bool,
    env_path: Path | None = None,
    environ: dict[str, str] | None = None,
) -> str | None:
    """Resolve a key; if none and ``interactive``, show the guide and ask once.

    A non-interactive caller (the bot, CI, a pipe) never prompts — it gets the
    resolved key or ``None`` and the caller skips VirusTotal.
    """
    key = resolve_api_key(explicit, environ=environ)
    if key or not interactive:
        return key
    print(GUIDE)
    try:
        entered = input("VirusTotal API key: ").strip()
    except EOFError:
        return None
    if not entered:
        return None
    if env_path is not None:
        _persist_to_env(env_path, entered)
    return entered


# -- target classification & parsing ---------------------------------------------
def classify_target(target: str) -> tuple[str, str, str, str]:
    """Return ``(kind, api_path, gui_kind, ident)`` for a VT lookup.

    Raises :class:`VtError` for something VirusTotal cannot look up.
    """
    t = target.strip()
    if not t:
        raise VtError("empty target")
    try:
        ipaddress.ip_address(t)
    except ValueError:
        pass
    else:
        return ("ip", f"ip_addresses/{t}", "ip-address", t)
    if t.lower().startswith(("http://", "https://")):
        ident = base64.urlsafe_b64encode(t.encode("utf-8")).decode("ascii").rstrip("=")
        return ("url", f"urls/{ident}", "url", ident)
    if _HEX_HASH.match(t):
        return ("file", f"files/{t}", "file", t.lower())
    if _HOSTNAME.match(t):
        return ("domain", f"domains/{t}", "domain", t)
    raise VtError(f"{target!r} is not a domain, IP, URL or file hash")


def parse_reputation(target: str, kind: str, gui_kind: str, ident: str, attributes: dict[str, Any]) -> Reputation:
    """Fold a VT ``data.attributes`` object into a :class:`Reputation`."""
    stats = attributes.get("last_analysis_stats") or {}
    cats = attributes.get("categories")
    categories = sorted({str(v) for v in cats.values()}) if isinstance(cats, dict) else []
    return Reputation(
        target=target,
        kind=kind,
        found=True,
        malicious=int(stats.get("malicious", 0) or 0),
        suspicious=int(stats.get("suspicious", 0) or 0),
        harmless=int(stats.get("harmless", 0) or 0),
        undetected=int(stats.get("undetected", 0) or 0),
        reputation=int(attributes.get("reputation", 0) or 0),
        categories=categories,
        permalink=f"{_GUI}/{gui_kind}/{ident}",
    )


# -- the request -----------------------------------------------------------------
async def lookup(client: httpx.AsyncClient, api_key: str, target: str) -> Reputation:
    """Query VirusTotal for one target. A 404 is a valid 'not seen' result."""
    kind, path, gui_kind, ident = classify_target(target)
    try:
        resp = await client.get(
            f"{_API}/{path}", headers={"x-apikey": api_key, "accept": "application/json"}
        )
    except httpx.HTTPError as exc:
        raise VtError(f"VirusTotal request failed: {exc}") from exc
    if resp.status_code == 404:
        return Reputation(target=target, kind=kind, found=False,
                          permalink=f"{_GUI}/{gui_kind}/{ident}")
    if resp.status_code in (401, 403):
        raise VtError("VirusTotal rejected the API key (401/403)")
    if resp.status_code == 429:
        raise VtError("VirusTotal rate limit hit (429) — free tier is 4/min, 500/day")
    if resp.status_code >= 400:
        raise VtError(f"VirusTotal returned HTTP {resp.status_code}")
    attributes = (resp.json().get("data") or {}).get("attributes") or {}
    return parse_reputation(target, kind, gui_kind, ident, attributes)


def enrichment_targets(records: Iterable[Any]) -> list[str]:
    """Unique VT-lookable targets (domains / IPs / URLs) from a run's records.

    Reads each record's ``.target``; keeps only what :func:`classify_target`
    accepts (so ``host:port`` and the like are dropped), preserving order.
    """
    seen: set[str] = set()
    out: list[str] = []
    for record in records:
        target = (getattr(record, "target", "") or "").strip()
        if not target or target in seen:
            continue
        try:
            classify_target(target)
        except VtError:
            continue
        seen.add(target)
        out.append(target)
    return out


async def enrich(
    targets: list[str],
    api_key: str,
    limit: int = 20,
    per_minute: int = 4,
    *,
    client: httpx.AsyncClient | None = None,
) -> list[Reputation]:
    """Look up up to ``limit`` targets, throttled to ``per_minute`` (VT free = 4).

    One target's failure (rate limit, bad response) is skipped, not fatal.
    """
    gap = 60.0 / max(1, per_minute)
    own = client is None
    client = client or httpx.AsyncClient(timeout=30.0)
    out: list[Reputation] = []
    try:
        for index, target in enumerate(targets[:limit]):
            if index:
                await asyncio.sleep(gap)
            try:
                out.append(await lookup(client, api_key, target))
            except VtError:
                continue
    finally:
        if own:
            await client.aclose()
    return out
