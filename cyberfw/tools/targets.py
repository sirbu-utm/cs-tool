"""Turning what the user (or an upstream stage) supplies into what a tool accepts.

The framework is fed URLs everywhere — the seed a user pastes, httpx's live hosts,
nuclei's matches — but the port scanners take a host or an IP. naabu rejects a URL
outright (``no valid ipv4 or ipv6 targets were found``, exit 1), so the adapter for
a host-only tool normalises its targets here.
"""

from __future__ import annotations

from urllib.parse import urlsplit

__all__ = ["hostname_of"]


def hostname_of(target: str) -> str:
    """``https://999.md:8443/admin`` -> ``999.md``; a bare host is returned unchanged.

    ``urlsplit`` only recognises a netloc after ``//``, so a scheme-less
    ``192.0.2.10:8080`` (naabu's own ``target`` shape) would otherwise parse as
    ``scheme="192.0.2.10"`` and come back with its port. Anything that does not
    parse as a host is passed through untouched: letting the tool reject it with
    its own message beats mangling it here.
    """
    if not target.strip():
        return target
    try:
        parsed = urlsplit(target if "://" in target else f"//{target}")
        return parsed.hostname or target
    except ValueError:  # e.g. an invalid IPv6 literal
        return target
