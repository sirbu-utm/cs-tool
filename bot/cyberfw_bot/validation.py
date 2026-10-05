"""Target validation — the gate between a chat message and an active scan.

A scan is intrusive, so a target is accepted only when it is unambiguously a
single host the user typed: a domain name, an ``http(s)`` URL, or an IP address.
Everything else is refused with a reason. In particular this refuses:

* shell/argument metacharacters and whitespace (defence in depth — the runner
  never uses a shell, but a value must not look like a flag either);
* a leading ``-`` (argument injection into the downstream tool's argv);
* by default, loopback / private / link-local addresses and ``localhost`` (an
  SSRF-style pivot to internal infrastructure), unless ``block_private`` is off.

Only the literal target is inspected; DNS is not resolved, so a public name that
resolves to a private address is out of scope — documented in the README.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

__all__ = ["ValidationError", "validate_target", "suggest_target"]


class ValidationError(ValueError):
    """The target is not a single, safe, user-authorised host."""


#: RFC 1123 host label, joined into a dotted name with a non-numeric TLD.
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
    r"\.[A-Za-z]{2,63}$"
)


def _reject_private_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        raise ValidationError(
            f"{ip} is a private/loopback address; scanning internal ranges is blocked "
            "(set BOT_BLOCK_PRIVATE=false to allow it deliberately)."
        )


def _host_from(target: str) -> str:
    """The bare host of a URL, or the target itself when it is not a URL."""
    if "://" in target:
        parts = urlsplit(target)
        if parts.scheme not in {"http", "https"}:
            raise ValidationError(f"only http/https URLs are accepted, not {parts.scheme!r}.")
        if not parts.hostname:
            raise ValidationError("the URL has no host.")
        return parts.hostname
    return target


def validate_target(raw: str, *, block_private: bool = True) -> str:
    """Return the cleaned target, or raise :class:`ValidationError`.

    The returned string is exactly what should be passed to
    ``cyberfw ... --target``: the user's input, trimmed, once it is proven to be
    a single domain, ``http(s)`` URL, or IP address.
    """
    target = raw.strip()
    if not target:
        raise ValidationError("no target given. Usage: /scan <domain|url|ip>")
    if len(target) > 253:
        raise ValidationError("target is too long to be a single host.")
    if target[0] == "-":
        raise ValidationError("target must not start with '-'.")
    # No shell is ever involved (the runner uses exec form), so URL-legal
    # punctuation is harmless data. Whitespace and control characters, though,
    # never belong in a single host and could break argv/logging — reject them,
    # and let the strict host check below refuse metacharacters in a bare host.
    if any(ch.isspace() or ord(ch) < 0x20 for ch in target):
        raise ValidationError("target must not contain whitespace or control characters.")

    host = _host_from(target)

    # An IP literal (bare, or the host of a URL) is checked as an address.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if block_private:
            _reject_private_ip(ip)
        return target

    if host.lower() in {"localhost", "localhost.localdomain"}:
        if block_private:
            raise ValidationError("localhost is blocked (set BOT_BLOCK_PRIVATE=false to allow).")
        return target

    if not _HOSTNAME.match(host):
        raise ValidationError(
            f"{host!r} is not a valid domain, URL or IP. Give one host, e.g. example.com."
        )
    return target


def suggest_target(text: str, *, block_private: bool = True) -> str | None:
    """Return the first whitespace-separated token that is a valid scan target.

    ``None`` when the text holds no plausible single host. Used to turn a mistyped
    or plain message (``example.com`` or ``scan example.com``) into a
    "did you mean ``/scan <host>``?" hint, reusing :func:`validate_target` so the
    suggestion can never be something a real ``/scan`` would reject.
    """
    for token in text.split():
        try:
            return validate_target(token, block_private=block_private)
        except ValidationError:
            continue
    return None
