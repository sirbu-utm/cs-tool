"""TLS certificate health, read from httpx's ``-tls-grab`` data.

httpx already completes a TLS handshake with every live HTTPS host; with
``-tls-grab`` it also reports the certificate it was served. This module turns
those blocks into a certificate inventory (issuer, expiry, negotiated version)
and into findings an owner can act on:

* **expired** — browsers block the site outright (high);
* **expires soon** — the outage is already scheduled: medium inside
  :data:`URGENT_DAYS`, low inside :data:`SOON_DAYS`. nuclei has no check for
  this — its ``expired-ssl`` only fires once it is too late;
* **self-signed / untrusted** and **hostname mismatch** — visitors get a
  certificate warning (medium);
* **outdated protocol** — the best the server would negotiate is TLS 1.1 or
  older (medium).

No connection is made here: it only reads what the scan already collected. A
problem nuclei's own ``ssl/`` templates already reported for the same host is
not reported a second time.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone

from cyberfw.pipeline.schemas import HttpxResult, PostureFinding, ToolRecord
from cyberfw.tools.targets import hostname_of

__all__ = ["TOOL", "SOON_DAYS", "URGENT_DAYS", "Cert", "certificates", "findings"]

#: ``tool`` of the findings this check emits.
TOOL = "tlscheck"
#: A certificate running out within this many days is reported...
SOON_DAYS = 30
#: ...and within this many, as medium rather than low.
URGENT_DAYS = 7

_OLD_PROTOCOLS = {"ssl30": "SSL 3.0", "tls10": "TLS 1.0", "tls11": "TLS 1.1"}
_VERSION_NAMES = {"tls13": "TLS 1.3", "tls12": "TLS 1.2", **_OLD_PROTOCOLS}

#: Our check → nuclei ``ssl/`` templates that report the same problem.
_NUCLEI_TWINS = {
    "tls-cert-expired": {"expired-ssl"},
    "tls-cert-self-signed": {"self-signed-ssl", "untrusted-root-certificate"},
    "tls-cert-mismatch": {"mismatched-ssl-certificate"},
}


@dataclass(frozen=True)
class Cert:
    """The certificate one host:port served during the scan."""

    url: str
    host: str
    port: str
    subject: str
    sans: tuple[str, ...]
    issuer: str
    not_after: datetime | None
    version: str
    expired_flag: bool
    self_signed: bool
    mismatched: bool
    wildcard: bool

    def days_left(self, now: datetime) -> int | None:
        """Whole days until expiry (negative once expired); ``None`` if unknown."""
        if self.not_after is None:
            return None
        return math.floor((self.not_after - now).total_seconds() / 86400)

    def is_expired(self, now: datetime) -> bool:
        return self.expired_flag or (self.not_after is not None and self.not_after <= now)

    @property
    def version_name(self) -> str:
        return _VERSION_NAMES.get(self.version, self.version.upper() or "unknown")

    @property
    def old_protocol(self) -> bool:
        return self.version in _OLD_PROTOCOLS


def _parse_time(value: object) -> datetime | None:
    """httpx's ``2026-12-25T22:56:35Z`` (Python 3.10's fromisoformat rejects the Z)."""
    if not isinstance(value, str) or not value:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _cert(record: HttpxResult, tls: dict[str, object]) -> Cert:
    sans = tls.get("subject_an")
    issuer = tls.get("issuer_cn") or tls.get("issuer_dn") or ""
    return Cert(
        url=record.url or record.target,
        host=str(tls.get("host") or hostname_of(record.url or record.target)).lower(),
        port=str(tls.get("port") or "443"),
        subject=str(tls.get("subject_cn") or ""),
        sans=tuple(str(name) for name in sans) if isinstance(sans, list) else (),
        issuer=str(issuer),
        not_after=_parse_time(tls.get("not_after")),
        version=str(tls.get("tls_version") or "").lower(),
        expired_flag=tls.get("expired") is True,
        self_signed=tls.get("self_signed") is True,
        mismatched=tls.get("mismatched") is True,
        wildcard=tls.get("wildcard_certificate") is True,
    )


def certificates(records: Iterable[ToolRecord]) -> list[Cert]:
    """Certificates httpx saw, one per host:port (the first probe of each wins)."""
    seen: dict[tuple[str, str], Cert] = {}
    for record in records:
        if not isinstance(record, HttpxResult) or not isinstance(record.tls, dict):
            continue
        if record.tls.get("probe_status") is False:  # the handshake itself failed
            continue
        cert = _cert(record, record.tls)
        seen.setdefault((cert.host, cert.port), cert)
    return list(seen.values())


def _in_days(days: int) -> str:
    if days <= 0:
        return "today"
    return "in 1 day" if days == 1 else f"in {days} days"


def _problems(cert: Cert, now: datetime) -> Iterator[tuple[str, str, str, str, str]]:
    """``(check_id, severity, name, description, remediation)`` per problem."""
    days = cert.days_left(now)
    until = f" on {cert.not_after:%Y-%m-%d}" if cert.not_after else ""
    issuer = f" (issued by {cert.issuer})" if cert.issuer else ""
    renew = (
        "Renew the certificate and automate renewal (ACME / Let's Encrypt, or your "
        "provider's auto-renew), with an alert well before the expiry date."
    )
    if cert.is_expired(now):
        ago = f" {-days} day(s) ago" if days is not None and days < 0 else ""
        yield (
            "tls-cert-expired", "high", f"TLS certificate expired{ago}",
            f"The certificate for {cert.host}{issuer} expired{until}. Browsers block the "
            "site with a full-page warning and API clients refuse to connect.",
            renew,
        )
    elif days is not None and days <= SOON_DAYS:
        yield (
            "tls-cert-expiring", "medium" if days <= URGENT_DAYS else "low",
            f"TLS certificate expires {_in_days(days)}",
            f"The certificate for {cert.host}{issuer} runs out{until}. After that, "
            "browsers block the site and API clients refuse to connect.",
            renew,
        )
    if cert.self_signed:
        yield (
            "tls-cert-self-signed", "medium", "Self-signed or untrusted TLS certificate",
            f"{cert.host} serves a certificate browsers do not trust{issuer}. Visitors get "
            "a security warning, and users taught to click through it are easy to intercept.",
            "Serve a certificate from a publicly trusted CA (Let's Encrypt is free).",
        )
    if cert.mismatched:
        names = ", ".join(cert.sans[:3]) or cert.subject or "another name"
        yield (
            "tls-cert-mismatch", "medium", "TLS certificate does not match the host name",
            f"{cert.host} serves a certificate for {names}. Browsers show a warning; on a "
            "forgotten subdomain a mismatch can also mean the name points at a service you "
            "no longer control.",
            "Serve a certificate that covers this name — or remove the DNS record if the "
            "host is no longer in use.",
        )
    if cert.old_protocol:
        yield (
            "tls-old-protocol", "medium", f"Server negotiates only {cert.version_name}",
            f"The best protocol {cert.host} agreed to was {cert.version_name}: it has known "
            "weaknesses, modern browsers refuse it, and PCI DSS forbids it.",
            "Enable TLS 1.2 and 1.3; disable SSL 3.0, TLS 1.0 and TLS 1.1.",
        )


def findings(
    certs: Iterable[Cert], records: Iterable[ToolRecord], *, now: datetime | None = None
) -> list[PostureFinding]:
    """Findings for every certificate problem nuclei did not already report."""
    moment = now or datetime.now(timezone.utc)
    reported = {
        (str(getattr(r, "template_id", "")), hostname_of(r.target).lower())
        for r in records
        if r.kind == "vuln" and r.tool == "nuclei"
    }
    out: list[PostureFinding] = []
    for cert in certs:
        for check_id, severity, name, description, remediation in _problems(cert, moment):
            if any((twin, cert.host) in reported for twin in _NUCLEI_TWINS.get(check_id, ())):
                continue
            out.append(
                PostureFinding.make(
                    TOOL, check_id, cert.url, name=name, severity=severity,
                    description=description, remediation=remediation, tags=["tls"],
                )
            )
    return out
