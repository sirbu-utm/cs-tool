"""Subdomain takeover: a subdomain pointing at a third-party service that is no
longer there, which an attacker can re-register to serve content on your name.

A classic takeover is a dangling CNAME: ``blog.example.com`` still says
``CNAME myapp.herokuapp.com``, but the Heroku app was deleted. Anyone can now
create an app of that name and own ``blog.example.com`` — enough for phishing
that looks genuinely yours, cookie theft and bypass of same-site protections.

Detection is by DNS then a single HTTP read:

1. resolve each in-scope host's CNAME; keep only those pointing at a service we
   fingerprint (``*.github.io``, ``*.herokuapp.com``, ``*.s3.amazonaws.com``…);
2. for most of these the backing name is a wildcard that still resolves, so the
   "unclaimed" signal is the provider's own error page — one GET of the host,
   matched against the service's fingerprint string. A few services instead go
   NXDOMAIN when deleted (Azure, Elastic Beanstalk), checked over DNS only.

The GET lands on the *service's* edge (GitHub, Heroku…), not on the target's own
origin, and only for a host that already CNAMEs to that service — a handful at
most. Fingerprints are deliberately distinctive, to keep false positives low; a
match is reported as a finding shaped like nuclei's.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from fnmatch import fnmatch

import httpx

from cyberfw.pipeline.schemas import PostureFinding, ToolRecord
from cyberfw.posture.mail import DOH_PROVIDERS, DnsError
from cyberfw.tools.targets import hostname_of

__all__ = ["TOOL", "Service", "SERVICES", "candidates", "scan", "doh", "http_body"]

#: ``tool`` of the findings this check emits.
TOOL = "takeover"
_RTYPES = {"A": 1, "CNAME": 5}
_MAX_HOSTS = 300
_MAX_CONCURRENCY = 10
_BODY_BYTES = 60_000

#: A resolver ``(name, rtype) -> (dns_status, records)`` and an HTTP body reader.
Resolver = Callable[[str, str], Awaitable[tuple[int, list[str]]]]
Fetcher = Callable[[str], Awaitable[str]]


@dataclass(frozen=True)
class Service:
    """A third-party host and how to tell its resource is unclaimed."""

    name: str
    cnames: tuple[str, ...]  # fnmatch patterns a CNAME target may match
    #: Case-insensitive substrings of the provider's "nothing here" page.
    fingerprints: tuple[str, ...] = ()
    #: True when a deleted resource makes the host go NXDOMAIN (no error page).
    nxdomain: bool = False
    remediation: str = "Remove the DNS record, or re-claim the resource it points to."

    def matches(self, target: str) -> bool:
        return any(fnmatch(target, pattern) for pattern in self.cnames)


#: Curated from can-i-take-over-xyz — services confirmed vulnerable, with a
#: distinctive signal. HTTP-fingerprint ones first, NXDOMAIN-only ones last.
SERVICES: tuple[Service, ...] = (
    Service("GitHub Pages", ("*.github.io",),
            ("There isn't a GitHub Pages site here.",
             "For root URLs (like http://example.com/) you must provide an index.html file"),
            remediation="Remove the DNS record, or create the GitHub Pages site / add the custom domain."),
    Service("Heroku", ("*.herokuapp.com", "*.herokudns.com", "*.herokussl.com"),
            ("No such app", "herokucdn.com/error-pages/no-such-app.html"),
            remediation="Remove the DNS record, or re-create the Heroku app and add this domain."),
    Service("Amazon S3", ("*.s3.amazonaws.com", "*.s3-website*.amazonaws.com",
                          "*.s3.*.amazonaws.com", "*.s3-*.amazonaws.com"),
            ("NoSuchBucket", "The specified bucket does not exist"),
            remediation="Remove the DNS record, or re-create the S3 bucket of this name."),
    Service("Fastly", ("*.fastly.net",), ("Fastly error: unknown domain",)),
    Service("Pantheon", ("*.pantheonsite.io",),
            ("The gods are wise, but do not know of the site which you seek.",)),
    Service("Surge.sh", ("*.surge.sh",), ("project not found",)),
    Service("Shopify", ("*.myshopify.com",), ("Sorry, this shop is currently unavailable",)),
    Service("Tumblr", ("domains.tumblr.com",),
            ("Whatever you were looking for doesn't currently exist at this address.",)),
    Service("Bitbucket", ("*.bitbucket.io",), ("Repository not found",)),
    Service("Ghost", ("*.ghost.io",),
            ("The thing you were looking for is no longer here, or never was",)),
    Service("Zendesk", ("*.zendesk.com",), ("Help Center Closed",)),
    Service("Helpjuice", ("*.helpjuice.com",), ("We could not find what you're looking for.",)),
    Service("Help Scout", ("*.helpscoutdocs.com",), ("No settings were found for this company:",)),
    Service("Readme.io", ("*.readme.io",), ("Project doesnt exist... yet!",)),
    Service("Azure", ("*.azurewebsites.net", "*.cloudapp.net", "*.cloudapp.azure.com",
                      "*.trafficmanager.net", "*.blob.core.windows.net", "*.azureedge.net"),
            nxdomain=True,
            remediation="Remove the DNS record, or re-create the Azure resource of this name."),
    Service("AWS Elastic Beanstalk", ("*.elasticbeanstalk.com",), nxdomain=True,
            remediation="Remove the DNS record, or re-create the Elastic Beanstalk environment."),
)


@dataclass
class _Hit:
    host: str
    service: Service
    target: str
    evidence: str


def candidates(records: Iterable[ToolRecord]) -> list[str]:
    """In-scope hostnames worth a CNAME check — subdomains and probed hosts."""
    kinds = {"host", "http", "scan", "port"}
    seen: set[str] = set()
    out: list[str] = []
    for record in records:
        if record.kind not in kinds:
            continue
        host = hostname_of(record.target).strip().rstrip(".").lower()
        if not host or "." not in host or host in seen:
            continue
        try:  # a bare IP cannot be taken over this way
            ipaddress.ip_address(host)
        except ValueError:
            seen.add(host)
            out.append(host)
    return out


# -- DNS + HTTP primitives ---------------------------------------------------------
async def doh(client: httpx.AsyncClient, name: str, rtype: str) -> tuple[int, list[str]]:
    """``(dns_status, records)`` for ``name``/``rtype`` from the first DoH resolver.

    Unlike the mail check's helper this keeps the status, so NXDOMAIN (3) is told
    apart from "exists, no such record". Records are lower-cased, trailing dot
    stripped — ready for :meth:`Service.matches`.
    """
    errors: list[str] = []
    for url in DOH_PROVIDERS:
        try:
            resp = await client.get(
                url, params={"name": name, "type": rtype}, headers={"accept": "application/dns-json"}
            )
            resp.raise_for_status()
            payload = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(f"{url}: {exc}")
            continue
        status = payload.get("Status") if isinstance(payload, dict) else None
        if status not in (0, 3):  # transient (SERVFAIL…): try the next resolver
            errors.append(f"{url}: DNS status {status}")
            continue
        code = _RTYPES[rtype]
        records = [
            str(answer.get("data", "")).strip().rstrip(".").lower()
            for answer in payload.get("Answer") or []
            if isinstance(answer, dict) and answer.get("type") == code
        ]
        return int(status), records
    raise DnsError("; ".join(errors) or "no DNS-over-HTTPS resolver answered")


async def http_body(client: httpx.AsyncClient, host: str) -> str:
    """The body served at ``host`` (https, then http), for fingerprint matching."""
    for url in (f"https://{host}/", f"http://{host}/"):
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            continue
        return resp.text[:_BODY_BYTES]
    return ""


# -- the check ---------------------------------------------------------------------
def _match(targets: list[str]) -> tuple[Service | None, str]:
    for target in targets:
        for service in SERVICES:
            if service.matches(target):
                return service, target
    return None, ""


def _finding(hit: _Hit) -> PostureFinding:
    return PostureFinding.make(
        TOOL, "subdomain-takeover", f"https://{hit.host}",
        name=f"Subdomain takeover possible — {hit.service.name}",
        severity="high",
        description=(
            f"{hit.host} still points (CNAME) at {hit.target} on {hit.service.name}, but "
            f"{hit.evidence}. An attacker can register that resource and serve their own "
            f"content on {hit.host} — phishing under your name, cookie theft and bypass of "
            "same-site protections."
        ),
        remediation=hit.service.remediation,
        tags=["dns", "takeover"],
    )


async def _check(host: str, resolve: Resolver, fetch: Fetcher) -> _Hit | None:
    _status, cnames = await resolve(host, "CNAME")
    if not cnames:
        return None
    service, target = _match(cnames)
    if service is None:
        return None
    if service.fingerprints:
        body = await fetch(host)
        hit = next((fp for fp in service.fingerprints if fp.lower() in body.lower()), "")
        if hit:
            snippet = hit if len(hit) <= 60 else hit[:59] + "…"
            return _Hit(host, service, target, f'it returns the service\'s unclaimed-resource page ("{snippet}")')
    if service.nxdomain:
        status, records = await resolve(host, "A")
        if status == 3 and not records:  # the canonical target no longer exists
            return _Hit(host, service, target, "the target name no longer resolves (NXDOMAIN)")
    return None


async def scan(
    hosts: list[str],
    *,
    resolve: Resolver | None = None,
    fetch: Fetcher | None = None,
    client: httpx.AsyncClient | None = None,
    limit: int = _MAX_HOSTS,
) -> tuple[list[PostureFinding], list[str]]:
    """Check ``hosts`` for dangling CNAMEs; return ``(findings, notes)``.

    DNS being unreachable is reported in ``notes``, never raised — a posture
    check must not fail the scan.
    """
    targets = hosts[:limit]
    notes: list[str] = []
    if len(hosts) > limit:
        notes.append(f"subdomain-takeover check looked at the first {limit} of {len(hosts)} hosts")
    if not targets:
        return [], notes
    own = client is None
    client = client or httpx.AsyncClient(
        timeout=15.0, follow_redirects=True, headers={"User-Agent": "cyberfw"}
    )
    resolve = resolve or (lambda name, rtype: doh(client, name, rtype))
    fetch = fetch or (lambda host: http_body(client, host))
    gate = asyncio.Semaphore(_MAX_CONCURRENCY)

    async def guarded(host: str) -> _Hit | None | DnsError:
        async with gate:
            try:
                return await _check(host, resolve, fetch)
            except DnsError as exc:
                return exc

    try:
        results = await asyncio.gather(*(guarded(host) for host in targets))
    finally:
        if own:
            await client.aclose()
    hits = [r for r in results if isinstance(r, _Hit)]
    if not hits and any(isinstance(r, DnsError) for r in results):
        notes.append("subdomain-takeover check skipped — DNS-over-HTTPS unreachable")
    return [_finding(hit) for hit in hits], notes
