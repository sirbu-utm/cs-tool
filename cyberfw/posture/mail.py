"""Can someone send email as this domain? SPF, DMARC and MX, over DNS-over-HTTPS.

Spoofed mail — a message whose visible From says ``ceo@your-domain`` — is
stopped by DMARC, not by SPF alone: SPF only vouches for the hidden envelope
sender, while DMARC ties the visible From to a passing SPF/DKIM check and tells
receivers what to do with mail that fails (``p=reject`` / ``quarantine``;
``p=none`` merely monitors). So the verdict hinges on DMARC:

* ``protected`` — DMARC rejects or quarantines every failing message;
* ``partial`` — enforced, but only for some messages (``pct`` < 100) or not for
  subdomains (``sp=none``);
* ``spoofable`` — no usable DMARC record, ``p=none``, or SPF ``+all`` (which
  lets anyone pass SPF *aligned* with the domain, defeating DMARC as well).

Lookups go to a public DNS-over-HTTPS resolver (Cloudflare, then Google): the
standard library cannot query TXT records, and DoH needs nothing beyond httpx.
Only the domain's public DNS is read; the target's own servers are never
contacted. DMARC is looked up on the domain and then on its parent domains —
DMARC's "organizational domain" fallback, approximated without a suffix list.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from collections.abc import Awaitable, Callable

import httpx

from cyberfw.pipeline.schemas import MailSecurity, PostureFinding
from cyberfw.tools.targets import hostname_of

__all__ = [
    "TOOL",
    "DOH_PROVIDERS",
    "DnsError",
    "Resolver",
    "mail_domain",
    "txt_text",
    "spf_all",
    "dmarc_tags",
    "assess",
    "check",
]

#: ``tool`` of the records this check emits.
TOOL = "mailcheck"
DOH_PROVIDERS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")
_RTYPES = {"TXT": 16, "MX": 15}
_POLICIES = ("none", "quarantine", "reject")
_ENFORCING = ("quarantine", "reject")

#: ``(name, rtype)`` → the answers' ``data`` strings. :func:`doh_query` in
#: production; tests pass a dict-backed fake.
Resolver = Callable[[str, str], Awaitable[list[str]]]

_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
_ESCAPE = re.compile(r"\\(\d{3}|.)")


class DnsError(RuntimeError):
    """No DNS-over-HTTPS resolver answered."""


# -- DNS --------------------------------------------------------------------------
async def doh_query(client: httpx.AsyncClient, name: str, rtype: str) -> list[str]:
    """Answers for ``name``/``rtype`` from the first DoH resolver that responds."""
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
        if status == 3:  # NXDOMAIN: the name does not exist, so it has no records
            return []
        if status != 0:
            errors.append(f"{url}: DNS status {status}")
            continue
        code = _RTYPES[rtype]
        return [
            str(answer.get("data", ""))
            for answer in payload.get("Answer") or []
            if isinstance(answer, dict) and answer.get("type") == code
        ]
    raise DnsError("; ".join(errors) or "no DNS-over-HTTPS resolver answered")


def _unescape(match: re.Match[str]) -> str:
    """``\\"`` → ``"``, ``\\\\`` → ``\\``, and the decimal ``\\DDD`` escapes of zone-file text."""
    token = match.group(1)
    return chr(int(token)) if token.isdigit() else token


def txt_text(data: str) -> str:
    """One TXT answer as text. Cloudflare quotes (and may split) the strings; Google does not."""
    parts = _QUOTED.findall(data)
    if not parts:
        return data.strip()
    return "".join(_ESCAPE.sub(_unescape, part) for part in parts)


def mail_domain(target: str) -> str | None:
    """The domain to check for a pipeline seed; ``None`` for an IP or a bare name."""
    host = hostname_of(target.strip()).strip().rstrip(".").lower()
    if "." not in host or "/" in host:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return None
    if host.startswith("www.") and host.count(".") >= 2:
        host = host[4:]
    return host


# -- parsing ------------------------------------------------------------------------
def _is_spf(text: str) -> bool:
    lowered = text.lower()
    return lowered == "v=spf1" or lowered.startswith("v=spf1 ")


def spf_all(record: str) -> str:
    """The record's ``all`` with its qualifier (``-all`` ``~all`` ``?all`` ``+all``), or ``""``."""
    for term in record.split()[1:]:
        lowered = term.lower()
        if lowered in ("all", "+all"):
            return "+all"
        if lowered in ("-all", "~all", "?all"):
            return lowered
    return ""


def _redirect(record: str) -> str:
    for term in record.split()[1:]:
        if term.lower().startswith("redirect="):
            return term.split("=", 1)[1].strip().rstrip(".")
    return ""


def dmarc_tags(record: str) -> dict[str, str]:
    """``v=DMARC1; p=reject; pct=50`` → ``{"v": "DMARC1", "p": "reject", "pct": "50"}``."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


def _mx_hosts(answers: list[str]) -> tuple[list[str], bool]:
    """MX hosts by preference, and whether the domain publishes a "null MX" (accepts no mail)."""
    entries: list[tuple[int, str]] = []
    null_mx = False
    for answer in answers:
        priority, _, host = answer.strip().partition(" ")
        host = host.strip().rstrip(".").lower()
        if not host:
            null_mx = True  # RFC 7505: "0 ." — this domain receives no mail
            continue
        entries.append((int(priority) if priority.isdigit() else 0, host))
    return [host for _, host in sorted(entries)], null_mx


# -- the verdict ----------------------------------------------------------------------
def assess(
    domain: str,
    *,
    mx: list[str],
    null_mx: bool,
    spf: list[str],
    spf_policy: str,
    dmarc: list[str],
    dmarc_domain: str,
) -> tuple[MailSecurity, list[PostureFinding]]:
    """Judge one domain from its looked-up records (pure — no DNS here)."""
    found: list[PostureFinding] = []

    def add(check_id: str, severity: str, name: str, description: str, remediation: str) -> None:
        found.append(
            PostureFinding.make(
                TOOL, check_id, domain, name=name, severity=severity,
                description=description, remediation=remediation, tags=["email"],
            )
        )

    sends_nothing = not mx or null_mx
    lockdown = (
        f" {domain} receives no mail (no MX), so if it sends none either, lock it down "
        "completely: `v=spf1 -all` and `v=DMARC1; p=reject`."
        if sends_nothing
        else ""
    )

    # SPF — who may send as the domain.
    if not spf:
        add("mail-spf-missing", "low", "No SPF record",
            f"{domain} publishes no SPF record, so receivers cannot tell its real mail "
            f"servers from anyone else's and DMARC has one check fewer to pass on.{lockdown}",
            "Publish one TXT record `v=spf1 <your senders> -all` (`v=spf1 -all` if the "
            "domain sends no mail).")
    elif len(spf) > 1:
        add("mail-spf-multiple", "medium", "Several SPF records — SPF fails for every message",
            f"{domain} publishes {len(spf)} SPF records. Receivers then treat SPF as a "
            "permanent error and every message fails it, legitimate mail included.",
            "Merge them into a single `v=spf1` record.")
    elif spf_policy == "+all":
        add("mail-spf-pass-all", "high", "SPF lets any server on the internet send as this domain",
            f"{domain}'s SPF record ends in `+all`: any server passes SPF for it, and that "
            "pass is aligned with the domain, so it defeats DMARC too.",
            "Replace `+all` with `-all` (or `~all`) and list your real senders.")
    elif spf_policy in ("?all", ""):
        add("mail-spf-weak", "low", "SPF does not reject unauthorised senders",
            f"{domain}'s SPF record ends in `{spf_policy or 'nothing'}` — mail from servers "
            "it does not list is not marked as failing.",
            "End the record with `-all` (or `~all`).")

    # DMARC — what receivers do with mail that fails.
    tags = dmarc_tags(dmarc[0]) if len(dmarc) == 1 else {}
    valid = bool(tags) and tags.get("v", "").upper() == "DMARC1"
    policy = tags.get("p", "").lower() if valid else ""
    if valid and policy not in _POLICIES:
        policy = "none"  # RFC 7489 §6.6.3: an invalid p is applied as "none"
    inherited = valid and dmarc_domain != domain
    subdomain_policy = tags.get("sp", "").lower() if valid else ""
    if subdomain_policy not in _POLICIES:
        subdomain_policy = policy
    effective = subdomain_policy if inherited else policy
    try:
        pct = max(0, min(100, int(tags.get("pct", "100"))))
    except ValueError:
        pct = 100

    if not dmarc:
        add("mail-dmarc-missing", "medium", "No DMARC record — the domain can be spoofed",
            f"There is no DMARC record for {domain}, so receivers get no instruction to "
            f"reject mail that forges it: phishing can arrive 'from' this domain.{lockdown}",
            f"Publish a TXT record at `_dmarc.{domain}`: start with `v=DMARC1; p=none; "
            "rua=mailto:<reports address>` to see who sends as you, then move to "
            "`p=quarantine` and `p=reject`.")
    elif not valid:
        add("mail-dmarc-invalid", "medium", "DMARC record is unusable — the domain can be spoofed",
            f"_dmarc.{dmarc_domain} holds {len(dmarc)} DMARC records or a malformed one, so "
            "receivers ignore DMARC for it altogether.",
            f"Keep exactly one TXT record at `_dmarc.{dmarc_domain}`, starting `v=DMARC1; p=`.")
    elif effective == "none":
        source = f" (inherited from {dmarc_domain})" if inherited else ""
        add("mail-dmarc-none", "medium", "DMARC policy is p=none — spoofed mail is still delivered",
            f"{domain}'s DMARC policy{source} is `none`: receivers only report forged mail "
            f"and still deliver it.{lockdown}",
            "Once the aggregate reports show all legitimate mail passing, move to "
            "`p=quarantine` and then `p=reject`.")
    else:
        if pct < 100:
            add("mail-dmarc-partial", "low", f"DMARC is enforced on only {pct}% of mail",
                f"{domain}'s DMARC record sets `pct={pct}`: the rest of the forged mail is "
                "treated as if the policy were one step weaker.",
                "Raise `pct` to 100 (or drop the tag).")
        if not inherited and policy in _ENFORCING and subdomain_policy == "none":
            add("mail-dmarc-subdomains-open", "low", "Subdomains can be spoofed (sp=none)",
                f"{domain} enforces DMARC, but `sp=none` leaves every subdomain "
                f"(billing.{domain}, say) open to forgery.",
                "Set `sp=quarantine` or `sp=reject`, or drop `sp` so subdomains inherit `p`.")

    spoofable = not valid or effective == "none" or spf_policy == "+all"
    partial = not spoofable and (
        pct < 100 or (not inherited and policy in _ENFORCING and subdomain_policy == "none")
    )
    record = MailSecurity(
        tool=TOOL,
        kind="mail",
        target=domain,
        domain=domain,
        verdict="spoofable" if spoofable else ("partial" if partial else "protected"),
        mx=mx,
        spf=spf[0] if len(spf) == 1 else " | ".join(spf),
        spf_all=spf_policy,
        dmarc=dmarc[0] if len(dmarc) == 1 else " | ".join(dmarc),
        dmarc_domain=dmarc_domain,
        dmarc_policy=policy,
        dmarc_subdomain_policy=subdomain_policy,
        dmarc_pct=pct,
    )
    return record, found


# -- the lookups -------------------------------------------------------------------------
async def _find_dmarc(resolve: Resolver, domain: str) -> tuple[str, list[str]]:
    """``(where, records)``: the domain's own DMARC, else its nearest parent's."""
    labels = domain.split(".")
    for start in range(len(labels) - 1):  # never the bare TLD
        name = ".".join(labels[start:])
        records = [
            text for text in map(txt_text, await resolve(f"_dmarc.{name}", "TXT"))
            if text.replace(" ", "").lower().startswith("v=dmarc1")
        ]
        if records:
            return name, records
    return "", []


async def _spf_policy(resolve: Resolver, records: list[str]) -> str:
    """The effective ``all`` of the domain's SPF, following up to 3 ``redirect=`` hops."""
    if len(records) != 1:
        return ""
    record = records[0]
    for _ in range(3):
        policy = spf_all(record)
        target = _redirect(record)
        if policy or not target:
            return policy
        found = [text for text in map(txt_text, await resolve(target, "TXT")) if _is_spf(text)]
        if len(found) != 1:
            return ""
        record = found[0]
    return spf_all(record)


async def _check(domain: str, resolve: Resolver) -> tuple[MailSecurity, list[PostureFinding]]:
    txt, mx_answers, (dmarc_domain, dmarc) = await asyncio.gather(
        resolve(domain, "TXT"), resolve(domain, "MX"), _find_dmarc(resolve, domain)
    )
    spf = [text for text in map(txt_text, txt) if _is_spf(text)]
    mx, null_mx = _mx_hosts(mx_answers)
    return assess(
        domain, mx=mx, null_mx=null_mx, spf=spf, spf_policy=await _spf_policy(resolve, spf),
        dmarc=dmarc, dmarc_domain=dmarc_domain,
    )


async def check(
    domain: str, *, resolve: Resolver | None = None, client: httpx.AsyncClient | None = None
) -> tuple[MailSecurity, list[PostureFinding]]:
    """Look up and judge ``domain``. Raises :class:`DnsError` if DNS is unreachable."""
    if resolve is not None:
        return await _check(domain, resolve)
    if client is not None:
        http = client
        return await _check(domain, lambda name, rtype: doh_query(http, name, rtype))
    async with httpx.AsyncClient(timeout=15.0) as own:
        return await _check(domain, lambda name, rtype: doh_query(own, name, rtype))
