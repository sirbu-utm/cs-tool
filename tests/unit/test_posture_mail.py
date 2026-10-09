"""Email-spoofing posture: SPF / DMARC / MX parsing and the verdict (no live DNS)."""

from __future__ import annotations

import httpx
import pytest

from cyberfw.pipeline.schemas import MailSecurity, PostureFinding
from cyberfw.posture import mail

# Grabbed at import, before tests/conftest.py swaps mail.doh_query for an offline stub.
from cyberfw.posture.mail import doh_query as real_doh_query

Zone = dict[tuple[str, str], list[str]]


def _resolver(zone: Zone) -> mail.Resolver:
    async def resolve(name: str, rtype: str) -> list[str]:
        return zone.get((name, rtype), [])

    return resolve


async def _check(domain: str, zone: Zone) -> tuple[MailSecurity, dict[str, str]]:
    record, found = await mail.check(domain, resolve=_resolver(zone))
    return record, {f.template_id: f.severity for f in found}


# -- parsing ----------------------------------------------------------------------------
def test_txt_text_handles_cloudflare_and_google_shapes() -> None:
    assert mail.txt_text('"v=spf1 -all"') == "v=spf1 -all"  # Cloudflare: quoted
    assert mail.txt_text('"v=spf1 include:_spf.example.net " "~all"') == "v=spf1 include:_spf.example.net ~all"
    assert mail.txt_text(r'"say \"hi\" \059 ok"') == 'say "hi" ; ok'  # escapes, incl. \DDD
    assert mail.txt_text("v=spf1 ~all") == "v=spf1 ~all"  # Google: unquoted


def test_mail_domain_from_a_seed() -> None:
    assert mail.mail_domain("https://www.Example.com/login") == "example.com"
    assert mail.mail_domain("app.example.com:8443") == "app.example.com"
    assert mail.mail_domain("93.184.216.34") is None
    assert mail.mail_domain("localhost") is None


def test_spf_all_and_dmarc_tags() -> None:
    assert mail.spf_all("v=spf1 include:x -all") == "-all"
    assert mail.spf_all("v=spf1 a mx all") == "+all"  # a bare all means +all
    assert mail.spf_all("v=spf1 a mx") == ""
    assert mail.dmarc_tags("v=DMARC1; p=reject; pct=50 ;rua=mailto:x@y") == {
        "v": "DMARC1", "p": "reject", "pct": "50", "rua": "mailto:x@y",
    }


# -- verdicts ---------------------------------------------------------------------------
async def test_locked_down_domain_is_protected() -> None:
    record, found = await _check("example.com", {
        ("example.com", "TXT"): ['"v=spf1 -all"', '"some-verification-token"'],
        ("example.com", "MX"): ["0 ."],
        ("_dmarc.example.com", "TXT"): ['"v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s"'],
    })
    assert record.verdict == "protected" and found == {}
    assert record.spf == "v=spf1 -all" and record.dmarc_policy == "reject" and record.mx == []


async def test_missing_dmarc_means_spoofable() -> None:
    record, found = await _check("shop.test", {
        ("shop.test", "TXT"): ['"v=spf1 include:_spf.mailhost.test ~all"'],
        ("shop.test", "MX"): ["20 backup.mailhost.test.", "10 mx.mailhost.test."],
    })
    assert record.verdict == "spoofable"
    assert found == {"mail-dmarc-missing": "medium"}  # ~all is fine next to DMARC
    assert record.mx == ["mx.mailhost.test", "backup.mailhost.test"]  # by preference


async def test_monitor_only_dmarc_is_spoofable() -> None:
    record, found = await _check("shop.test", {
        ("shop.test", "TXT"): ['"v=spf1 mx -all"'],
        ("_dmarc.shop.test", "TXT"): ['"v=DMARC1; p=none; rua=mailto:dmarc@shop.test"'],
    })
    assert record.verdict == "spoofable" and found == {"mail-dmarc-none": "medium"}


async def test_partial_enforcement() -> None:
    record, found = await _check("shop.test", {
        ("shop.test", "TXT"): ['"v=spf1 mx -all"'],
        ("_dmarc.shop.test", "TXT"): ['"v=DMARC1; p=reject; sp=none; pct=50"'],
    })
    assert record.verdict == "partial"
    assert found == {"mail-dmarc-partial": "low", "mail-dmarc-subdomains-open": "low"}
    assert record.dmarc_pct == 50 and record.dmarc_subdomain_policy == "none"


async def test_spf_plus_all_defeats_even_a_reject_policy() -> None:
    record, found = await _check("shop.test", {
        ("shop.test", "TXT"): ['"v=spf1 +all"'],
        ("_dmarc.shop.test", "TXT"): ['"v=DMARC1; p=reject"'],
    })
    assert record.verdict == "spoofable" and found == {"mail-spf-pass-all": "high"}


async def test_duplicate_records_break_spf_and_dmarc() -> None:
    record, found = await _check("shop.test", {
        ("shop.test", "TXT"): ['"v=spf1 mx -all"', '"v=spf1 include:other.test -all"'],
        ("_dmarc.shop.test", "TXT"): ['"v=DMARC1; p=reject"', '"v=DMARC1; p=none"'],
    })
    assert record.verdict == "spoofable"
    assert found == {"mail-spf-multiple": "medium", "mail-dmarc-invalid": "medium"}


async def test_subdomain_inherits_the_parent_policy_via_sp() -> None:
    record, found = await _check("app.shop.test", {
        ("app.shop.test", "TXT"): ['"v=spf1 -all"'],
        ("_dmarc.shop.test", "TXT"): ['"v=DMARC1; p=reject; sp=none"'],
    })
    assert record.dmarc_domain == "shop.test"  # found one level up
    assert record.verdict == "spoofable"  # a subdomain gets sp, and sp=none
    assert found == {"mail-dmarc-none": "medium"}


async def test_spf_redirect_is_followed() -> None:
    record, found = await _check("shop.test", {
        ("shop.test", "TXT"): ['"v=spf1 redirect=_spf.mailhost.test"'],
        ("_spf.mailhost.test", "TXT"): ['"v=spf1 ip4:192.0.2.0/24 -all"'],
        ("_dmarc.shop.test", "TXT"): ['"v=DMARC1; p=quarantine"'],
    })
    assert record.spf_all == "-all" and record.verdict == "protected" and found == {}


async def test_a_domain_without_mail_is_told_to_lock_down() -> None:
    _record, found = await mail.check("parked.test", resolve=_resolver({}))
    by_id = {f.template_id: f for f in found}
    assert set(by_id) == {"mail-spf-missing", "mail-dmarc-missing"}
    assert "receives no mail" in by_id["mail-dmarc-missing"].info["description"]
    assert isinstance(by_id["mail-dmarc-missing"], PostureFinding)
    assert by_id["mail-dmarc-missing"].as_dict()["kind"] == "vuln"  # a finding like nuclei's


# -- DNS-over-HTTPS -----------------------------------------------------------------------
async def test_doh_falls_back_to_the_second_resolver_and_filters_types() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "cloudflare-dns.com":
            return httpx.Response(503)
        assert request.url.params["name"] == "_dmarc.shop.test" and request.url.params["type"] == "TXT"
        return httpx.Response(200, json={"Status": 0, "Answer": [
            {"type": 5, "data": "alias.shop.test."},  # a CNAME on the way — not a TXT answer
            {"type": 16, "data": "v=DMARC1; p=reject"},
        ]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        assert await real_doh_query(client, "_dmarc.shop.test", "TXT") == ["v=DMARC1; p=reject"]


async def test_doh_nxdomain_is_no_records_and_total_failure_raises() -> None:
    nxdomain = httpx.MockTransport(lambda r: httpx.Response(200, json={"Status": 3}))
    async with httpx.AsyncClient(transport=nxdomain) as client:
        assert await real_doh_query(client, "nope.shop.test", "TXT") == []
    down = httpx.MockTransport(lambda r: httpx.Response(500))
    async with httpx.AsyncClient(transport=down) as client:
        with pytest.raises(mail.DnsError):
            await real_doh_query(client, "shop.test", "TXT")


async def test_tests_never_reach_live_dns() -> None:
    """The suite-wide guard in tests/conftest.py: a real lookup reports DNS as down."""
    with pytest.raises(mail.DnsError):
        await mail.check("example.com")
