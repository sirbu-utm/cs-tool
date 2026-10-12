"""Subdomain takeover: candidate hosts, CNAME matching, the verdict (no live DNS)."""

from __future__ import annotations

import json

import httpx
import pytest

from cyberfw.pipeline.schemas import PostureFinding, validate_record
from cyberfw.posture import takeover

# Grabbed before tests/conftest.py swaps takeover.doh for an offline stub.
from cyberfw.posture.takeover import doh as real_doh

Zone = dict[tuple[str, str], tuple[int, list[str]]]


def _resolver(zone: Zone) -> takeover.Resolver:
    async def resolve(name: str, rtype: str) -> tuple[int, list[str]]:
        return zone.get((name, rtype), (0, []))

    return resolve


def _fetcher(bodies: dict[str, str]) -> takeover.Fetcher:
    async def fetch(host: str) -> str:
        return bodies.get(host, "")

    return fetch


async def _scan(hosts: list[str], zone: Zone, bodies: dict[str, str] | None = None) -> list[PostureFinding]:
    findings, _notes = await takeover.scan(hosts, resolve=_resolver(zone), fetch=_fetcher(bodies or {}))
    return findings


# -- candidate extraction & matching -----------------------------------------------
def test_candidates_are_in_scope_hosts_without_ips_or_duplicates() -> None:
    records = [
        validate_record("subfinder", json.dumps({"host": "Blog.example.com"}), 1),
        validate_record("httpx", json.dumps({"url": "https://blog.example.com/x", "status_code": 200}), 1),
        validate_record("naabu", json.dumps({"host": "1.2.3.4", "port": 443}), 1),  # IP → out
        validate_record("nuclei", json.dumps({"template-id": "t", "matched-at": "https://api.example.com/"}), 1),
    ]
    assert takeover.candidates(records) == ["blog.example.com"]  # deduped, lower-cased; vuln kind ignored


def test_service_match_is_by_cname_pattern() -> None:
    service, target = takeover._match(["myapp.herokuapp.com", "x"])
    assert service is not None and service.name == "Heroku" and target == "myapp.herokuapp.com"
    assert takeover._match(["example.com."])[0] is None


# -- the verdict -------------------------------------------------------------------
async def test_dangling_github_pages_is_flagged_by_its_error_page() -> None:
    zone = {("blog.example.com", "CNAME"): (0, ["user.github.io"])}
    bodies = {"blog.example.com": "<h1>404</h1> There isn't a GitHub Pages site here."}
    findings = await _scan(["blog.example.com"], zone, bodies)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool == "takeover" and finding.kind == "vuln" and finding.severity == "high"
    assert finding.template_id == "subdomain-takeover" and finding.target == "https://blog.example.com"
    assert "GitHub Pages" in finding.name
    assert "user.github.io" in finding.info["description"] and finding.info["remediation"]


async def test_a_live_service_page_is_not_flagged() -> None:
    zone = {("shop.example.com", "CNAME"): (0, ["acme.myshopify.com"])}
    bodies = {"shop.example.com": "<html><title>ACME Store</title>real shop</html>"}
    assert await _scan(["shop.example.com"], zone, bodies) == []  # no fingerprint → claimed → fine


async def test_heroku_and_s3_fingerprints() -> None:
    heroku = await _scan(
        ["a.example.com"],
        {("a.example.com", "CNAME"): (0, ["gone.herokuapp.com"])},
        {"a.example.com": "...herokucdn.com/error-pages/no-such-app.html..."},
    )
    assert heroku and "Heroku" in heroku[0].name
    s3 = await _scan(
        ["b.example.com"],
        {("b.example.com", "CNAME"): (0, ["bkt.s3.amazonaws.com"])},
        {"b.example.com": "<Error><Code>NoSuchBucket</Code></Error>"},
    )
    assert s3 and "Amazon S3" in s3[0].name


async def test_nxdomain_service_needs_the_target_gone_not_a_body() -> None:
    # Azure: no HTTP fingerprint; the signal is the host going NXDOMAIN.
    gone = {("x.example.com", "CNAME"): (0, ["app.azurewebsites.net"]), ("x.example.com", "A"): (3, [])}
    assert len(await _scan(["x.example.com"], gone)) == 1
    live = {("y.example.com", "CNAME"): (0, ["app.azurewebsites.net"]), ("y.example.com", "A"): (0, ["20.1.2.3"])}
    assert await _scan(["y.example.com"], live) == []


async def test_hosts_without_a_fingerprinted_cname_are_left_alone() -> None:
    zones: Zone = {
        ("plain.example.com", "CNAME"): (0, []),  # no CNAME at all
        ("other.example.com", "CNAME"): (0, ["lb.internal.example.net"]),  # CNAME, unknown service
    }
    assert await _scan(["plain.example.com", "other.example.com"], zones) == []


async def test_dns_unreachable_is_reported_not_raised() -> None:
    async def dead(_name: str, _rtype: str) -> tuple[int, list[str]]:
        raise takeover.DnsError("down")

    findings, notes = await takeover.scan(["a.example.com"], resolve=dead, fetch=_fetcher({}))
    assert findings == [] and notes == ["subdomain-takeover check skipped — DNS-over-HTTPS unreachable"]


async def test_scan_caps_the_host_count() -> None:
    hosts = [f"h{i}.example.com" for i in range(takeover._MAX_HOSTS + 5)]
    _findings, notes = await takeover.scan(hosts, resolve=_resolver({}), fetch=_fetcher({}))
    assert any("looked at the first" in note for note in notes)


# -- DoH primitive (mocked transport) ----------------------------------------------
async def test_doh_keeps_status_and_normalises_records() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params["type"] == "CNAME":
            return httpx.Response(200, json={"Status": 0, "Answer": [
                {"type": 5, "data": "User.GitHub.io."}, {"type": 1, "data": "1.2.3.4"},  # A filtered out
            ]})
        return httpx.Response(200, json={"Status": 3})  # NXDOMAIN, no Answer

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        assert await real_doh(client, "x.example.com", "CNAME") == (0, ["user.github.io"])
        assert await real_doh(client, "x.example.com", "A") == (3, [])


async def test_doh_falls_back_then_raises_when_all_resolvers_fail() -> None:
    down = httpx.MockTransport(lambda r: httpx.Response(502))
    async with httpx.AsyncClient(transport=down) as client:
        with pytest.raises(takeover.DnsError):
            await real_doh(client, "x.example.com", "CNAME")


async def test_http_body_tries_https_then_http() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.scheme)
        if request.url.scheme == "https":
            raise httpx.ConnectError("no https")
        return httpx.Response(200, text="No such app")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as client:
        assert await takeover.http_body(client, "a.example.com") == "No such app"
    assert seen == ["https", "http"]


async def test_tests_never_reach_live_dns() -> None:
    """The suite-wide guard in tests/conftest.py also covers the takeover resolver."""
    with pytest.raises(takeover.DnsError):
        await takeover.doh(httpx.AsyncClient(), "example.com", "CNAME")  # patched offline
