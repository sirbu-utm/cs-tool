"""VirusTotal client: key resolution, target classification, parsing, lookup."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from cyberfw import vt


# -- key resolution --------------------------------------------------------------
def test_resolve_prefers_explicit_then_env_chain(tmp_path: Path) -> None:
    env = {"CYBERFW_VT_API_KEY": "cyberfw", "VT_API_KEY": "vt", "VTCLI_APIKEY": "cli"}
    assert vt.resolve_api_key("explicit", environ=env, home=tmp_path) == "explicit"
    assert vt.resolve_api_key(None, environ=env, home=tmp_path) == "cyberfw"
    assert vt.resolve_api_key(None, environ={"VT_API_KEY": "vt"}, home=tmp_path) == "vt"
    assert vt.resolve_api_key(None, environ={"VTCLI_APIKEY": "cli"}, home=tmp_path) == "cli"


def test_resolve_reads_vt_toml_last(tmp_path: Path) -> None:
    (tmp_path / ".vt.toml").write_text('apikey = "fromtoml123"\n', encoding="utf-8")
    assert vt.resolve_api_key(None, environ={}, home=tmp_path) == "fromtoml123"
    assert vt.resolve_api_key(None, environ={}, home=tmp_path / "nope") is None


def test_persist_to_env_adds_then_replaces(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("BOT_TOKEN=x\n", encoding="utf-8")
    vt._persist_to_env(env_file, "KEY1")
    assert "CYBERFW_VT_API_KEY=KEY1" in env_file.read_text(encoding="utf-8")
    vt._persist_to_env(env_file, "KEY2")
    text = env_file.read_text(encoding="utf-8")
    assert "CYBERFW_VT_API_KEY=KEY2" in text and "KEY1" not in text  # replaced, not duplicated


def test_resolve_or_prompt_never_prompts_when_not_interactive(tmp_path: Path) -> None:
    assert vt.resolve_or_prompt(None, interactive=False, environ={}) is None  # would hang if it prompted


# -- target classification -------------------------------------------------------
@pytest.mark.parametrize(
    ("target", "kind", "path_prefix"),
    [
        ("example.com", "domain", "domains/"),
        ("93.184.216.34", "ip", "ip_addresses/"),
        ("https://example.com/x", "url", "urls/"),
        ("44d88612fea8a8f36de82e1278abb02f", "file", "files/"),
    ],
)
def test_classify_target(target: str, kind: str, path_prefix: str) -> None:
    got_kind, api_path, _gui, _ident = vt.classify_target(target)
    assert got_kind == kind
    assert api_path.startswith(path_prefix)


def test_classify_rejects_junk() -> None:
    with pytest.raises(vt.VtError):
        vt.classify_target("not a target")


# -- parsing ---------------------------------------------------------------------
def test_parse_reputation_folds_stats_and_categories() -> None:
    attrs = {
        "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 4},
        "reputation": -30,
        "categories": {"Forcepoint": "malware", "BitDefender": "phishing", "X": "malware"},
    }
    rep = vt.parse_reputation("evil.com", "domain", "domain", "evil.com", attrs)
    assert (rep.malicious, rep.suspicious, rep.harmless) == (5, 1, 60)
    assert rep.reputation == -30
    assert rep.categories == ["malware", "phishing"]  # deduped + sorted
    assert rep.flagged is True
    assert rep.permalink == "https://www.virustotal.com/gui/domain/evil.com"


# -- lookup (mocked transport) ---------------------------------------------------
async def test_lookup_parses_a_hit_and_sends_the_key() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["apikey"] = request.headers.get("x-apikey", "")
        return httpx.Response(
            200,
            json={"data": {"attributes": {
                "last_analysis_stats": {"malicious": 3, "suspicious": 0, "harmless": 70, "undetected": 1},
                "reputation": -10, "categories": {"a": "malware"},
            }}},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        rep = await vt.lookup(client, "secret-key", "evil.com")

    assert seen["apikey"] == "secret-key"
    assert rep.found and rep.malicious == 3 and rep.flagged


async def test_lookup_treats_404_as_not_seen() -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))) as client:
        rep = await vt.lookup(client, "k", "clean.com")
    assert rep.found is False and rep.malicious == 0


async def test_lookup_raises_on_bad_key() -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(401))) as client:
        with pytest.raises(vt.VtError):
            await vt.lookup(client, "bad", "example.com")


def test_virustotal_record_round_trips_through_validate_record() -> None:
    import json

    from cyberfw.pipeline.schemas import validate_record

    rep = vt.Reputation(
        target="evil.com", kind="domain", found=True, malicious=3,
        categories=["malware"], permalink="https://vt/gui/domain/evil.com",
    )
    rec = validate_record("virustotal", json.dumps(rep.as_record()), 1)
    assert rec.kind == "reputation"
    assert rec.target == "evil.com"
    assert rec.model_dump()["malicious"] == 3


def test_enrichment_targets_keeps_lookable_and_dedups() -> None:
    from types import SimpleNamespace

    recs = [
        SimpleNamespace(target="a.com"),
        SimpleNamespace(target="a.com"),           # duplicate
        SimpleNamespace(target="https://a.com/x"),
        SimpleNamespace(target="a.com:80"),        # host:port — not a VT target
        SimpleNamespace(target=""),                # empty
        SimpleNamespace(target="1.2.3.4"),
    ]
    assert vt.enrichment_targets(recs) == ["a.com", "https://a.com/x", "1.2.3.4"]


async def test_enrich_respects_limit_and_skips_failures() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if "bad.com" in str(request.url):
            return httpx.Response(401)
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    reps = await vt.enrich(["a.com", "bad.com", "c.com", "d.com"], "k", limit=3, per_minute=6000, client=client)
    await client.aclose()

    assert len(calls) == 3  # limit honoured (d.com not reached)
    assert [r.target for r in reps] == ["a.com", "c.com"]  # bad.com (401) skipped
