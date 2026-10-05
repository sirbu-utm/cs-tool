"""Target validation is the security boundary — test what it accepts and refuses."""

from __future__ import annotations

import pytest
from cyberfw_bot.validation import ValidationError, suggest_target, validate_target


@pytest.mark.parametrize(
    "target",
    [
        "example.com",
        "sub.example.co.uk",
        "https://example.com/path?q=1",
        "http://example.com:8080/",
        "93.184.216.34",
        "2606:2800:220:1:248:1893:25c8:1946",
    ],
)
def test_accepts_a_single_public_host(target: str) -> None:
    assert validate_target(target) == target


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "-oJ/tmp/x",  # leading dash → argument injection
        "example.com; rm -rf /",  # shell metacharacters
        "a.com && b.com",
        "$(whoami).example.com",
        "example.com | tee",
        "ftp://example.com",  # non-http scheme
        "not a domain",
        "http://",  # no host
        "example",  # no TLD
    ],
)
def test_rejects_unsafe_or_malformed(target: str) -> None:
    with pytest.raises(ValidationError):
        validate_target(target)


@pytest.mark.parametrize(
    "target",
    ["127.0.0.1", "10.0.0.5", "192.168.1.10", "169.254.1.1", "localhost", "http://127.0.0.1:8000/"],
)
def test_blocks_private_and_loopback_by_default(target: str) -> None:
    with pytest.raises(ValidationError):
        validate_target(target)


@pytest.mark.parametrize("target", ["127.0.0.1", "192.168.1.10", "localhost"])
def test_private_allowed_when_block_disabled(target: str) -> None:
    assert validate_target(target, block_private=False) == target


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("example.com", "example.com"),
        ("scan example.com", "example.com"),  # first token that validates
        ("check http://example.com/path please", "http://example.com/path"),
        ("93.184.216.34", "93.184.216.34"),
    ],
)
def test_suggest_target_finds_a_plausible_host(text: str, expected: str) -> None:
    assert suggest_target(text) == expected


@pytest.mark.parametrize("text", ["", "   ", "привет", "just some words", "-oJ/tmp/x"])
def test_suggest_target_returns_none_for_non_targets(text: str) -> None:
    assert suggest_target(text) is None


def test_suggest_target_respects_block_private() -> None:
    assert suggest_target("10.0.0.5") is None
    assert suggest_target("10.0.0.5", block_private=False) == "10.0.0.5"
