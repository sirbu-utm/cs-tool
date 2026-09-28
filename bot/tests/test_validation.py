"""Target validation is the security boundary — test what it accepts and refuses."""

from __future__ import annotations

import pytest
from cyberfw_bot.validation import ValidationError, validate_target


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
