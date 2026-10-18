"""tests/unit/_cli.py: reading and replacing the CLI's internals wherever they live."""

from __future__ import annotations

import pytest

from ._cli import cli, cli_modules, patch_cli


def test_a_name_is_read_from_the_module_that_has_it() -> None:
    assert callable(cli._is_interactive)
    assert cli.app.info.name == "cyberfw"


def test_an_unknown_name_is_an_attribute_error() -> None:
    with pytest.raises(AttributeError, match="no cyberfw.cli module"):
        cli.no_such_thing  # noqa: B018 - the lookup itself is under test


def test_patch_cli_replaces_every_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_cli(monkeypatch, "_is_interactive", lambda: "patched")

    bound = [vars(module)["_is_interactive"] for module in cli_modules() if "_is_interactive" in vars(module)]
    assert bound and all(function() == "patched" for function in bound)


def test_patch_cli_refuses_a_name_no_module_binds(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(AssertionError, match="binds"):
        patch_cli(monkeypatch, "no_such_thing", None)
