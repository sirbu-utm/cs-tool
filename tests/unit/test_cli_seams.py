"""tests/unit/_cli.py: reading and replacing the CLI's internals wherever they live."""

from __future__ import annotations

from pathlib import Path

import pytest

import cyberfw

from ._cli import cli, cli_modules, patch_cli


def test_the_helper_covers_every_cli_and_core_module() -> None:
    # Taken from the files on disk, so a module added later is reached too.
    root = Path(cyberfw.__file__).resolve().parent
    on_disk = {
        f"cyberfw.{package}.{path.stem}"
        for package in ("cli", "core")
        for path in (root / package).glob("*.py")
        if path.stem not in {"__init__", "__main__"}
    }

    assert {module.__name__ for module in cli_modules()} == on_disk


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


def test_monkeypatching_the_helper_rebinds_every_module() -> None:
    # `monkeypatch.setattr(cli, ...)` must reach the CLI modules rather than shadow
    # the name on the helper, and undoing it must put the real function back everywhere.
    real = cli._is_interactive
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(cli, "_is_interactive", lambda: "patched")
        patched = [vars(module)["_is_interactive"] for module in cli_modules() if "_is_interactive" in vars(module)]
        assert patched and all(function() == "patched" for function in patched)

    restored = [vars(module)["_is_interactive"] for module in cli_modules() if "_is_interactive" in vars(module)]
    assert restored and all(function is real for function in restored)
    assert "_is_interactive" not in vars(cli)
