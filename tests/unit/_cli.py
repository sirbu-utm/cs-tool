"""The CLI's internals for tests, wherever they live.

`cyberfw.cli` is being split from one module into a package, and every module
that imports a name holds its own reference to it. Tests therefore read
internals through ``cli.<name>`` and replace them through :func:`patch_cli`,
which work the same on the single module and on the package.
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import Any

import pytest

#: The package's modules, the launcher first: it imports the most names.
_SUBMODULES = ("launcher", "scan", "tools", "reports", "triage", "schedule", "views", "common", "app")


def cli_modules() -> list[ModuleType]:
    """Every module of the CLI — just ``cyberfw.cli`` while it is a single file."""
    package = importlib.import_module("cyberfw.cli")
    if not hasattr(package, "__path__"):
        return [package]
    return [importlib.import_module(f"cyberfw.cli.{name}") for name in _SUBMODULES]


class _Cli:
    """``cli.<name>``: what the CLI module that has that name binds it to."""

    def __getattr__(self, name: str) -> Any:
        for module in cli_modules():
            if name in vars(module):
                return vars(module)[name]
        raise AttributeError(f"no cyberfw.cli module has {name!r}")


cli = _Cli()


def patch_cli(monkeypatch: pytest.MonkeyPatch, name: str, value: object) -> None:
    """Replace ``name`` in every CLI module that binds it: patching one module
    would miss the callers that live in the others."""
    bound = [module for module in cli_modules() if name in vars(module)]
    assert bound, f"no cyberfw.cli module binds {name!r}"
    for module in bound:
        monkeypatch.setattr(module, name, value)
