"""The internals of the CLI and the core it drives, for tests, wherever they live.

Code keeps moving between the modules of ``cyberfw.cli`` and ``cyberfw.core``,
and every module that imports a name holds its own reference to it. Tests
therefore read internals through ``cli.<name>`` and replace them through
:func:`patch_cli`, which reach every module of both packages.
"""

from __future__ import annotations

import importlib
import pkgutil
from types import ModuleType
from typing import Any

import pytest

#: The packages whose modules tests reach into, and the API module on top of them.
_PACKAGES = ("cyberfw.cli", "cyberfw.core")
_MODULES = ("cyberfw.api",)


def cli_modules() -> list[ModuleType]:
    """Every module of the CLI and the core — found on disk, so a new one is never missed — and the API.

    ``__main__`` is left out: importing it would run the CLI."""
    modules: list[ModuleType] = []
    for package_name in _PACKAGES:
        package = importlib.import_module(package_name)
        for info in pkgutil.iter_modules(package.__path__):
            if info.name != "__main__":
                modules.append(importlib.import_module(f"{package_name}.{info.name}"))
    return modules + [importlib.import_module(name) for name in _MODULES]


def _bound(name: str) -> list[ModuleType]:
    """The CLI and core modules that bind ``name``."""
    return [module for module in cli_modules() if name in vars(module)]


class _Cli:
    """``cli.<name>``: what the CLI or core module that has that name binds it to.

    Setting ``cli.<name>`` — as ``monkeypatch.setattr(cli, name, value)`` does —
    rebinds it in every module that has it, never on this object, where it
    would only shadow the real bindings."""

    def __getattr__(self, name: str) -> Any:
        for module in cli_modules():
            if name in vars(module):
                return vars(module)[name]
        raise AttributeError(f"no cyberfw.cli module has {name!r}")

    def __setattr__(self, name: str, value: object) -> None:
        bound = _bound(name)
        if not bound:
            raise AttributeError(f"no cyberfw.cli module has {name!r}")
        for module in bound:
            setattr(module, name, value)


cli = _Cli()


def patch_cli(monkeypatch: pytest.MonkeyPatch, name: str, value: object) -> None:
    """Replace ``name`` in every CLI and core module that binds it: patching one
    module would miss the callers that live in the others."""
    bound = _bound(name)
    assert bound, f"no cyberfw.cli module binds {name!r}"
    for module in bound:
        monkeypatch.setattr(module, name, value)
