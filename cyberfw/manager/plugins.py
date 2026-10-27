"""Which plugin tools are in use: ``plugins.yaml``, each tool's state, and loading them.

``plugins.yaml`` names the packages the user enabled and, of those, the code
packages allowed to run Python inside cyberfw::

    # managed by `cyberfw plugins enable/disable`
    enabled:
      - cyberfw-foo        # a manifest package
      - cyberfw-bar
    allow_code:
      - cyberfw-bar        # a code package: its Python runs inside cyberfw

:func:`load_plugins` turns what :func:`~cyberfw.manager.discovery.discover`
found into a :class:`PluginSet`: the tools that loaded, and every declared tool's
state and why. Only enabled packages are loaded — a manifest by reading its YAML,
a code tool (only from a package in ``allow_code``) by importing its entry point —
and a plugin never breaks cyberfw: a problem puts its tools in their state, with
one warning per problem per process on the ``cyberfw`` logger.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from importlib.metadata import EntryPoint
from pathlib import Path
from typing import Literal

import yaml

from cyberfw.config import Settings
from cyberfw.exceptions import ContractError, ManifestError, PluginError
from cyberfw.logging import get_logger
from cyberfw.manager.discovery import CODE_GROUP, Declared, discover, normalize
from cyberfw.plugin import SUPPORTED_CONTRACTS, BaseTool, ToolPlugin, ToolRecord, ToolSpec
from cyberfw.tools import BUILTIN
from cyberfw.tools.manifest import parse_manifest
from cyberfw.tools.manifest_tool import compile_manifest

__all__ = ["RESERVED", "PluginInfo", "PluginSet", "PluginsFile", "State", "load_plugins", "read_plugins_file"]

LOG = get_logger("plugins")

#: Names cyberfw gives records of its own (its post-scan checks): no plugin tool may take one.
RESERVED = frozenset({"tlscheck", "mailcheck", "takeover", "virustotal"})
#: What a tool's name may be.
TOOL_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*$")

State = Literal["enabled", "disabled", "code-not-allowed", "conflict", "incompatible", "broken", "missing"]


@dataclass(frozen=True)
class PluginInfo:
    """One plugin tool as ``cyberfw plugins`` lists it — or a package that is missing."""

    package: str
    version: str
    #: ``manifest`` or ``code``; empty for a missing package.
    kind: str
    #: Empty for a missing package.
    tool: str
    state: State
    #: Why the tool is in a state other than ``enabled``.
    reason: str = ""
    #: The extra environment variables its recipe asks for, when its manifest or plugin could be read.
    env: tuple[str, ...] = ()


@dataclass(frozen=True)
class PluginsFile:
    """``plugins.yaml``: the enabled packages, and those allowed to run code (names normalised)."""

    enabled: frozenset[str] = frozenset()
    allow_code: frozenset[str] = frozenset()


def read_plugins_file(path: Path) -> PluginsFile:
    """``plugins.yaml`` at ``path``; nothing enabled when there is none.
    Raises :class:`PluginError` when it cannot be read or is not one."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return PluginsFile()
    except OSError as exc:
        raise PluginError(f"{path}: cannot be read: {exc}") from exc
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise PluginError(f"{path}: not valid YAML: {exc}") from exc
    if not isinstance(data, dict) or set(data) - {"enabled", "allow_code"}:
        raise PluginError(f"{path}: expected the keys enabled and allow_code, each a list of package names")
    lists: dict[str, frozenset[str]] = {}
    for key in ("enabled", "allow_code"):
        names = data.get(key) or []
        if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
            raise PluginError(f"{path}: {key}: a list of package names")
        lists[key] = frozenset(normalize(name) for name in names)
    return PluginsFile(enabled=lists["enabled"], allow_code=lists["allow_code"])


@dataclass
class PluginSet:
    """The plugin tools that loaded, and every declared tool's state."""

    infos: list[PluginInfo] = field(default_factory=list)
    #: The tools that loaded, by name — each with its install recipe.
    tools: dict[str, ToolPlugin] = field(default_factory=dict)

    def declared(self) -> frozenset[str]:
        """Every tool name an installed plugin package declares, whatever its state."""
        return frozenset(info.tool for info in self.infos if info.tool)

    def origin(self, tool: str) -> str | None:
        """``cyberfw-foo 0.3`` for a tool that loaded."""
        for info in self.infos:
            if info.tool == tool and info.state == "enabled":
                return f"{info.package} {info.version}"
        return None

    def unavailable(self, tool: str) -> str | None:
        """Why a declared plugin tool cannot be used, as a sentence; ``None`` when it can,
        or when no plugin declares it."""
        if tool in self.tools:
            return None
        for info in self.infos:
            if info.tool == tool:
                return f"{tool} is not available: plugin {info.package} {info.version} is {_PHRASE[info.state]} — {info.reason}"
        return None


#: Each state as the sentence about a plugin reads it.
_PHRASE: dict[State, str] = {
    "enabled": "enabled",
    "disabled": "disabled",
    "code-not-allowed": "not allowed to run code",
    "conflict": "in conflict",
    "incompatible": "incompatible",
    "broken": "broken",
    "missing": "missing",
}


#: (plugins file, its bytes, sys.path) → the set loaded for them; and the problems already warned about.
_LOADED: dict[tuple[str, bytes | None, tuple[str, ...]], PluginSet] = {}
_WARNED: set[tuple[str, str, str]] = set()


def load_plugins(settings: Settings) -> PluginSet:
    """The plugin tools for ``settings``' ``plugins.yaml``, loaded once per process for
    the same file and the same installed packages."""
    path = settings.plugins_file
    try:
        content: bytes | None = path.read_bytes()
    except OSError:
        content = None
    key = (str(path), content, tuple(sys.path))
    if key not in _LOADED:
        _LOADED.clear()
        _LOADED[key] = _load(path)
    return _LOADED[key]


def _load(path: Path) -> PluginSet:
    try:
        chosen = read_plugins_file(path)
    except PluginError as exc:
        _warn("plugins.yaml", "", f"{exc} — no plugin is enabled until it is fixed")
        chosen = PluginsFile()
    declared = discover()
    packages = Counter(point.tool for point in {(d.package, d.tool): d for d in declared}.values())
    twice = Counter((d.package, d.tool) for d in declared)
    result = PluginSet()
    for point in declared:
        if twice[(point.package, point.tool)] > 1 and point.group == CODE_GROUP:
            continue  # reported once, with its manifest entry
        state, reason, env, plugin = _state(point, chosen, packages, twice)
        result.infos.append(
            PluginInfo(
                package=point.package, version=point.version, kind=point.kind, tool=point.tool,
                state=state, reason=reason, env=env,
            )
        )
        if plugin is not None:
            result.tools[point.tool] = plugin
        elif point.package in chosen.enabled:
            # Only what the user asked for is a problem: a package nobody enabled stays quiet.
            _warn(point.package, point.tool, f"{_PHRASE[state]} — {reason}")
    found = {point.package for point in declared}
    for package in sorted(chosen.enabled - found):
        reason = "not installed, or it declares no cyberfw tool"
        result.infos.append(PluginInfo(package=package, version="", kind="", tool="", state="missing", reason=reason))
        _warn(package, "", f"{_PHRASE['missing']} — {reason}")
    return result


def _state(
    point: Declared, chosen: PluginsFile, packages: Counter[str], twice: Counter[tuple[str, str]]
) -> tuple[State, str, tuple[str, ...], ToolPlugin | None]:
    """A declared tool's state, the reason, its ``env:`` when known, and the plugin when it loaded."""
    if not TOOL_NAME.match(point.tool):
        return "broken", f"{point.tool!r} is not a tool name (lowercase letters, digits, - and _)", (), None
    if twice[(point.package, point.tool)] > 1:
        return "broken", f"{point.package} declares {point.tool} both as a manifest and as code", (), None
    if point.tool in BUILTIN:
        return "conflict", f"{point.tool} is a built-in tool", (), None
    if point.tool in RESERVED:
        return "conflict", f"{point.tool} names records cyberfw makes itself", (), None
    if packages[point.tool] > 1:
        return "conflict", f"another installed package declares {point.tool} too: disable one of them", (), None
    env = _manifest_env(point) if point.group != CODE_GROUP else ()
    if point.package not in chosen.enabled:
        return "disabled", f"enable it with `cyberfw plugins enable {point.package}`", env, None
    if point.kind == "code" and point.package not in chosen.allow_code:
        return (
            "code-not-allowed",
            "it ships Python that would run inside cyberfw — "
            f"allow that with `cyberfw plugins enable {point.package} --allow-code`",
            env,
            None,
        )
    try:
        plugin = _load_manifest(point) if point.group != CODE_GROUP else _load_code(point)
    except ContractError as exc:
        loads = ", ".join(str(version) for version in sorted(SUPPORTED_CONTRACTS))
        return "incompatible", f"written for plugin contract {exc.contract}; this cyberfw loads {loads} — update cyberfw", env, None
    except (ManifestError, ValueError) as exc:
        return "broken", str(exc), env, None
    except Exception as exc:  # whatever a plugin's own import raises
        return "broken", f"{type(exc).__name__}: {exc}", env, None
    assert plugin.install is not None
    return "enabled", "", tuple(plugin.install.env), plugin


def _manifest_path(point: Declared) -> Path:
    """The manifest file of a manifest tool, located without running anything: its
    entry point names a top-level package, which ``find_spec`` finds without importing."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", point.value):
        raise ManifestError(f"the cyberfw.manifests entry point must name a top-level package, not {point.value!r}")
    spec = importlib.util.find_spec(point.value)
    for location in (spec.submodule_search_locations or []) if spec is not None else []:
        path = Path(location) / f"{point.tool}.yaml"
        if path.is_file():
            return path
    raise ManifestError(f"{point.tool}.yaml was not found in the package {point.value}")


def _manifest_env(point: Declared) -> tuple[str, ...]:
    """A manifest tool's ``env:`` — read from its YAML, which runs nothing — or nothing when it cannot be read."""
    try:
        path = _manifest_path(point)
        return tuple(parse_manifest(path.read_text(encoding="utf-8"), where=str(path)).install.env)
    except Exception:  # its state says what is wrong when it is loaded
        return ()


def _load_manifest(point: Declared) -> ToolPlugin:
    path = _manifest_path(point)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ManifestError(f"{path}: cannot be read: {exc}") from exc
    return compile_manifest(point.tool, parse_manifest(text, where=str(path)))


def _load_code(point: Declared) -> ToolPlugin:
    """Import a code tool's entry point and check that it is a usable ``ToolPlugin``."""
    plugin = EntryPoint(name=point.tool, value=point.value, group=point.group).load()
    if not isinstance(plugin, ToolPlugin):
        raise ValueError(f"{point.value} is a {type(plugin).__name__}, not a ToolPlugin")
    if plugin.contract not in SUPPORTED_CONTRACTS:
        raise ContractError(f"written for plugin contract {plugin.contract}", contract=plugin.contract)
    if not (isinstance(plugin.adapter, type) and issubclass(plugin.adapter, BaseTool)):
        raise ValueError("its adapter is not a BaseTool subclass")
    if not (isinstance(plugin.record, type) and issubclass(plugin.record, ToolRecord)):
        raise ValueError("its record is not a ToolRecord subclass")
    if not isinstance(plugin.install, ToolSpec):
        raise ValueError("it brings no install recipe (install=ToolSpec(...))")
    install = ToolSpec.model_validate({**plugin.install.model_dump(), "name": point.tool})
    return ToolPlugin(contract=plugin.contract, adapter=plugin.adapter, record=plugin.record, install=install)


def _warn(package: str, tool: str, problem: str) -> None:
    if (package, tool, problem) not in _WARNED:
        _WARNED.add((package, tool, problem))
        LOG.warning("plugin %s%s: %s", package, f" ({tool})" if tool else "", problem)
