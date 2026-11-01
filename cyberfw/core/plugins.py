"""Enabling and disabling plugin packages — what ``cyberfw plugins enable/disable`` do.

``plugins.yaml`` is the record (CI commits it). Enabling writes a package to it and
loads it at once, so its tools' states are known before the command ends; a code
package — whose Python would run inside cyberfw — is enabled only when its code is
allowed. Running someone else's code is the user's decision, so none of this is in
the public API.
"""

from __future__ import annotations

from dataclasses import dataclass

from cyberfw.config import Settings
from cyberfw.exceptions import PluginError
from cyberfw.manager.discovery import discover, normalize
from cyberfw.manager.plugins import (
    PluginInfo,
    PluginsFile,
    load_plugins,
    read_plugins_file,
    write_plugins_file,
)

__all__ = ["CodeNotAllowed", "Enabled", "UnknownPackage", "disable_plugin", "enable_plugin"]


class UnknownPackage(PluginError):
    """No installed package by that name declares cyberfw tools."""


class CodeNotAllowed(PluginError):
    """A code package, enabled without allowing its code."""


@dataclass(frozen=True)
class Enabled:
    """What enabling a package did: its normalised name, whether it was enabled
    already, and its tools' states once loaded."""

    package: str
    already: bool
    tools: list[PluginInfo]

    @property
    def working(self) -> bool:
        """Every tool of the package loaded."""
        return all(info.state == "enabled" for info in self.tools)


def enable_plugin(settings: Settings, package: str, *, allow_code: bool = False) -> Enabled:
    """Enable ``package`` in ``settings``' ``plugins.yaml`` and load it.

    A code package needs ``allow_code``, which also writes it to ``allow_code``; for a
    manifest package the flag allows nothing (a release that starts shipping Python
    then stays ``code-not-allowed``). A package that loads broken stays enabled, so a
    fixed release works without enabling it again. Raises :class:`UnknownPackage`
    when no installed package by that name declares cyberfw tools,
    :class:`CodeNotAllowed`, or :class:`PluginError` when ``plugins.yaml`` cannot be
    read or written — and then changes nothing.
    """
    name = normalize(package)
    declared = discover()
    own = [point for point in declared if point.package == name]
    if not own:
        known = ", ".join(sorted({point.package for point in declared})) or "none is installed"
        raise UnknownPackage(f"no installed package {package!r} declares cyberfw tools (those that do: {known})")
    code = any(point.kind == "code" for point in own)
    if code and not allow_code:
        raise CodeNotAllowed(
            f"{name} ships Python that would run inside cyberfw, with access to everything cyberfw can "
            f"reach — your files, tokens and network. If you trust it: `cyberfw plugins enable {name} --allow-code`"
        )
    current = read_plugins_file(settings.plugins_file)
    wanted = PluginsFile(
        enabled=current.enabled | {name},
        allow_code=current.allow_code | ({name} if code else frozenset()),
    )
    if wanted != current:
        write_plugins_file(settings.plugins_file, wanted)
    tools = [info for info in load_plugins(settings).infos if info.package == name]
    return Enabled(package=name, already=wanted == current, tools=tools)


def disable_plugin(settings: Settings, package: str) -> bool:
    """Take ``package`` off both lists of ``plugins.yaml`` — installed or not; whether
    it was on one. Raises :class:`PluginError` when the file cannot be read or written."""
    name = normalize(package)
    current = read_plugins_file(settings.plugins_file)
    if name not in current.enabled | current.allow_code:
        return False
    write_plugins_file(
        settings.plugins_file,
        PluginsFile(enabled=current.enabled - {name}, allow_code=current.allow_code - {name}),
    )
    return True
