"""The tools cyberfw ships, and the lookups the rest of the framework uses.

Each built-in tool's module describes it as a :class:`~cyberfw.plugin.ToolPlugin`
— its adapter and its record model — exactly as a plugin describes its own
tools; its install recipe is its entry in ``registry.yaml``. Every map from a
tool's name to its code is built from these descriptions, which makes them the
only place the framework couples the two.
"""

from __future__ import annotations

from pathlib import Path

from cyberfw.exceptions import RegistryError
from cyberfw.pipeline.schemas import VirusTotalResult
from cyberfw.plugin import BaseTool, ToolPlugin, ToolRecord, ToolSpec
from cyberfw.tools import (
    ffuf,
    gitleaks,
    gowitness,
    httpx_tool,
    naabu,
    nmap,
    nuclei,
    rustscan,
    subfinder,
)

__all__ = ["ADAPTERS", "BUILTIN", "MODELS", "adapter_class", "adapter_for"]

#: The built-in tools, by registry name.
BUILTIN: dict[str, ToolPlugin] = {
    "subfinder": subfinder.PLUGIN,
    "naabu": naabu.PLUGIN,
    "nmap": nmap.PLUGIN,
    "rustscan": rustscan.PLUGIN,
    "httpx": httpx_tool.PLUGIN,
    "ffuf": ffuf.PLUGIN,
    "nuclei": nuclei.PLUGIN,
    "gitleaks": gitleaks.PLUGIN,
    "gowitness": gowitness.PLUGIN,
}

#: Tool name → adapter class.
ADAPTERS: dict[str, type[BaseTool]] = {name: tool.adapter for name, tool in BUILTIN.items()}

#: Name → the model its records validate against: each tool's, and that of the
#: reputation records cyberfw makes itself (VirusTotal).
MODELS: dict[str, type[ToolRecord]] = {
    **{name: tool.record for name, tool in BUILTIN.items()},
    "virustotal": VirusTotalResult,
}


def adapter_class(name: str) -> type[BaseTool]:
    """Return the adapter class for tool ``name`` (no binary needed).

    Lets the CLI use class-level knowledge — prompts, target validation —
    before the tool is installed.
    """
    cls = ADAPTERS.get(name)
    if cls is None:
        raise RegistryError(f"no adapter registered for tool {name!r}")
    return cls


def adapter_for(spec: ToolSpec, binary: Path) -> BaseTool:
    """Instantiate the adapter for ``spec``, given its installed binary path."""
    return adapter_class(spec.name)(spec, binary)
