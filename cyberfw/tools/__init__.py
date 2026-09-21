"""Tool adapter registry.

Maps ``registry.yaml`` names to their adapter classes and builds instances from
a :class:`ToolSpec` + resolved binary path. Keeping this the only place the
framework couples tool names to code is what makes the rest declarative.
"""

from __future__ import annotations

from pathlib import Path

from cyberfw.exceptions import RegistryError
from cyberfw.manager.registry import ToolSpec
from cyberfw.tools.base import BaseTool
from cyberfw.tools.ffuf import FfufTool
from cyberfw.tools.gitleaks import GitleaksTool
from cyberfw.tools.gowitness import GowitnessTool
from cyberfw.tools.httpx_tool import HttpxTool
from cyberfw.tools.naabu import NaabuTool
from cyberfw.tools.nuclei import NucleiTool
from cyberfw.tools.rustscan import RustscanTool
from cyberfw.tools.subfinder import SubfinderTool

__all__ = ["ADAPTERS", "adapter_for"]

ADAPTERS: dict[str, type[BaseTool]] = {
    "subfinder": SubfinderTool,
    "naabu": NaabuTool,
    "rustscan": RustscanTool,
    "httpx": HttpxTool,
    "ffuf": FfufTool,
    "nuclei": NucleiTool,
    "gitleaks": GitleaksTool,
    "gowitness": GowitnessTool,
}


def adapter_for(spec: ToolSpec, binary: Path) -> BaseTool:
    """Instantiate the adapter for ``spec``, given its installed binary path."""
    cls = ADAPTERS.get(spec.name)
    if cls is None:
        raise RegistryError(f"no adapter registered for tool {spec.name!r}")
    return cls(spec, binary)
