"""Ready-made, orchestratable pipelines."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from cyberfw.pipeline.engine import Node
from cyberfw.pipelines.recon_to_vuln import ReconToVulnOptions, build_recon_to_vuln

__all__ = ["build_recon_to_vuln", "build", "PIPELINES"]

PIPELINES: dict[str, Callable[[ReconToVulnOptions | None], list[Node]]] = {
    "recon-to-vuln": build_recon_to_vuln,
}


def build(name: str, **options: object) -> list[Node]:
    """Return the ordered ``Node`` list for pipeline ``name``.

    Extra keyword arguments are passed to the builder (e.g. ``include_ffuf``).
    Raises :class:`RegistryError` for an unknown pipeline.
    """
    from cyberfw.exceptions import RegistryError

    builder = PIPELINES.get(name)
    if builder is None:
        raise RegistryError(f"Unknown pipeline {name!r}. Known: {', '.join(sorted(PIPELINES))}")
    return builder(builder_options_from(options))


def builder_options_from(options: dict[str, object]) -> ReconToVulnOptions | None:
    """Wrap free kwargs into a typed options object when the builder expects one."""
    if not options:
        return None
    return ReconToVulnOptions(**cast(dict[str, Any], options))
