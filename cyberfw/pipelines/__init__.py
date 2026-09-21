"""Ready-made, orchestratable pipelines.

Two sources: the Python builders in :data:`PIPELINES` (which take options, e.g.
``recon-to-vuln --ffuf``) and plain YAML files under ``Settings.pipelines_dir``
(see :mod:`cyberfw.pipelines.loader`). Both are addressed by name.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from cyberfw.exceptions import RegistryError
from cyberfw.logging import get_logger
from cyberfw.pipeline.engine import Node
from cyberfw.pipelines.loader import discover_pipelines, load_pipeline_file
from cyberfw.pipelines.recon_to_vuln import ReconToVulnOptions, build_recon_to_vuln

__all__ = ["build_recon_to_vuln", "build", "available_pipelines", "PIPELINES"]

LOG = get_logger("pipelines")

PIPELINES: dict[str, Callable[[ReconToVulnOptions | None], list[Node]]] = {
    "recon-to-vuln": build_recon_to_vuln,
}


def available_pipelines(pipelines_dir: Path | None = None) -> list[str]:
    """Sorted names of every runnable pipeline: built-in plus YAML files."""
    return sorted({*PIPELINES, *discover_pipelines(pipelines_dir)})


def build(name: str, *, pipelines_dir: Path | None = None, **options: object) -> list[Node]:
    """Return the ordered ``Node`` list for pipeline ``name``.

    A built-in builder wins over a YAML file of the same name. Extra keyword
    arguments are passed to the builder (e.g. ``include_ffuf``); a YAML pipeline
    has no options, so any that are set are reported and ignored.
    Raises :class:`RegistryError` for an unknown pipeline or an invalid file.
    """
    builder = PIPELINES.get(name)
    if builder is not None:
        return builder(builder_options_from(options))

    files = discover_pipelines(pipelines_dir)
    path = files.get(name)
    if path is None:
        known = ", ".join(available_pipelines(pipelines_dir))
        raise RegistryError(f"Unknown pipeline {name!r}. Known: {known}")
    ignored = sorted(key for key, value in options.items() if value)
    if ignored:
        LOG.warning(
            "pipeline %s is defined in %s and takes no options; ignoring %s",
            name,
            path.name,
            ", ".join(ignored),
        )
    return load_pipeline_file(path)


def builder_options_from(options: dict[str, object]) -> ReconToVulnOptions | None:
    """Wrap free kwargs into a typed options object when the builder expects one."""
    if not options:
        return None
    return ReconToVulnOptions(**cast(dict[str, Any], options))
