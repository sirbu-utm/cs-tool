"""Pipelines defined as YAML files.

Any ``<name>.yaml`` under the pipelines directory (``Settings.pipelines_dir``,
``pipelines/`` in the repo by default) is a pipeline the CLI can run by its file
stem, next to the built-in Python ones::

    description: Active port scan, HTTP probe, then nuclei on the live services
    nodes:
      - tool: naabu
        stage: ports
      - tool: httpx
        stage: live_http
      - tool: nuclei
        stage: vulns
        input_from: live_http   # optional: defaults to the previous stage
        max_records: 50         # optional: 0 = unlimited

The engine is already data-driven, so this is only a validated loader: unknown
keys, an ``input_from`` that does not name an earlier stage and duplicate stage
names are rejected up front with the file named, as :class:`RegistryError`.
Whether each ``tool`` is registered is the caller's check (it needs the registry).
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from cyberfw.exceptions import RegistryError
from cyberfw.pipeline.engine import Node

__all__ = ["NodeSpec", "PipelineSpec", "load_pipeline_file", "discover_pipelines"]


class NodeSpec(BaseModel):
    """One ``nodes:`` entry."""

    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1)
    stage: str = Field(min_length=1)
    input_from: str | None = None
    max_records: int = Field(default=0, ge=0)


class PipelineSpec(BaseModel):
    """The whole document."""

    model_config = ConfigDict(extra="forbid")

    description: str = ""
    nodes: list[NodeSpec] = Field(min_length=1)


def load_pipeline_file(path: Path) -> list[Node]:
    """Parse and validate one pipeline file into the engine's ``Node`` list."""
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RegistryError(f"cannot read pipeline {path.name}: {exc}") from exc
    if not isinstance(document, dict):
        raise RegistryError(f"pipeline {path.name}: expected a mapping with a `nodes:` list")
    try:
        spec = PipelineSpec.model_validate(document)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in err['loc']) or '<root>'}: {err['msg']}" for err in exc.errors()
        )
        raise RegistryError(f"pipeline {path.name}: {problems}") from exc

    seen: set[str] = set()
    for node in spec.nodes:
        if node.stage in seen:
            raise RegistryError(f"pipeline {path.name}: stage {node.stage!r} is defined twice")
        if node.input_from is not None and node.input_from not in seen:
            raise RegistryError(
                f"pipeline {path.name}: stage {node.stage!r} has input_from={node.input_from!r}, "
                f"which is not an earlier stage (known: {sorted(seen) or '<none>'})"
            )
        seen.add(node.stage)

    return [
        Node(tool=node.tool, stage=node.stage, max_records=node.max_records, input_from=node.input_from)
        for node in spec.nodes
    ]


def discover_pipelines(pipelines_dir: Path | None) -> dict[str, Path]:
    """Map pipeline names (file stems) to their ``.yaml`` files; ``{}`` when the dir is absent."""
    if pipelines_dir is None or not pipelines_dir.is_dir():
        return {}
    return {path.stem: path for path in sorted(pipelines_dir.glob("*.yaml")) if path.is_file()}
