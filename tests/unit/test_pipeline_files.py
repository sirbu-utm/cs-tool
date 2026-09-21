"""Tests for pipelines defined as YAML files (``pipelines/<name>.yaml``)."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberfw.exceptions import RegistryError
from cyberfw.pipelines import PIPELINES, available_pipelines, build
from cyberfw.pipelines.loader import discover_pipelines, load_pipeline_file

REPO_ROOT = Path(__file__).resolve().parents[2]

PORTS_TO_VULN = """\
description: Active port scan, HTTP probe, then nuclei on the live services
nodes:
  - tool: naabu
    stage: ports
  - tool: httpx
    stage: live_http
  - tool: nuclei
    stage: vulns
    input_from: live_http
    max_records: 50
"""


def _write(tmp_path: Path, name: str, text: str) -> Path:
    pipelines_dir = tmp_path / "pipelines"
    pipelines_dir.mkdir(exist_ok=True)
    path = pipelines_dir / f"{name}.yaml"
    path.write_text(text, encoding="utf-8")
    return path


class TestLoadPipelineFile:
    def test_nodes_are_read_in_order_with_wiring(self, tmp_path: Path) -> None:
        nodes = load_pipeline_file(_write(tmp_path, "ports-to-vuln", PORTS_TO_VULN))

        assert [(n.tool, n.stage) for n in nodes] == [("naabu", "ports"), ("httpx", "live_http"), ("nuclei", "vulns")]
        assert nodes[2].input_from == "live_http"
        assert nodes[2].max_records == 50
        assert nodes[0].input_from is None and nodes[0].max_records == 0

    def test_unknown_key_is_rejected_with_the_file_named(self, tmp_path: Path) -> None:
        """A typo such as ``inputs_from`` must not be silently ignored."""
        path = _write(tmp_path, "typo", "nodes:\n  - tool: httpx\n    stage: a\n    inputs_from: x\n")
        with pytest.raises(RegistryError, match=r"typo\.yaml.*inputs_from"):
            load_pipeline_file(path)

    def test_input_from_must_name_an_earlier_stage(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "bad-wiring", "nodes:\n  - tool: httpx\n    stage: a\n    input_from: later\n  - tool: nuclei\n    stage: later\n")
        with pytest.raises(RegistryError, match="input_from"):
            load_pipeline_file(path)

    def test_duplicate_stage_names_are_rejected(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "dupe", "nodes:\n  - tool: httpx\n    stage: a\n  - tool: nuclei\n    stage: a\n")
        with pytest.raises(RegistryError, match="stage"):
            load_pipeline_file(path)

    def test_empty_pipeline_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(RegistryError):
            load_pipeline_file(_write(tmp_path, "empty", "nodes: []\n"))

    def test_non_mapping_document_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(RegistryError, match="mapping"):
            load_pipeline_file(_write(tmp_path, "list", "- just\n- a list\n"))

    def test_invalid_yaml_is_a_registry_error(self, tmp_path: Path) -> None:
        with pytest.raises(RegistryError):
            load_pipeline_file(_write(tmp_path, "broken", "nodes: [\n"))


class TestDiscoverAndBuild:
    def test_discover_maps_file_stems_to_paths(self, tmp_path: Path) -> None:
        a = _write(tmp_path, "ports-to-vuln", PORTS_TO_VULN)
        b = _write(tmp_path, "web-only", "nodes:\n  - tool: httpx\n    stage: live\n")
        (tmp_path / "pipelines" / "notes.txt").write_text("ignored", encoding="utf-8")

        assert discover_pipelines(tmp_path / "pipelines") == {"ports-to-vuln": a, "web-only": b}

    def test_discover_tolerates_a_missing_directory(self, tmp_path: Path) -> None:
        assert discover_pipelines(tmp_path / "nowhere") == {}

    def test_available_pipelines_merges_python_and_yaml(self, tmp_path: Path) -> None:
        _write(tmp_path, "ports-to-vuln", PORTS_TO_VULN)

        assert available_pipelines(tmp_path / "pipelines") == sorted({*PIPELINES, "ports-to-vuln"})

    def test_build_resolves_a_yaml_pipeline_by_name(self, tmp_path: Path) -> None:
        _write(tmp_path, "ports-to-vuln", PORTS_TO_VULN)

        nodes = build("ports-to-vuln", pipelines_dir=tmp_path / "pipelines")

        assert [n.tool for n in nodes] == ["naabu", "httpx", "nuclei"]

    def test_python_builder_wins_over_a_yaml_file_of_the_same_name(self, tmp_path: Path) -> None:
        _write(tmp_path, "recon-to-vuln", "nodes:\n  - tool: httpx\n    stage: only\n")

        nodes = build("recon-to-vuln", pipelines_dir=tmp_path / "pipelines")

        assert [n.tool for n in nodes] == ["subfinder", "httpx", "nuclei"]

    def test_unknown_name_lists_both_kinds(self, tmp_path: Path) -> None:
        _write(tmp_path, "ports-to-vuln", PORTS_TO_VULN)

        with pytest.raises(RegistryError, match="recon-to-vuln.*ports-to-vuln|ports-to-vuln.*recon-to-vuln"):
            build("nope", pipelines_dir=tmp_path / "pipelines")

    def test_recon_options_are_ignored_for_yaml_pipelines_with_a_warning(self, tmp_path: Path, caplog) -> None:
        _write(tmp_path, "ports-to-vuln", PORTS_TO_VULN)

        with caplog.at_level("WARNING", logger="cyberfw.pipelines"):
            nodes = build("ports-to-vuln", pipelines_dir=tmp_path / "pipelines", include_ffuf=True)

        assert [n.tool for n in nodes] == ["naabu", "httpx", "nuclei"]
        assert any("include_ffuf" in r.getMessage() for r in caplog.records)


class TestShippedPipelineFiles:
    """Every pipelines/*.yaml committed to the repository must load and only use tools
    that are both registered in registry.yaml and backed by an adapter."""

    def test_repo_pipelines_load_and_reference_known_tools(self) -> None:
        from cyberfw.manager.registry import load_registry
        from cyberfw.tools import ADAPTERS

        files = discover_pipelines(REPO_ROOT / "pipelines")
        assert files, "expected at least one shipped pipeline file"
        registry = load_registry(REPO_ROOT / "registry.yaml")
        for name, path in files.items():
            for node in load_pipeline_file(path):
                assert node.tool in registry, f"{name}: {node.tool} is not in registry.yaml"
                assert node.tool in ADAPTERS, f"{name}: {node.tool} has no adapter"
