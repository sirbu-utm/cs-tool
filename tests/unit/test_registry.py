"""Unit tests for the tool registry loader."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from cyberfw.exceptions import RegistryError
from cyberfw.manager.registry import ToolRegistry, ToolSpec, load_registry


class TestLoadRegistry:
    def test_loads_minimal_registry(self, tmp_path: Path) -> None:
        data = {
            "foo": {"repo": "org/foo", "asset_patterns": ["*linux*amd64*"], "binary": "foo"},
        }
        path = tmp_path / "registry.yaml"
        path.write_text(yaml.dump(data), encoding="utf-8")
        registry = load_registry(path)
        assert len(registry) == 1
        assert "foo" in registry
        spec = registry.require("foo")
        assert spec.repo == "org/foo"
        assert spec.asset_patterns == ["*linux*amd64*"]

    def test_sets_name_from_key(self, tmp_path: Path) -> None:
        data = {"bar": {"repo": "org/bar", "asset_patterns": []}}
        path = tmp_path / "registry.yaml"
        path.write_text(yaml.dump(data), encoding="utf-8")
        registry = load_registry(path)
        assert registry.require("bar").name == "bar"

    def test_defaults_applied(self, tmp_path: Path) -> None:
        data = {"x": {"repo": "o/x", "asset_patterns": []}}
        path = tmp_path / "registry.yaml"
        path.write_text(yaml.dump(data), encoding="utf-8")
        spec = load_registry(path).require("x")
        assert spec.archive == "auto"
        assert spec.needs_checksum is True
        assert spec.check_deps == []

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(RegistryError, match="not found"):
            load_registry(tmp_path / "nope.yaml")

    def test_not_a_mapping_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "registry.yaml"
        path.write_text("- foo\n- bar\n", encoding="utf-8")
        with pytest.raises(RegistryError, match="must be a mapping"):
            load_registry(path)


class TestToolRegistry:
    def _registry(self, names: list[str] | None = None) -> ToolRegistry:
        names = names or ["alpha", "beta", "gamma"]
        tools = {
            n: ToolSpec(name=n, repo=f"o/{n}", asset_patterns=["*"]) for n in names
        }
        return ToolRegistry(tools)

    def test_contains_and_get(self) -> None:
        reg = self._registry()
        assert "beta" in reg
        assert reg.get("beta") is not None
        assert reg.get("nope") is None

    def test_require_unknown_raises(self) -> None:
        with pytest.raises(RegistryError, match="Unknown tool"):
            self._registry().require("nope")

    def test_names_sorted(self) -> None:
        assert self._registry().names() == ["alpha", "beta", "gamma"]

    def test_iter(self) -> None:
        assert set(self._registry()) == {"alpha", "beta", "gamma"}

    def test_len(self) -> None:
        assert len(self._registry(["a", "b"])) == 2


class TestToolSpec:
    def test_repo_split(self) -> None:
        spec = ToolSpec(name="x", repo="org/repo", asset_patterns=[])
        assert spec.repo_owner == "org"
        assert spec.repo_name == "repo"
