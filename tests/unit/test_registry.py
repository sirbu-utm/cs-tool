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

    def test_source_defaults_to_github(self) -> None:
        spec = ToolSpec(name="x", repo="org/repo", asset_patterns=[])
        assert spec.source == "github"
        assert spec.is_local is False


class TestLocalSource:
    """A `source: local` tool is one already on the machine — not downloaded."""

    def test_a_local_tool_needs_no_repo(self, tmp_path: Path) -> None:
        path = tmp_path / "registry.yaml"
        path.write_text(yaml.dump({"nmap": {"source": "local", "binary": "nmap"}}), encoding="utf-8")

        spec = load_registry(path).require("nmap")

        assert spec.is_local is True
        assert spec.binary == "nmap"
        assert spec.repo == ""

    def test_a_local_tool_may_pin_an_explicit_path(self, tmp_path: Path) -> None:
        path = tmp_path / "registry.yaml"
        path.write_text(
            yaml.dump({"nmap": {"source": "local", "binary": "nmap", "path": "/opt/nmap/bin/nmap"}}),
            encoding="utf-8",
        )

        assert load_registry(path).require("nmap").path == "/opt/nmap/bin/nmap"

    def test_a_github_tool_still_requires_a_repo(self, tmp_path: Path) -> None:
        path = tmp_path / "registry.yaml"
        path.write_text(yaml.dump({"x": {"asset_patterns": [], "binary": "x"}}), encoding="utf-8")

        with pytest.raises(RegistryError, match="repo"):
            load_registry(path)

    def test_an_unknown_source_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "registry.yaml"
        path.write_text(yaml.dump({"x": {"source": "ftp", "binary": "x"}}), encoding="utf-8")

        with pytest.raises(RegistryError, match="source"):
            load_registry(path)


class TestVersionPinning:
    def test_version_defaults_to_latest(self, tmp_path: Path) -> None:
        path = tmp_path / "registry.yaml"
        path.write_text(yaml.dump({"x": {"repo": "o/x", "asset_patterns": []}}), encoding="utf-8")
        spec = load_registry(path).require("x")
        assert spec.version == "latest"
        assert spec.pinned_version is None

    def test_pinned_tag_is_kept_and_normalised(self, tmp_path: Path) -> None:
        path = tmp_path / "registry.yaml"
        path.write_text(
            yaml.dump({"x": {"repo": "o/x", "asset_patterns": [], "version": "v2.6.6"}}), encoding="utf-8"
        )
        spec = load_registry(path).require("x")
        assert spec.version == "v2.6.6"
        assert spec.pinned_version == "2.6.6"


class TestLegacyIntegrityKeys:
    """1.x `sha256:` / `needs_checksum:` moved to tools.lock: still loadable, ignored, flagged."""

    def test_they_load_with_a_warning_pointing_at_tools_lock(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        path = tmp_path / "registry.yaml"
        block = {"repo": "o/x", "asset_patterns": [], "needs_checksum": True, "sha256": {"x.zip": "not-hex"}}
        path.write_text(yaml.dump({"x": block}), encoding="utf-8")

        with caplog.at_level("WARNING", logger="cyberfw.manager"):
            spec = load_registry(path).require("x")

        assert spec.repo == "o/x"
        assert not hasattr(spec, "sha256") and not hasattr(spec, "needs_checksum")
        assert any("tools.lock" in r.getMessage() for r in caplog.records)
