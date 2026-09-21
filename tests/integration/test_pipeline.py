"""Integration test: a fake tools_bin drives a real pipeline end-to-end.

No network and no real binaries. Fake executables shadow the three tools of the
``recon-to-vuln`` pipeline and print tool-appropriate JSONL, so the whole chain
— seed → Subfinder → Httpx → Nuclei → records, threading and context store — is
exercised against the production adapters and engine.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from cyberfw.config import Settings
from cyberfw.manager import ToolManager, load_registry
from cyberfw.pipeline.context import SessionContext
from cyberfw.pipeline.engine import PipelineEngine
from cyberfw.pipelines import build

#: JSONL each fake tool prints, keyed by its argv role.
_FAKE_OUTPUT = {
    "subfinder": '{"host": "api.example.com", "source": "stub"}\n',
    "httpx": '{"url": "https://api.example.com/", "status_code": 200, "title": "API"}\n',
    "nuclei": '{"template-id": "stub-check", "matched-at": "https://api.example.com/", '
              '"info": {"name": "Stub check", "severity": "low"}}\n',
}


def _make_fake_tool(tools_dir: Path, name: str) -> Path:
    """Write an executable ``name`` that prints :data:`_FAKE_OUTPUT[name]`."""
    path = tools_dir / name
    path.write_text("#!/usr/bin/env bash\n" + f'printf "%s" \'{_FAKE_OUTPUT[name]}\'\n', encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


def _write_registry(tmp_path: Path) -> Path:
    registry_path = tmp_path / "registry.yaml"
    registry_path.write_text(
        "\n".join(
            f"{name}:\n  repo: org/{name}\n  asset_patterns: []\n  binary: {name}\n"
            for name in ("subfinder", "httpx", "nuclei")
        ),
        encoding="utf-8",
    )
    return registry_path


def _engine(tmp_path: Path) -> PipelineEngine:
    tools_dir = tmp_path / "tools_bin"
    tools_dir.mkdir(parents=True, exist_ok=True)
    for name in _FAKE_OUTPUT:
        _make_fake_tool(tools_dir, name)
    settings = Settings(root_dir=tmp_path, tools_dir=tools_dir, reports_dir=tmp_path / "reports")
    settings.ensure_dirs()
    manager = ToolManager(settings, load_registry(_write_registry(tmp_path)))
    context = SessionContext(tmp_path / "reports", "int-sess")
    return PipelineEngine(settings, manager, context=context)


class TestReconToVuln:
    async def test_full_pipeline(self, tmp_path: Path) -> None:
        engine = _engine(tmp_path)
        nodes = build("recon-to-vuln")
        result = await engine.run(nodes, seed="example.com")

        assert result.succeeded()
        # subfinder + httpx + nuclei each emit exactly one record
        assert len(result.nodes) == 3
        assert [n.node.tool for n in result.nodes] == ["subfinder", "httpx", "nuclei"]
        assert all(n.ok for n in result.nodes)
        assert len(result.records) == 3
        assert result.totals_by_tool == {"subfinder": 1, "httpx": 1, "nuclei": 1}

    async def test_records_persisted_to_context_store(self, tmp_path: Path) -> None:
        engine = _engine(tmp_path)
        await engine.run(build("recon-to-vuln"), seed="example.com")
        assert engine.context is not None
        # the last stage's records are readable back from the context store
        assert engine.context.targets("vulns") == ["https://api.example.com/"]

    async def test_unknown_pipeline_raises(self, tmp_path: Path) -> None:
        from cyberfw.exceptions import RegistryError

        with pytest.raises(RegistryError, match="Unknown pipeline"):
            build("does-not-exist")
