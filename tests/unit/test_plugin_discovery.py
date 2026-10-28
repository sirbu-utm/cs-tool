"""Finding plugin packages: from their metadata alone, each with its verified kind."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from cyberfw.manager.discovery import CODE_GROUP, MANIFEST_GROUP, Declared, discover, normalize

from ._dists import install

MANIFEST = "contract: 1\n"  # its content is not read here


def _ours(found: list[Declared]) -> list[Declared]:
    return [declared for declared in found if declared.package.startswith("cyberfw-")]


def test_both_groups_are_read_from_the_metadata(site: Path) -> None:
    install(site, "cyberfw-sample", version="0.3", manifests={"sample": "cyberfw_sample"},
            files={"cyberfw_sample/sample.yaml": MANIFEST})
    install(site, "cyberfw-bar", tools={"bar": "cyberfw_bar:PLUGIN"}, files={"cyberfw_bar/__init__.py": "PLUGIN = None\n"})

    assert _ours(discover()) == [
        Declared(tool="bar", package="cyberfw-bar", version="1.0", group=CODE_GROUP, value="cyberfw_bar:PLUGIN", kind="code"),
        Declared(tool="sample", package="cyberfw-sample", version="0.3", group=MANIFEST_GROUP, value="cyberfw_sample", kind="manifest"),
    ]


def test_finding_a_package_runs_none_of_its_code(site: Path) -> None:
    install(site, "cyberfw-boom", tools={"boom": "cyberfw_boom:PLUGIN"},
            files={"cyberfw_boom/__init__.py": "raise RuntimeError('cyberfw_boom was imported')\n"})

    assert [declared.tool for declared in _ours(discover())] == ["boom"]
    assert "cyberfw_boom" not in sys.modules


@pytest.mark.parametrize(
    ("files", "tools", "record", "kind"),
    [
        ({"cyberfw_k/k.yaml": MANIFEST}, None, True, "manifest"),
        ({"cyberfw_k/k.yaml": MANIFEST, "cyberfw_k/__init__.py": ""}, None, True, "code"),
        ({"cyberfw_k/k.yaml": MANIFEST, "cyberfw_k.pth": "import os\n"}, None, True, "code"),
        ({"cyberfw_k/k.yaml": MANIFEST, "cyberfw_k/fast.pyd": ""}, None, True, "code"),
        ({"cyberfw_k/k.yaml": MANIFEST}, {"other": "cyberfw_k:PLUGIN"}, True, "code"),
        ({"cyberfw_k/k.yaml": MANIFEST}, None, False, "code"),
    ],
    ids=["data only", "a .py file", "a .pth file", "a compiled module", "a code tool too", "files unlisted"],
)
def test_a_package_is_a_manifest_package_only_when_it_installed_no_python(
    site: Path, files: dict[str, str], tools: dict[str, str] | None, record: bool, kind: str
) -> None:
    install(site, "cyberfw-k", manifests={"k": "cyberfw_k"}, tools=tools, files=files, record=record)

    assert {declared.kind for declared in _ours(discover())} == {kind}


def test_package_names_are_compared_normalised(site: Path) -> None:
    install(site, "CyberFW_Sample.Extra", manifests={"sample": "cyberfw_sample"}, files={"cyberfw_sample/sample.yaml": MANIFEST})

    assert normalize("CyberFW_Sample.Extra") == "cyberfw-sample-extra"
    assert [declared.package for declared in _ours(discover())] == ["cyberfw-sample-extra"]


def test_a_distribution_whose_metadata_cannot_be_read_is_passed_over(site: Path) -> None:
    # Any installed distribution may be broken; none of them may stop cyberfw finding the rest.
    install(site, "cyberfw-sample", manifests={"sample": "cyberfw_sample"}, files={"cyberfw_sample/sample.yaml": MANIFEST})
    broken_points = site / "unrelated-1.0.dist-info"
    broken_points.mkdir()
    (broken_points / "METADATA").write_text("Metadata-Version: 2.1\nName: unrelated\nVersion: 1.0\n", encoding="utf-8")
    (broken_points / "entry_points.txt").write_text("[console_scripts]\nthis line has no equals sign\n", encoding="utf-8")
    nameless = site / "nameless-1.0.dist-info"
    nameless.mkdir()
    (nameless / "entry_points.txt").write_text("[cyberfw.tools]\nghost = ghost:PLUGIN\n", encoding="utf-8")

    assert [declared.tool for declared in _ours(discover())] == ["sample"]
