"""The Python API example in README.md runs as written — against the CLI tests' fake tools."""

from __future__ import annotations

import builtins
import re
from pathlib import Path

import pytest

from cyberfw import api

from .test_cli import _workspace  # noqa: F401 - the fake-tools workspace, autouse

README = Path(__file__).resolve().parents[2] / "README.md"
FENCE = "`" * 3


def _api_section() -> str:
    text = README.read_text(encoding="utf-8")
    return text[text.index("## Python API") : text.index("## Разработка")]


def test_the_readme_example_runs(capsys: pytest.CaptureFixture[str]) -> None:
    example = re.search(FENCE + r"python\n(.*?)\n" + FENCE, _api_section(), re.S)
    assert example is not None, "the Python API section shows an example"

    with pytest.raises(SystemExit) as stopped:
        exec(compile(example[1], "README.md", "exec"), {})  # noqa: S102 - the example is the test

    lines = capsys.readouterr().out.splitlines()
    assert "done: scan" in lines and lines[-1].startswith("True ")
    assert stopped.value.code == 0


def test_the_errors_the_readme_names_can_be_caught_from_the_api() -> None:
    named = set(re.findall(r"`(\w+Error)`", _api_section())) - set(dir(builtins))

    assert named and {name for name in named if name not in api.__all__ or not hasattr(api, name)} == set()
