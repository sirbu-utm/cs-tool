"""The Python API example in README.md runs as written — against the CLI tests' fake tools."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from .test_cli import _workspace  # noqa: F401 - the fake-tools workspace, autouse

README = Path(__file__).resolve().parents[2] / "README.md"
FENCE = "`" * 3


def test_the_readme_example_runs(capsys: pytest.CaptureFixture[str]) -> None:
    text = README.read_text(encoding="utf-8")
    section = text[text.index("## Python API") : text.index("## Разработка")]
    example = re.search(FENCE + r"python\n(.*?)\n" + FENCE, section, re.S)
    assert example is not None, "the Python API section shows an example"

    with pytest.raises(SystemExit) as stopped:
        exec(compile(example[1], "README.md", "exec"), {})  # noqa: S102 - the example is the test

    lines = capsys.readouterr().out.splitlines()
    assert "done: scan" in lines and lines[-1].startswith("True ")
    assert stopped.value.code == 0
