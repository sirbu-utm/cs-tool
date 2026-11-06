"""Nobody answers through the null device: a run with its input or output thrown away never asks."""

from __future__ import annotations

import io
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from cyberfw.cli import common
from cyberfw.logging import console

from . import test_cli as base

REPO = Path(__file__).resolve().parents[2]
PIPELINE = "nodes:\n  - {tool: subfinder, stage: hosts}\n"


@pytest.fixture
def null_input() -> Iterator[io.TextIOWrapper]:
    with open(os.devnull, encoding="utf-8") as stream:
        yield stream


@pytest.fixture
def null_output() -> Iterator[io.TextIOWrapper]:
    with open(os.devnull, "w", encoding="utf-8") as stream:
        yield stream


@pytest.fixture
def pipe_ends() -> Iterator[tuple[io.TextIOWrapper, io.TextIOWrapper]]:
    read, write = os.pipe()
    with os.fdopen(read, encoding="utf-8") as reading, os.fdopen(write, "w", encoding="utf-8") as writing:
        yield reading, writing


def test_the_null_device_is_told_from_anything_else(
    null_input: io.TextIOWrapper,
    null_output: io.TextIOWrapper,
    pipe_ends: tuple[io.TextIOWrapper, io.TextIOWrapper],
    tmp_path: Path,
) -> None:
    assert common._is_null_device(null_input) and common._is_null_device(null_output)

    reading, writing = pipe_ends
    assert not common._is_null_device(reading) and not common._is_null_device(writing)
    with (tmp_path / "out.txt").open("w", encoding="utf-8") as file:
        assert not common._is_null_device(file)
    assert not common._is_null_device(io.StringIO())  # no file behind it: a test's or a library's stream


def test_no_stream_at_all_is_the_same_as_the_null_device() -> None:
    assert common._is_null_device(None)  # how pythonw and a detached process start


@pytest.mark.skipif(os.name == "nt", reason="pty is POSIX; a Windows console takes a real console to test")
def test_a_terminal_is_not_the_null_device() -> None:
    import pty

    primary, secondary = pty.openpty()
    try:
        with os.fdopen(os.dup(secondary), encoding="utf-8") as stream:
            assert stream.isatty()
            assert not common._is_null_device(stream)
    finally:
        os.close(primary)
        os.close(secondary)


def test_a_question_nobody_can_answer_is_not_asked(
    monkeypatch: pytest.MonkeyPatch,
    null_input: io.TextIOWrapper,
    null_output: io.TextIOWrapper,
    pipe_ends: tuple[io.TextIOWrapper, io.TextIOWrapper],
) -> None:
    reading, writing = pipe_ends
    monkeypatch.setattr(console, "is_interactive", True)

    monkeypatch.setattr(sys, "stdin", null_input)
    monkeypatch.setattr(sys, "stdout", writing)
    assert not common._is_interactive()  # `< NUL`, `< /dev/null`

    monkeypatch.setattr(sys, "stdin", reading)
    monkeypatch.setattr(sys, "stdout", null_output)
    assert not common._is_interactive()  # `> NUL`: on Windows Rich takes it for a terminal

    monkeypatch.setattr(sys, "stdout", writing)
    assert common._is_interactive()  # `echo y | cyberfw …`: the answers come through the pipe


def _cyberfw_thrown_away(workspace: Path, *args: str) -> int:
    """The real process, under a user's TERM (conftest's "dumb" alone keeps Rich from asking):
    CliRunner's own streams are not what isatty() is wrong about."""
    path = os.pathsep.join(filter(None, [str(REPO), os.environ.get("PYTHONPATH")]))
    env = {**os.environ, "PYTHONPATH": path, "TERM": "xterm-256color", "CYBERFW_ANIMATIONS": "false"}
    return subprocess.run(
        [sys.executable, "-m", "cyberfw", *args],
        cwd=workspace, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    ).returncode


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    base._write_fake_binaries(tmp_path / "tools_bin")
    base._write_registry(tmp_path)
    (tmp_path / "pipelines").mkdir()
    (tmp_path / "pipelines" / "hosts.yaml").write_text(PIPELINE, encoding="utf-8")
    return tmp_path


def test_a_scan_with_its_input_and_output_thrown_away_still_saves_its_report(workspace: Path) -> None:
    code = _cyberfw_thrown_away(
        workspace, "pipeline", "hosts", "-t", "example.com", "--session", "s1", "--no-mail", "--no-takeover", "--no-intel", "--no-vt"
    )

    assert code == 0
    assert (workspace / "reports" / "s1" / "report.json").is_file()


def test_a_run_with_its_input_and_output_thrown_away_keeps_to_its_default(workspace: Path) -> None:
    code = _cyberfw_thrown_away(workspace, "run", "subfinder", "-t", "example.com")

    assert code == 0
    assert not (workspace / "reports").exists() or not list((workspace / "reports").iterdir())
