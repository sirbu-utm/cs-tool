"""Tests for the Context Store (per-stage JSONL persistence)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from cyberfw.pipeline.context import SessionContext
from cyberfw.pipeline.schemas import ToolRecord


async def test_concurrent_fan_out_appends_never_interleave(tmp_path: Path) -> None:
    """Many coroutines appending to one stage file (the ``_fan_out`` shape) must yield
    one valid JSON document per line — no torn writes, no sharing violations on Windows.

    ``append`` is synchronous (write + flush with no await in between), so under a
    single event loop no other coroutine can run mid-write; this pins that property.
    """
    total, per_worker = 40, 25

    with SessionContext(tmp_path, "sess") as ctx:

        async def worker(index: int) -> None:
            for n in range(per_worker):
                ctx.append(
                    "fuzz",
                    ToolRecord(tool="ffuf", target=f"https://h{index}.example.com/{n}", kind="fuzz"),
                )
                await asyncio.sleep(0)  # yield between writes to maximise interleaving pressure

        await asyncio.gather(*(worker(i) for i in range(total)))

    lines = (tmp_path / "sess" / "fuzz.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == total * per_worker
    parsed = [json.loads(line) for line in lines]  # raises on any torn line
    assert len({p["target"] for p in parsed}) == total * per_worker
    assert ctx.targets("fuzz") == [p["target"] for p in parsed]


def _count_opens(monkeypatch) -> list[int]:
    """Spy on ``Path.open`` (the real open still happens) and return a 1-cell counter."""
    counter = [0]
    real_open = Path.open

    def counting_open(self: Path, *args, **kwargs):
        counter[0] += 1
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", counting_open)
    return counter


def _rec(target: str) -> ToolRecord:
    return ToolRecord(tool="subfinder", target=target, kind="host")


def test_appends_to_one_stage_share_a_single_open_file(tmp_path: Path, monkeypatch) -> None:
    """Re-opening the JSONL file for every record costs an open() — and, on Windows, an
    antivirus scan — per finding; a stage's file must stay open across the run."""
    opens = _count_opens(monkeypatch)
    ctx = SessionContext(tmp_path, "sess")

    for n in range(50):
        ctx.append("hosts", _rec(f"h{n}.example.com"))
    ctx.close()

    assert opens[0] == 1


def test_records_are_readable_before_close(tmp_path: Path) -> None:
    """Crash-safety: every record reaches the file as it arrives, not at close()."""
    ctx = SessionContext(tmp_path, "sess")
    ctx.append("hosts", _rec("a.example.com"))

    assert ctx.targets("hosts") == ["a.example.com"]
    ctx.close()


def test_close_is_idempotent_and_the_store_stays_usable(tmp_path: Path, monkeypatch) -> None:
    opens = _count_opens(monkeypatch)
    ctx = SessionContext(tmp_path, "sess")
    ctx.append("hosts", _rec("a.example.com"))
    ctx.close()
    ctx.close()

    ctx.append("hosts", _rec("b.example.com"))  # reopened in append mode
    ctx.close()

    assert opens[0] == 2
    assert ctx.targets("hosts") == ["a.example.com", "b.example.com"]


def test_context_manager_closes_on_exit(tmp_path: Path, monkeypatch) -> None:
    opens = _count_opens(monkeypatch)
    with SessionContext(tmp_path, "sess") as ctx:
        ctx.append("hosts", _rec("a.example.com"))
    ctx.append("hosts", _rec("b.example.com"))
    ctx.close()

    assert opens[0] == 2
