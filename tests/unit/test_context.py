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

    ``append`` is synchronous (open/write/close with no await in between), so under a
    single event loop no other coroutine can run mid-write; this pins that property.
    """
    ctx = SessionContext(tmp_path, "sess")
    total, per_worker = 40, 25

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
