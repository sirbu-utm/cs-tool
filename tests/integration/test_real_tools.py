"""Integration tests against the REAL precompiled binaries in ``tools_bin/``.

Opt-in: marked ``integration`` and excluded from the default run / CI gate
(see ``addopts`` in pyproject). Run explicitly with::

    pytest -m integration -q

Why this tier exists
--------------------
Every other test drives *fake* shebang scripts, so none of them can catch the
most common real-world break: an adapter building a command the actual tool
rejects. That class of bug bit this project repeatedly (subfinder/httpx using
``-jsonl`` instead of ``-json``, gowitness ``single`` vs ``scan single``,
gitleaks ``detect`` vs ``dir``, rustscan's greppable format). These tests run
the genuine binaries and assert they *accept* the adapter's command — a wrong
flag makes the tool print "flag provided but not defined" / usage and is caught
immediately.

Each test skips cleanly when its binary is missing, and network-dependent tests
skip when offline, so the suite never hard-fails on a machine that simply lacks
a tool or connectivity.
"""

from __future__ import annotations

import contextlib
import socket
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from cyberfw.manager.registry import ToolSpec
from cyberfw.pipeline.executor import run_stage
from cyberfw.tools import adapter_for
from cyberfw.tools.base import BaseTool, ToolContext

pytestmark = pytest.mark.integration

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_TOOLS_DIR = _REPO_ROOT / "tools_bin"

#: Substrings that mean the real tool REJECTED the adapter's command. This is
#: exactly the failure mode fake-binary tests cannot see.
_FLAG_REJECTIONS = (
    "flag provided but not defined",
    "unknown command",
    "unknown flag",
    "unknown shorthand flag",
    "Either -w or --input-cmd",  # ffuf: missing wordlist
)


def _binary(name: str) -> Path | None:
    for candidate in (_TOOLS_DIR / f"{name}.exe", _TOOLS_DIR / name):
        if candidate.is_file():
            return candidate
    return None


def _adapter(name: str) -> BaseTool:
    binary = _binary(name)
    if binary is None:
        pytest.skip(f"{name}: binary not present in tools_bin/ (run `cyberfw init {name}`)")
    spec = ToolSpec(name=name, repo=f"org/{name}", asset_patterns=[], binary=name)
    return adapter_for(spec, binary)


def _online(host: str = "example.com", port: int = 443, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _require_online() -> None:
    if not _online():
        pytest.skip("no network connectivity")


def _run(cmd: list[str], timeout: float) -> tuple[int | None, str]:
    """Run the real tool; return (returncode, stdout+stderr).

    A timeout is treated as success for flag-acceptance purposes: the tool was
    happily working (not rejecting our flags) when we cut it off.
    """
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        def _decode(blob: object) -> str:
            if isinstance(blob, bytes):
                return blob.decode("utf-8", "replace")
            return "" if blob is None else str(blob)

        return None, _decode(exc.stdout) + _decode(exc.stderr)


def _assert_flags_accepted(name: str, blob: str) -> None:
    for signature in _FLAG_REJECTIONS:
        assert signature not in blob, f"{name} rejected the adapter's command ({signature!r}):\n{blob[:500]}"


@contextlib.contextmanager
def _open_port() -> Iterator[int]:
    """A throwaway TCP listener on 127.0.0.1 so a port scan has a real hit."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.3)
    stop = threading.Event()

    def _accept() -> None:
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
            except OSError:
                pass

    thread = threading.Thread(target=_accept, daemon=True)
    thread.start()
    try:
        yield srv.getsockname()[1]
    finally:
        stop.set()
        srv.close()
        thread.join(timeout=1.0)


# -- ProjectDiscovery web/OSINT tools (network) --------------------------------
def test_subfinder_command_accepted() -> None:
    _require_online()
    adapter = _adapter("subfinder")
    cmd = adapter.build_cmd(ToolContext(target="example.com"))
    code, blob = _run(cmd, timeout=60)
    _assert_flags_accepted("subfinder", blob)
    assert code in (0, None), f"subfinder exited {code}: {blob[:300]}"


def test_httpx_probes_and_parses_a_record() -> None:
    _require_online()
    adapter = _adapter("httpx")
    cmd = adapter.build_cmd(ToolContext(target="https://example.com"))
    code, blob = _run(cmd, timeout=60)
    _assert_flags_accepted("httpx", blob)
    assert code == 0
    assert '"status_code"' in blob or '"url"' in blob


def test_nuclei_command_accepted() -> None:
    _require_online()
    adapter = _adapter("nuclei")
    cmd = adapter.build_cmd(ToolContext(target="https://example.com"))
    # nuclei scans for minutes; a short window is enough to prove it accepted
    # our flags and started rather than bailing on a bad flag.
    _code, blob = _run(cmd, timeout=25)
    _assert_flags_accepted("nuclei", blob)


def test_ffuf_command_accepted(tmp_path: Path) -> None:
    _require_online()
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("index\nrobots.txt\nadmin\n", encoding="utf-8")
    adapter = _adapter("ffuf")
    cmd = adapter.build_cmd(ToolContext(target="https://example.com", extra_input=str(wordlist)))
    code, blob = _run(cmd, timeout=60)
    _assert_flags_accepted("ffuf", blob)
    assert code == 0, f"ffuf exited {code}: {blob[:300]}"


# -- Port scanners (local, deterministic) --------------------------------------
def test_rustscan_command_accepted() -> None:
    adapter = _adapter("rustscan")
    with _open_port() as port:
        cmd = adapter.build_cmd(ToolContext(target=f"127.0.0.1:{port}"))
        code, blob = _run(cmd, timeout=60)
    _assert_flags_accepted("rustscan", blob)
    assert code in (0, None)


def test_naabu_command_accepted() -> None:
    adapter = _adapter("naabu")
    cmd = adapter.build_cmd(ToolContext(target="127.0.0.1"))
    code, blob = _run(cmd, timeout=60)
    if code in (126, 127) or "permission denied" in blob.lower():
        pytest.skip("naabu needs elevated privileges / raw sockets here")
    _assert_flags_accepted("naabu", blob)


# -- gitleaks (local, exercises the buffered JSON-array parse) ------------------
async def test_gitleaks_finds_a_planted_secret(tmp_path: Path) -> None:
    adapter = _adapter("gitleaks")
    (tmp_path / "leak.txt").write_text(
        'gitlab_token = "glpat-12345678901234567890"\n', encoding="utf-8"
    )
    cmd = adapter.build_cmd(ToolContext(target=str(tmp_path)))
    records = await run_stage(
        cmd,
        tool="gitleaks",
        stage="secrets",
        context=None,
        parse_buffer=adapter.parse_output if adapter.buffered else None,
    )
    assert any(r.kind == "secret" for r in records), "gitleaks did not report the planted secret"


# -- gowitness (local, needs a headless Chrome) --------------------------------
def test_gowitness_command_accepted() -> None:
    from cyberfw.tools.gowitness import _find_chrome

    if _find_chrome() is None:
        pytest.skip("gowitness needs a headless Chrome/Chromium, none found")
    _require_online()
    adapter = _adapter("gowitness")
    cmd = adapter.build_cmd(ToolContext(target="https://example.com"))
    _code, blob = _run(cmd, timeout=90)
    _assert_flags_accepted("gowitness", blob)
