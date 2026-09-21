"""Single-file verification helpers: SHA-256 checksums and ``tools_bin`` state.

``cyberfw init`` and ``run`` call :func:`ensure_binary` to confirm a tool is
installed and executable before the pipeline spawns it, and :func:`init_tools`
to bring all registered tools up to date. ``needs_checksum`` tools additionally
cross-check the downloaded archive against ``checksums.txt`` published by the
release (when upstream provides one).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
from pathlib import Path

from cyberfw.exceptions import ChecksumError, ToolNotFoundError

__all__ = ["sha256_hex", "verify_checksum", "ensure_binary", "find_in_path", "is_executable"]

_HASH_CHUNK = 1 << 20


def sha256_hex(path: Path) -> str:
    """Return the lowercase hex SHA-256 of ``path`` (streaming)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_HASH_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def find_in_path(cmd: str) -> str | None:
    """Return the absolute path to ``cmd`` if it is on ``PATH`` (Windows-safe)."""
    return shutil.which(cmd)


def is_executable(path: Path) -> bool:
    """True when ``path`` exists and carries the execute bit (or is on Windows)."""
    if not path.exists():
        return False
    if os.name == "nt":
        try:
            with path.open("rb") as handle:
                signature = handle.read(2)
        except OSError:
            return False
        # Native Windows binaries are PE files. Keep project-local shebang
        # wrappers usable in tests and development environments.
        return signature in (b"MZ", b"#!")
    mode = path.stat().st_mode
    return bool(mode & stat.S_IEXEC)


def ensure_binary(tools_dir: Path, name: str, binary_hint: str | None = None) -> Path:
    """Locate the installed binary for ``name`` inside ``tools_dir``.

    Searches ``tools_dir/<name>`` first, then any extension Windows may add,
    then a recursive scan — ProjectDiscovery archives nest the binary one
    directory deep. Raises :class:`ToolNotFoundError` with install guidance.
    """
    root = Path(tools_dir)
    search = binary_hint or name

    candidates = [root / search]
    if os.name == "nt" and not search.lower().endswith(".exe"):
        candidates.insert(0, root / (search + ".exe"))

    inaccessible: list[Path] = []

    def _remember(path: Path) -> None:
        if path not in inaccessible:  # the recursive scan can re-hit a candidate
            inaccessible.append(path)

    for candidate in candidates:
        if not candidate.is_file():
            continue
        if is_executable(candidate):
            return candidate
        _remember(candidate)

    for candidate in root.rglob("*"):
        if not candidate.is_file():
            continue
        if candidate.name == search or candidate.stem == search:
            if is_executable(candidate):
                return candidate
            _remember(candidate)

    if inaccessible:
        locations = ", ".join(str(path) for path in inaccessible[:3])
        raise ToolNotFoundError(
            f"Tool {name!r} was downloaded but its executable could not be read or run: "
            f"{locations}. Windows Defender or another security product may have blocked "
            "the binary; restore/allow it and run `cyberfw init "
            f"{name}` again."
        )
    raise ToolNotFoundError(
        f"Tool {name!r} is not installed. Run `cyberfw init` to fetch its precompiled binary "
        f"into {root.resolve()} or check GITHUB_TOKEN for your release access."
    )


def verify_checksum(checksums_text: str | bytes, asset_name: str, archive_path: Path) -> bool:
    """True if ``archive_path`` matches the SHA-256 upstream lists for ``asset_name``.

    ``checksums_text`` is the body of ``checksums.txt``; filenames may carry a
    leading ``*``/`` `` (BSD/GPG signing style). A missing entry tolerates (the
    tool did not publish one for this asset); a present-but-mismatched entry
    raises :class:`ChecksumError` so a corrupted download is never unpacked.
    """
    if isinstance(checksums_text, bytes):
        checksums_text = checksums_text.decode("utf-8", errors="replace")
    entry: str | None = None
    for line in checksums_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.endswith(asset_name) or f"*{asset_name}" in line:
            entry = line.split()[0]
            break
    if entry is None:
        return True  # upstream publishes no checksum for this archive
    actual = sha256_hex(archive_path)
    if actual != entry.lower():
        raise ChecksumError(
            f"SHA-256 mismatch for {asset_name}: expected {entry.lower()}, got {actual}"
        )
    return True
