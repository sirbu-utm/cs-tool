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
    directory deep. The recursive scan looks inside ``tools_dir/<name>/`` (where
    installs live) before the whole ``tools_dir``, so resolving one tool never
    walks another's tree — notably the ~hundreds of files under
    ``tools_bin/chromium/``, which made the launcher's inventory pass slow.
    Raises :class:`ToolNotFoundError` with install guidance.
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

    # The per-tool directory first (the common, fast case), the whole tree only
    # as a fallback for the legacy flat layout.
    scan_roots = [root / name] if (root / name).is_dir() else []
    scan_roots.append(root)
    for scan_root in scan_roots:
        for candidate in scan_root.rglob("*"):
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
    """Check ``archive_path`` against the SHA-256 upstream lists for ``asset_name``.

    ``checksums_text`` is the body of ``checksums.txt``: ``<sha256>  <name>``
    lines, where the name may carry a leading ``*`` (binary mode) or a
    directory. The name must equal ``asset_name`` exactly — a suffix match
    would take ``mytool_linux_amd64.zip``'s line for ``tool_linux_amd64.zip``.
    Returns True when an entry was found and matched, False when the file has
    no entry for this asset (the caller decides how loudly to report an
    unverified download); a present-but-mismatched entry raises
    :class:`ChecksumError` so a corrupted download is never unpacked.
    """
    if isinstance(checksums_text, bytes):
        checksums_text = checksums_text.decode("utf-8", errors="replace")
    entry: str | None = None
    for line in checksums_text.splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) != 2:
            continue
        digest, name = parts
        if name.lstrip("*").rsplit("/", 1)[-1] == asset_name:
            entry = digest
            break
    if entry is None:
        return False  # upstream publishes no checksum for this archive
    actual = sha256_hex(archive_path)
    if actual != entry.lower():
        raise ChecksumError(
            f"SHA-256 mismatch for {asset_name}: expected {entry.lower()}, got {actual}"
        )
    return True
