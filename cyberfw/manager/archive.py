"""Safe archive extraction shared by the tool installer and Chromium installer.

The guarantees live here, in one place, so every downloaded archive — a tool
from GitHub Releases or a portable Chromium from Chrome for Testing — is unpacked
under the same rules:

* **Zip Slip guard** — a member whose path escapes the destination directory is
  refused (:func:`safe_member`).
* **Extraction cap** — the sum of members' declared sizes is checked against a
  limit before anything is written, so a forged-size decompression bomb cannot
  fill the disk (:func:`assert_extract_size`). The stdlib bounds each member to
  its declared size, so a member that lies about being small still cannot inflate
  past the checked total.
"""

from __future__ import annotations

import os
import shutil
import zipfile
from pathlib import Path

from cyberfw.exceptions import ArchiveSafetyError, DownloadError

__all__ = ["normalize", "safe_member", "assert_extract_size", "safe_extract_zip"]


def normalize(name: str) -> str:
    """Collapse ``..``/``.`` segments and normalise separators to the OS form."""
    return os.path.normpath(name.replace("\\", "/"))


def safe_member(member_rel: str, dest: Path) -> Path:
    """Resolve ``member_rel`` under ``dest``, refusing any path that escapes it."""
    target = (dest / member_rel).resolve()
    root = dest.resolve()
    if target != root and root not in target.parents:
        raise ArchiveSafetyError(f"Archive member escapes {dest.name}/: {member_rel!r}")
    return target


def assert_extract_size(total: int, archive_name: str, limit: int) -> None:
    """Refuse an archive whose members would extract to more than ``limit`` bytes."""
    if total > limit:
        raise DownloadError(
            f"Archive {archive_name} would extract to {total} bytes (limit {limit})"
        )


def safe_extract_zip(archive_path: Path, dest: Path, *, max_size: int) -> None:
    """Extract a zip into ``dest`` with the Zip Slip and size guards applied."""
    with zipfile.ZipFile(archive_path) as zf:
        assert_extract_size(sum(i.file_size for i in zf.infolist()), archive_path.name, max_size)
        for info in zf.infolist():
            target = safe_member(normalize(info.filename), dest)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
