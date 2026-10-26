"""Vault file helpers: filename sanitizing, atomic streaming copy, read-only flag.

On Windows "read-only" is the file attribute: it stops accidental edits, not a determined
administrator. That is why SHA-256 hashes and the ledger exist.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
from pathlib import Path

MAX_NAME = 100


def sanitize_filename(name: str) -> str:
    """Keep ASCII letters, digits, '.', '-', '_'; cap length; never start with a dot."""
    clean = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    clean = re.sub(r"^\.+", lambda m: "_" * len(m.group()), clean)
    if len(clean) > MAX_NAME:
        stem, dot, ext = clean.rpartition(".")
        ext = ext[:16]
        clean = (stem[: MAX_NAME - len(ext) - 1] + "." + ext) if dot and stem else clean[:MAX_NAME]
    return clean or "file"


def make_read_only(path: Path) -> None:
    """Set the read-only flag."""
    os.chmod(path, stat.S_IREAD)


def make_writable(path: Path) -> None:
    """Clear the read-only flag."""
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)


def is_read_only(path: Path) -> bool:
    """True when the file has no write permission."""
    return not os.access(path, os.W_OK)


def remove_file(path: Path) -> None:
    """Delete a (possibly read-only) file, ignoring a missing one."""
    if path.exists():
        make_writable(path)
        path.unlink()


def copy_atomic(src: Path, dest: Path) -> None:
    """Stream-copy src to dest via a temporary name, then rename atomically."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    try:
        shutil.copyfile(src, tmp)
        os.replace(tmp, dest)
    finally:
        if tmp.exists():
            tmp.unlink()
