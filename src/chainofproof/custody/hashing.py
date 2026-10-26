"""Hashing and canonical-JSON helpers."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

CHUNK = 1024 * 1024  # 1 MiB


def sha256_file(path: Path) -> str:
    """SHA-256 of a file, streamed in 1 MiB chunks."""
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """SHA-256 of bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    """SHA-256 of text encoded as UTF-8."""
    return sha256_bytes(text.encode("utf-8"))


def canonical_json(obj: Any) -> str:
    """Deterministic JSON (sorted keys, compact). Raises TypeError on non-serializable values."""
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as e:
        raise TypeError(f"value is not JSON-serializable: {e}") from e


def sha256_json(obj: Any) -> str:
    """SHA-256 of the canonical JSON form of obj."""
    return sha256_text(canonical_json(obj))


def utc_now() -> datetime:
    """Timezone-aware current UTC time."""
    return datetime.now(UTC)


def iso_utc(dt: datetime) -> str:
    """ISO-8601 UTC with microseconds and trailing Z."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
