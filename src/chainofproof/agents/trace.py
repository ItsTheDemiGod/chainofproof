"""Run trace: ``trace.jsonl``, one canonical-JSON line per step, written line by line.

A trace line holds ids, counts, hashes, statuses, tokens and timings, plus the model's short
rationale; never raw evidence content. ``fsync`` happens at the end of each round (``flush``).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from chainofproof.custody.hashing import canonical_json, sha256_file


class Trace:
    """Append-only writer for one run's trace file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.step = 0
        self._f = path.open("a", encoding="utf-8", newline="\n")

    def add(self, role: str, action: str, **fields: Any) -> dict[str, Any]:
        """Write one step line and return it."""
        self.step += 1
        rec = {"step": self.step, "role": role, "action": action,
               **{k: v for k, v in fields.items() if v is not None}}  # fmt: skip
        self._f.write(canonical_json(rec) + "\n")
        return rec

    def flush(self) -> None:
        """Flush and fsync (called at the end of every round and when the run ends)."""
        self._f.flush()
        os.fsync(self._f.fileno())

    def close(self) -> str:
        """Flush, close and return the sha256 of the trace file."""
        if not self._f.closed:
            self.flush()
            self._f.close()
        return sha256_file(self.path)


def read_trace(path: Path) -> list[dict[str, Any]]:
    """All lines of a trace file."""
    return [json.loads(x) for x in Path(path).read_text(encoding="utf-8").splitlines() if x]


def tool_sequence(lines: list[dict[str, Any]]) -> list[tuple[str, str, str, bool]]:
    """(role, tool, args_sha256, ok) of every tool call, in order: what a replay must reproduce."""
    return [(x["role"], x["tool"], x["args_sha256"], bool(x.get("ok")))
            for x in lines if x["action"] == "tool"]  # fmt: skip
