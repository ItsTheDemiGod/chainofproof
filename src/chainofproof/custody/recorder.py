"""Helpers for recording tool calls in the ledger (wired to real tools in Phase 3)."""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Any

from chainofproof.custody.hashing import sha256_bytes, sha256_json, sha256_text
from chainofproof.custody.ledger import Ledger
from chainofproof.schemas.custody import LedgerEntry


def hash_output(output: bytes | str | Any) -> str:
    """Hash tool output: bytes -> sha256_bytes, str -> sha256_text, else canonical JSON."""
    if isinstance(output, bytes | bytearray):
        return sha256_bytes(bytes(output))
    if isinstance(output, str):
        return sha256_text(output)
    return sha256_json(output)


def record_tool_call(
    ledger: Ledger,
    actor: str,
    command: str,
    input_hashes: Sequence[str],
    output: bytes | str | Any,
    details: dict[str, Any] | None = None,
) -> LedgerEntry:
    """Append a ledger entry for a finished tool call, hashing its output."""
    return ledger.append(
        actor=actor,
        action="tool_call",
        command=command,
        input_hashes=input_hashes,
        output_hash=hash_output(output),
        details=details or {},
    )


class ToolRun:
    """Context manager: ledger entry with duration on exit, or the exception type on failure.

    Set ``run.output`` inside the block to have it hashed into ``output_hash``.
    """

    def __init__(
        self, ledger: Ledger, actor: str, command: str, input_hashes: Sequence[str]
    ) -> None:
        self.ledger, self.actor, self.command = ledger, actor, command
        self.input_hashes = list(input_hashes)
        self.output: Any = None
        self.entry: LedgerEntry | None = None
        self._t0 = 0.0

    def __enter__(self) -> ToolRun:
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        details: dict[str, Any] = {"duration_s": round(time.perf_counter() - self._t0, 6)}
        if exc_type is not None:
            details["status"] = "failed"
            details["error_type"] = exc_type.__name__
            details["error_message"] = str(exc)[:300]
            action, out = "tool_call_failed", None
        else:
            details["status"] = "ok"
            action = "tool_call"
            out = hash_output(self.output) if self.output is not None else None
        self.entry = self.ledger.append(
            self.actor, action, self.command, self.input_hashes, out, details
        )
        return False
