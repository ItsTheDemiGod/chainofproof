"""Hash-chained, append-only JSONL ledger with a SQLite head anchor.

Each line holds one entry; ``entry_hash`` = sha256 of the canonical JSON of the entry without
``entry_hash`` and ``prev_hash`` links to the previous entry (64 zeros for the first). Editing,
deleting or reordering entries breaks the chain. Truncating the END cannot be seen from the chain
alone, so after each append the latest (ledger_id, count, entry_hash) is also written to the
``ledger_head`` table of the SQLite database; ``verify`` compares the two.

Limits: this is tamper-EVIDENT, not tamper-PROOF. An attacker who can rewrite BOTH the JSONL file
and the SQLite database can forge a consistent history. Publishing ``export_head()`` somewhere
outside the machine (e.g. printed in a report) strengthens the guarantee.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterable
from typing import Any

from pydantic import ValidationError

from chainofproof.config import Paths
from chainofproof.custody.db import connect
from chainofproof.custody.hashing import canonical_json, iso_utc, sha256_json, utc_now
from chainofproof.custody.locking import FileLock
from chainofproof.errors import UserError
from chainofproof.schemas.custody import (
    GENESIS_HASH,
    IntegrityResult,
    LedgerEntry,
    make_ledger_id,
)


class LedgerError(UserError):
    """The ledger cannot be read or appended to."""


def _compute_hash(raw: dict[str, Any]) -> str:
    return sha256_json({k: v for k, v in raw.items() if k != "entry_hash"})


def _id_number(ledger_id: str) -> int:
    return int(ledger_id.split("-")[1])


class Ledger:
    """Append-only ledger bound to ``paths.ledger_path``."""

    def __init__(self, paths: Paths) -> None:
        self.paths = paths
        self.path = paths.ledger_path
        self._lock = FileLock(self.path.with_name(self.path.name + ".lock"))

    # ---- writing -------------------------------------------------------------------------
    def append(
        self,
        actor: str,
        action: str,
        command: str | None = None,
        input_hashes: Iterable[str] = (),
        output_hash: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> LedgerEntry:
        """Append one entry (file lock held; last line re-read under the lock)."""
        details = details or {}
        canonical_json(details)  # fail early with a clear error if not serializable
        with self._lock:
            last = self._last_raw()
            n = _id_number(last["ledger_id"]) + 1 if last else 1
            # refuse to append over a truncated ledger: that would silently move the anchor
            head = self._check_head(n - 1, last and last["ledger_id"], last and last["entry_hash"])
            if head:
                raise LedgerError(head[0])
            raw: dict[str, Any] = {
                "ledger_id": make_ledger_id(n),
                "timestamp": iso_utc(utc_now()),
                "actor": actor,
                "action": action,
                "command": command,
                "input_hashes": list(input_hashes),
                "output_hash": output_hash,
                "details": details,
                "prev_hash": last["entry_hash"] if last else GENESIS_HASH,
            }
            raw["entry_hash"] = _compute_hash(raw)
            entry = LedgerEntry.model_validate_json(json.dumps(raw))
            self._write_line(json.dumps(raw, ensure_ascii=False))
            self._set_head(raw["ledger_id"], n, raw["entry_hash"])
        return entry

    def _write_line(self, line: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())

    def _last_raw(self) -> dict[str, Any] | None:
        """Parse the last line of the file, or None when the ledger is empty."""
        if not self.path.exists() or self.path.stat().st_size == 0:
            return None
        with self.path.open("rb") as f:
            size = f.seek(0, 2)
            block = 4096
            while True:
                start = max(0, size - block)
                f.seek(start)
                data = f.read(size - start)
                lines = data.rstrip(b"\n").split(b"\n")
                if len(lines) > 1 or start == 0:
                    break
                block *= 2
        try:
            raw = json.loads(lines[-1].decode("utf-8"))
            LedgerEntry.model_validate_json(json.dumps(raw))
        except (ValueError, ValidationError) as e:
            raise LedgerError(f"last ledger line is malformed; refusing to append: {e}") from e
        return raw

    def _set_head(self, ledger_id: str, count: int, entry_hash: str) -> None:
        conn = connect(self.paths.db_path)
        try:
            conn.execute(
                "INSERT INTO ledger_head(id, ledger_id, entry_count, entry_hash) "
                "VALUES (1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
                "ledger_id=excluded.ledger_id, entry_count=excluded.entry_count, "
                "entry_hash=excluded.entry_hash",
                (ledger_id, count, entry_hash),
            )
        finally:
            conn.close()

    # ---- reading -------------------------------------------------------------------------
    def read_all(self) -> list[LedgerEntry]:
        """All entries; raises LedgerError on a malformed line."""
        out = []
        for i, line in enumerate(self._lines(), 1):
            try:
                out.append(LedgerEntry.model_validate_json(line))
            except ValidationError as e:
                raise LedgerError(f"line {i} is malformed: {e.error_count()} error(s)") from e
        return out

    def tail(self, n: int) -> list[LedgerEntry]:
        """The last n entries."""
        return self.read_all()[-n:] if n > 0 else []

    def get(self, ledger_id: str) -> LedgerEntry | None:
        """One entry by ID, or None."""
        return next((e for e in self.read_all() if e.ledger_id == ledger_id), None)

    def _lines(self) -> list[str]:
        if not self.path.exists():
            return []
        text = self.path.read_text(encoding="utf-8")
        return [ln for ln in text.split("\n") if ln.strip()]

    # ---- verification --------------------------------------------------------------------
    def _scan_chain(self) -> tuple[list[str], list[tuple[str, str]]]:
        """Check the chain itself (IDs, links, hashes, genesis), ignoring the head anchor.

        Returns (problems, [(ledger_id, entry_hash), ...]) for the parseable entries.
        """
        problems: list[str] = []
        prev_hash, expected, last_id = GENESIS_HASH, 1, None
        ends: list[tuple[str, str]] = []
        for i, line in enumerate(self._lines(), 1):
            after = f" (after {last_id})" if last_id else ""
            try:
                raw = json.loads(line)
                entry = LedgerEntry.model_validate_json(line)
            except (ValueError, ValidationError) as e:
                problems.append(f"line {i}{after}: malformed entry ({type(e).__name__})")
                expected += 1
                continue
            lid = entry.ledger_id
            if lid != make_ledger_id(expected):
                problems.append(
                    f"{lid}: non-sequential ID (expected {make_ledger_id(expected)}); "
                    "entry deleted or reordered"
                )
            if entry.prev_hash != prev_hash:
                kind = "wrong genesis prev_hash" if i == 1 else "prev_hash mismatch (chain broken)"
                problems.append(f"{lid}: {kind}")
            if _compute_hash(raw) != entry.entry_hash:
                problems.append(f"{lid}: entry_hash mismatch (entry was modified)")
            prev_hash, last_id = entry.entry_hash, lid
            ends.append((lid, entry.entry_hash))
            expected = _id_number(lid) + 1
        return problems, ends

    def verify(self) -> IntegrityResult:
        """Check chain, sequence, genesis, schema and the SQLite head anchor."""
        problems, ends = self._scan_chain()
        count = len(self._lines())
        last_id, last_hash = ends[-1] if ends else (None, None)
        problems += self._check_head(count, last_id, last_hash)
        return IntegrityResult(ok=not problems, checked=count, problems=problems)

    def _read_head(self) -> sqlite3.Row | None:
        conn = connect(self.paths.db_path)
        try:
            return conn.execute("SELECT * FROM ledger_head WHERE id = 1").fetchone()
        finally:
            conn.close()

    def recover(self) -> tuple[IntegrityResult, str]:
        """Explicit crash recovery: re-sync the anchor when it lags the chain by exactly one entry.

        Acts only if the chain verifies internally, the chain end is exactly one entry ahead of
        the anchor, and the chain entry at the anchor's position matches the anchor's ID and hash.
        Anything else (truncation, tampering) is refused and nothing is changed.
        Returns (result, one-line message); ``result.ok`` is False when refused.
        """
        with self._lock:
            problems, ends = self._scan_chain()
            n, row = len(ends), self._read_head()
            refuse = self._recover_refusal(problems, ends, n, row)
            if refuse is None:
                return IntegrityResult(ok=True, checked=n), "ledger healthy: nothing to recover"
            if refuse == "":
                old = (row["ledger_id"], row["entry_count"])
                self._set_head(ends[-1][0], n, ends[-1][1])
            else:
                return IntegrityResult(ok=False, checked=n, problems=[refuse]), refuse
        self.append(
            "ledger",
            "ledger_recovered",
            details={
                "old_anchor_id": old[0],
                "old_anchor_count": old[1],
                "new_anchor_id": ends[-1][0],
                "new_anchor_count": n,
            },
        )
        msg = f"anchor advanced {old[0]} -> {ends[-1][0]}; ledger_recovered entry appended"
        return IntegrityResult(ok=True, checked=n + 1), msg

    @staticmethod
    def _recover_refusal(
        problems: list[str], ends: list[tuple[str, str]], n: int, row: sqlite3.Row | None
    ) -> str | None:
        """None = healthy (no-op), "" = recoverable, else the refusal reason."""
        tamper = "looks like truncation or tampering, not a crash; nothing changed"
        if problems:
            return f"refused: chain is broken ({problems[0]}); {tamper}"
        if row is None:
            return None if n == 0 else f"refused: no head anchor stored; {tamper}"
        count = row["entry_count"]
        if count == n and (row["ledger_id"], row["entry_hash"]) == ends[-1]:
            return None
        if count > n:
            return f"refused: anchor is ahead of the chain ({count} > {n}); {tamper}"
        if n - count != 1:
            return f"refused: chain is {n - count} entries ahead of the anchor (only 1); {tamper}"
        if ends[count - 1] != (row["ledger_id"], row["entry_hash"]):
            return f"refused: chain entry at the anchor position differs from the anchor; {tamper}"
        return ""

    def _check_head(self, count: int, last_id: str | None, last_hash: str | None) -> list[str]:
        row = self._read_head()
        if row is None:
            if count == 0:
                return []
            return ["ledger truncated or head anchor out of sync: no head anchor stored"]
        if (row["ledger_id"], row["entry_count"], row["entry_hash"]) != (last_id, count, last_hash):
            return [
                "ledger truncated or head anchor out of sync: "
                f"anchor={row['ledger_id']} (count {row['entry_count']}), "
                f"chain end={last_id} (count {count})"
            ]
        return []

    def export_head(self) -> dict[str, Any]:
        """Head info (ledger_id, count, entry_hash) for publishing outside the machine."""
        entries = self.read_all()
        if not entries:
            return {"ledger_id": None, "count": 0, "entry_hash": GENESIS_HASH}
        e = entries[-1]
        return {"ledger_id": e.ledger_id, "count": len(entries), "entry_hash": e.entry_hash}
