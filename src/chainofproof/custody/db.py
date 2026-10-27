"""SQLite connection helper shared by the ledger anchor and the evidence store.

``restricted_reads()`` marks the current context as an AGENT context: every connection opened in it
gets a SQLite authorizer that denies reading or writing the eval-layer table(s) (rule A7).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

LEDGER_HEAD_DDL = """
CREATE TABLE IF NOT EXISTS ledger_head (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    ledger_id TEXT,
    entry_count INTEGER,
    entry_hash TEXT
)
"""
EVAL_TABLES = frozenset({"event_eval_meta"})  # tables an agent connection may never touch
_RESTRICTED: ContextVar[bool] = ContextVar("cop_restricted_reads", default=False)
_GUARDED = {
    sqlite3.SQLITE_READ, sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE,
}  # fmt: skip


def _authorizer(action: int, arg1: str | None, arg2, dbname, source) -> int:  # noqa: ANN001
    if action in _GUARDED and (arg1 or "").lower() in EVAL_TABLES:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


@contextmanager
def restricted_reads() -> Iterator[None]:
    """Connections opened inside this block cannot read or write the eval tables."""
    token = _RESTRICTED.set(True)
    try:
        yield
    finally:
        _RESTRICTED.reset(token)


def connect(db_path: Path) -> sqlite3.Connection:
    """Open the database with foreign keys on and WAL journaling. Caller must close it."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)  # explicit transactions
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(LEDGER_HEAD_DDL)
    if _RESTRICTED.get():
        conn.set_authorizer(_authorizer)
    return conn
