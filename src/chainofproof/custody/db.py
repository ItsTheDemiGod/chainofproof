"""SQLite connection helper shared by the ledger anchor and the evidence store."""

from __future__ import annotations

import sqlite3
from pathlib import Path

LEDGER_HEAD_DDL = """
CREATE TABLE IF NOT EXISTS ledger_head (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    ledger_id TEXT,
    entry_count INTEGER,
    entry_hash TEXT
)
"""


def connect(db_path: Path) -> sqlite3.Connection:
    """Open the database with foreign keys on and WAL journaling. Caller must close it."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)  # explicit transactions
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(LEDGER_HEAD_DDL)
    return conn
