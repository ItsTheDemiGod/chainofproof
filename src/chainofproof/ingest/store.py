"""SQLite evidence store (cases + evidence). Parameterized queries only."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager

from chainofproof.config import Paths
from chainofproof.custody.db import connect
from chainofproof.custody.hashing import iso_utc, utc_now
from chainofproof.errors import UserError
from chainofproof.schemas.custody import (
    CASE_ID_PATTERN,
    CaseRecord,
    EvidenceRecord,
    make_evidence_id,
)

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS cases (
        case_id TEXT PRIMARY KEY, title TEXT, description TEXT, created_at TEXT)""",
    """CREATE TABLE IF NOT EXISTS evidence (
        evidence_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL REFERENCES cases(case_id),
        original_name TEXT, original_path TEXT, vault_path TEXT, size_bytes INTEGER,
        sha256 TEXT, source_type TEXT, description TEXT, ingested_at TEXT, ingested_by TEXT,
        UNIQUE(case_id, sha256))""",
]


class StoreError(UserError):
    """Expected, user-facing store problem (unknown case, duplicate, bad ID...)."""


def validate_case_id(case_id: str) -> str:
    """Return case_id if it is safe to use as a folder name, else raise StoreError."""
    if not re.fullmatch(CASE_ID_PATTERN, case_id):
        raise StoreError(f"invalid case id {case_id!r}: use 1-64 letters, digits, '_' or '-'")
    return case_id


class EvidenceStore:
    """Cases and evidence records in the shared SQLite database."""

    def __init__(self, paths: Paths) -> None:
        self.paths = paths
        self.init_db()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        with closing(connect(self.paths.db_path)) as conn:
            yield conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """BEGIN IMMEDIATE transaction; commits on success, rolls back on error."""
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")

    def init_db(self) -> None:
        """Create tables if missing and set schema_version = 1."""
        with self._conn() as conn:
            for ddl in SCHEMA:
                conn.execute(ddl)
            if conn.execute("SELECT 1 FROM schema_version").fetchone() is None:
                conn.execute("INSERT INTO schema_version(version) VALUES (1)")

    # ---- cases ---------------------------------------------------------------------------
    def create_case(self, case_id: str, title: str = "", description: str = "") -> CaseRecord:
        """Create a case; raises StoreError if the ID is invalid or already exists."""
        validate_case_id(case_id)
        now = iso_utc(utc_now())
        try:
            with self._conn() as conn:
                conn.execute(
                    "INSERT INTO cases(case_id, title, description, created_at) VALUES (?,?,?,?)",
                    (case_id, title, description, now),
                )
        except sqlite3.IntegrityError as e:
            raise StoreError(f"case {case_id!r} already exists") from e
        return self.get_case(case_id)  # type: ignore[return-value]

    def get_case(self, case_id: str) -> CaseRecord | None:
        """One case, or None."""
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        return CaseRecord.model_validate(dict(row), strict=False) if row else None

    def list_cases(self) -> list[CaseRecord]:
        """All cases, oldest first."""
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM cases ORDER BY created_at, case_id").fetchall()
        return [CaseRecord.model_validate(dict(r), strict=False) for r in rows]

    # ---- evidence ------------------------------------------------------------------------
    @staticmethod
    def _next_id(conn: sqlite3.Connection) -> str:
        row = conn.execute("SELECT MAX(CAST(SUBSTR(evidence_id, 4) AS INTEGER)) FROM evidence")
        return make_evidence_id((row.fetchone()[0] or 0) + 1)

    def next_evidence_id(self) -> str:
        """Next sequential evidence ID across the whole database (EV-000001, ...)."""
        with self.transaction() as conn:
            return self._next_id(conn)

    def add_evidence(self, record: EvidenceRecord) -> None:
        """Insert a record; raises StoreError on duplicate (case, sha256) or unknown case."""
        d = record.model_dump(mode="json")
        d["ingested_at"] = iso_utc(record.ingested_at)
        sql = (
            "INSERT INTO evidence(evidence_id, case_id, original_name, original_path, vault_path, "
            "size_bytes, sha256, source_type, description, ingested_at, ingested_by) VALUES "
            "(:evidence_id, :case_id, :original_name, :original_path, :vault_path, :size_bytes, "
            ":sha256, :source_type, :description, :ingested_at, :ingested_by)"
        )
        try:
            with self.transaction() as conn:
                conn.execute(sql, d)
        except sqlite3.IntegrityError as e:
            raise StoreError(f"cannot register {record.evidence_id}: {e}") from e

    def remove_evidence(self, evidence_id: str) -> None:
        """Delete a registry row (rollback of a failed ingest; never touches files)."""
        with self._conn() as conn:
            conn.execute("DELETE FROM evidence WHERE evidence_id = ?", (evidence_id,))

    def get_evidence(self, evidence_id: str) -> EvidenceRecord | None:
        """One evidence record, or None."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,)
            ).fetchone()
        return EvidenceRecord.model_validate(dict(row), strict=False) if row else None

    def find_by_hash(self, case_id: str, sha256: str) -> EvidenceRecord | None:
        """The record with this (case_id, sha256), or None."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM evidence WHERE case_id = ? AND sha256 = ?", (case_id, sha256)
            ).fetchone()
        return EvidenceRecord.model_validate(dict(row), strict=False) if row else None

    def list_evidence(self, case_id: str | None = None) -> list[EvidenceRecord]:
        """Evidence records, optionally for one case, ordered by ID."""
        with self._conn() as conn:
            if case_id is None:
                rows = conn.execute("SELECT * FROM evidence ORDER BY evidence_id").fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM evidence WHERE case_id = ? ORDER BY evidence_id", (case_id,)
                ).fetchall()
        return [EvidenceRecord.model_validate(dict(r), strict=False) for r in rows]
