"""Explicit, safe database migrations (schema version 1 -> 2).

Version 2 adds the normalized-event tables. Fresh databases are created at version 2 directly; an
existing version-1 database is changed only by ``migrate_to_v2``: backup with the sqlite3 backup
API (the database is in WAL mode, so a raw file copy would be unsafe), one transaction, then a
``db_migrate`` ledger entry. Nothing is ever dropped or deleted.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from chainofproof.config import Paths
from chainofproof.custody.db import connect
from chainofproof.custody.hashing import sha256_file
from chainofproof.custody.ledger import Ledger

SCHEMA_VERSION = 2
BACKUP_NAME = "chainofproof.db.pre-v2"

V2_DDL = [
    """CREATE TABLE IF NOT EXISTS norm_runs (
        run_id TEXT PRIMARY KEY,
        evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
        case_id TEXT NOT NULL REFERENCES cases(case_id),
        norm_version INTEGER NOT NULL,
        jsonl_sha256 TEXT NOT NULL,
        event_count INTEGER NOT NULL,
        ledger_id TEXT NOT NULL,
        created_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS events (
        norm_run_id TEXT NOT NULL REFERENCES norm_runs(run_id),
        event_uid TEXT NOT NULL,
        ord INTEGER NOT NULL,
        evidence_label TEXT NOT NULL,
        source_kind TEXT NOT NULL,
        host TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        channel TEXT, provider TEXT, event_id INTEGER, record_id INTEGER,
        user TEXT, logon_type TEXT, logon_id TEXT,
        process_image TEXT, parent_image TEXT, target_image TEXT,
        command_line TEXT, command_line_length INTEGER,
        pipe_name TEXT, service_name TEXT, registry_target TEXT, file_path TEXT,
        src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER, dst_host TEXT,
        conn_id TEXT,
        fields_json TEXT NOT NULL,
        summary TEXT NOT NULL,
        injection_flags_json TEXT NOT NULL,
        truncated INTEGER NOT NULL,
        PRIMARY KEY (norm_run_id, event_uid))""",
    "CREATE INDEX IF NOT EXISTS ix_events_host_ts ON events(host, timestamp)",
    "CREATE INDEX IF NOT EXISTS ix_events_label ON events(evidence_label)",
    "CREATE INDEX IF NOT EXISTS ix_events_type ON events(event_type)",
    "CREATE INDEX IF NOT EXISTS ix_events_user ON events(user)",
    "CREATE INDEX IF NOT EXISTS ix_events_proc ON events(process_image)",
    "CREATE INDEX IF NOT EXISTS ix_events_conn ON events(conn_id)",
    """CREATE TABLE IF NOT EXISTS detections (
        detection_id TEXT PRIMARY KEY,
        norm_run_id TEXT NOT NULL REFERENCES norm_runs(run_id),
        event_uid TEXT,
        evidence_label TEXT NOT NULL,
        rule_title TEXT NOT NULL,
        rule_id TEXT,
        level TEXT NOT NULL,
        mitre_tags TEXT NOT NULL,
        record_id INTEGER,
        run_id TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS ix_det_run ON detections(norm_run_id)",
    """CREATE TABLE IF NOT EXISTS event_eval_meta (
        norm_run_id TEXT NOT NULL REFERENCES norm_runs(run_id),
        event_uid TEXT NOT NULL,
        source_key TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        locator TEXT NOT NULL,
        real_computer TEXT,
        real_timestamp TEXT,
        synth_only INTEGER NOT NULL,
        pair_field TEXT,
        pair_value TEXT,
        is_synthetic INTEGER NOT NULL,
        raw_note TEXT,
        PRIMARY KEY (norm_run_id, event_uid))""",
]


def create_v2_tables(conn: sqlite3.Connection) -> None:
    """Create the version-2 tables (idempotent)."""
    for ddl in V2_DDL:
        conn.execute(ddl)


def schema_version(conn: sqlite3.Connection) -> int | None:
    """Current schema version, or None when the database has no version row yet."""
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'"
    ).fetchone()
    row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone() if exists else None
    return row[0] if row else None


@dataclass
class MigrationResult:
    """What ``migrate_to_v2`` did."""

    from_version: int
    to_version: int
    migrated: bool
    backup_name: str | None = None
    backup_sha256: str | None = None


def _backup_path(db_dir: Path) -> Path:
    folder = db_dir / "backups"
    folder.mkdir(parents=True, exist_ok=True)
    p, n = folder / BACKUP_NAME, 1
    while p.exists():  # never overwrite an earlier backup
        n += 1
        p = folder / f"{BACKUP_NAME}.{n}"
    return p


def _backup(conn: sqlite3.Connection, dest: Path) -> str:
    with closing(sqlite3.connect(dest)) as out:
        conn.backup(out)  # online backup API: consistent even in WAL mode
    return sha256_file(dest)


def migrate_to_v2(paths: Paths) -> MigrationResult:
    """Bring the database to schema version 2 (no-op when it already is)."""
    with closing(connect(paths.db_path)) as conn:
        current = schema_version(conn)
        if current is None or current >= SCHEMA_VERSION:
            return MigrationResult(current or SCHEMA_VERSION, SCHEMA_VERSION, False)
        dest = _backup_path(paths.db_dir)
        digest = _backup(conn, dest)
        conn.execute("BEGIN IMMEDIATE")
        try:
            create_v2_tables(conn)
            conn.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION,))
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")
    Ledger(paths).append(
        "migration",
        "db_migrate",
        details={
            "from_version": current,
            "to_version": SCHEMA_VERSION,
            "backup_file": dest.name,
            "backup_sha256": digest,
        },
    )
    return MigrationResult(current, SCHEMA_VERSION, True, dest.name, digest)
