"""Database writes for normalization runs (insert-only: rows and files are never deleted).

"Latest completed run per evidence" is the rule for every read: a re-normalization adds a new
``norm_runs`` row (and new event rows) and the old ones simply stop being selected.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence

from chainofproof.config import Paths
from chainofproof.custody.db import connect
from chainofproof.custody.hashing import iso_utc, utc_now
from chainofproof.custody.migrations import SCHEMA_VERSION, schema_version
from chainofproof.errors import UserError
from chainofproof.schemas.events import Detection, NormalizedEvent

LATEST_RUNS = (
    "SELECT n.run_id FROM norm_runs n WHERE n.case_id = ? AND n.rowid = "
    "(SELECT MAX(m.rowid) FROM norm_runs m WHERE m.evidence_id = n.evidence_id)"
)
EVENT_COLUMNS = (
    "norm_run_id", "event_uid", "ord", "evidence_label", "source_kind", "host", "timestamp",
    "event_type", "channel", "provider", "event_id", "record_id", "user", "logon_type",
    "logon_id", "process_image", "parent_image", "target_image", "command_line",
    "command_line_length", "pipe_name", "service_name", "registry_target", "file_path",
    "src_ip", "dst_ip", "src_port", "dst_port", "dst_host", "conn_id", "fields_json",
    "summary", "injection_flags_json", "truncated",
)  # fmt: skip
_DIRECT = EVENT_COLUMNS[3:30]


class SchemaVersionError(UserError):
    """The database is older than this code expects."""


def require_v2(paths: Paths) -> None:
    """Raise unless the database is at schema version 2 (run ``db-migrate`` otherwise)."""
    conn = connect(paths.db_path)
    try:
        v = schema_version(conn)
    finally:
        conn.close()
    if v is None or v < SCHEMA_VERSION:
        raise SchemaVersionError(f"database is at schema version {v}; run db-migrate first")


def insert_run(
    conn: sqlite3.Connection, run_id: str, evidence_id: str, case_id: str, version: int,
    jsonl_sha256: str, count: int, ledger_id: str,
) -> None:  # fmt: skip
    """Register a completed normalization run."""
    conn.execute(
        "INSERT INTO norm_runs(run_id, evidence_id, case_id, norm_version, jsonl_sha256, "
        "event_count, ledger_id, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (run_id, evidence_id, case_id, version, jsonl_sha256, count, ledger_id,
         iso_utc(utc_now())),
    )  # fmt: skip


def insert_events(conn: sqlite3.Connection, run_id: str, events: Sequence[NormalizedEvent]) -> None:
    """Insert agent-view rows in file order."""
    rows = []
    for i, e in enumerate(events):
        d = e.model_dump(mode="json")
        direct = [d[c] for c in _DIRECT]
        rows.append(
            (run_id, e.event_uid, i, *direct, json.dumps(d["fields"], sort_keys=True),
             e.summary, json.dumps(d["injection_flags"]), int(e.truncated))
        )  # fmt: skip
    marks = ",".join("?" * len(EVENT_COLUMNS))
    conn.executemany(
        f"INSERT INTO events({','.join(EVENT_COLUMNS)}) VALUES ({marks})",  # noqa: S608 - fixed
        rows,
    )


def insert_detections(
    conn: sqlite3.Connection, norm_run_id: str, hayabusa_run_id: str, label: str,
    items: Sequence[tuple[Detection, str | None]],
) -> list[str]:  # fmt: skip
    """Insert detections (each with its linked event_uid or None); returns the DET ids."""
    row = conn.execute("SELECT MAX(CAST(SUBSTR(detection_id, 5) AS INTEGER)) FROM detections")
    n = row.fetchone()[0] or 0
    ids = []
    for det, uid in items:
        n += 1
        ids.append(f"DET-{n:06d}")
        conn.execute(
            "INSERT INTO detections(detection_id, norm_run_id, event_uid, evidence_label, "
            "rule_title, rule_id, level, mitre_tags, record_id, run_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (ids[-1], norm_run_id, uid, label, det.rule_title, det.rule_id, det.level,
             json.dumps(det.mitre_tags), det.record_id, hayabusa_run_id),
        )  # fmt: skip
    return ids
