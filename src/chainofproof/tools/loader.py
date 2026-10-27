"""Thin loader: all agent-view events of a case (latest completed normalization run per evidence).

Detectors and the graph work on plain lists of ``NormalizedEvent`` so they also run on in-memory
test data; this is the only place that reads them from the database for those tools.
"""

from __future__ import annotations

from contextlib import closing

from chainofproof.config import Paths
from chainofproof.custody.db import connect
from chainofproof.custody.hashing import sha256_json
from chainofproof.schemas.events import NormalizedEvent
from chainofproof.tools.norm_store import LATEST_RUNS
from chainofproof.tools.query import event_from_row


def sort_key(e: NormalizedEvent) -> tuple[str, str, int, str]:
    """Deterministic order: (timestamp, evidence_label, record_id, event_uid)."""
    return (e.timestamp, e.evidence_label, e.record_id or 0, e.event_uid)


def load_case_events(paths: Paths, case_id: str) -> tuple[list[NormalizedEvent], str]:
    """(events sorted deterministically, input_sha256).

    ``input_sha256`` is the sha256 over the sorted JSONL hashes of the latest normalization runs
    used, so a detector run records exactly which normalized data it saw.
    """
    with closing(connect(paths.db_path)) as conn:
        rows = conn.execute(
            f"SELECT e.* FROM events e WHERE e.norm_run_id IN ({LATEST_RUNS})", [case_id]
        ).fetchall()
        hashes = [
            r[0]
            for r in conn.execute(
                f"SELECT jsonl_sha256 FROM norm_runs WHERE run_id IN ({LATEST_RUNS})", [case_id]
            )
        ]
    events = sorted((event_from_row(r) for r in rows), key=sort_key)
    return events, sha256_json(sorted(hashes))
