"""The ONE place that writes and reads ``event_eval_meta`` (EVAL LAYER).

Only the ingest-side normalizer may call ``write_eval_meta``; reading belongs to evaluation code
(``chainofproof/eval/``, tests, scripts, CLI). Agent-facing modules must never import this file.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable

from chainofproof.schemas.events import EventEvalMeta

_COLS = (
    "norm_run_id, event_uid, source_key, evidence_id, locator, real_computer, real_timestamp, "
    "synth_only, pair_field, pair_value, is_synthetic, raw_note"
)


def write_eval_meta(
    conn: sqlite3.Connection, norm_run_id: str, metas: Iterable[EventEvalMeta]
) -> int:
    """Insert eval metadata rows for one normalization run; returns the row count."""
    rows = [
        (
            norm_run_id, m.event_uid, m.source_key, m.evidence_id, m.locator, m.real_computer,
            m.real_timestamp, int(m.synth_only), m.pair_field, m.pair_value, int(m.is_synthetic),
            m.raw_note,
        )
        for m in metas
    ]  # fmt: skip
    conn.executemany(f"INSERT INTO event_eval_meta({_COLS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    return len(rows)


def read_eval_meta(conn: sqlite3.Connection, norm_run_id: str) -> list[EventEvalMeta]:
    """All eval metadata rows of one normalization run (evaluation code only)."""
    out = []
    for r in conn.execute(
        "SELECT * FROM event_eval_meta WHERE norm_run_id = ? ORDER BY rowid", (norm_run_id,)
    ):
        d = dict(r)
        d.pop("norm_run_id")
        d["synth_only"], d["is_synthetic"] = bool(d["synth_only"]), bool(d["is_synthetic"])
        out.append(EventEvalMeta(**d))
    return out
