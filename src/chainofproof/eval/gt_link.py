"""EVALUATION ONLY: map answer-key references to normalized events (event_uid).

A key reference is (source_key, record id / seq / record_id [, conn_id]). The eval layer
(``event_eval_meta``) holds the source_key and raw locator of every event, so a reference resolves
through it. Agents never see this module.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from dataclasses import dataclass, field

from chainofproof.config import Paths
from chainofproof.custody.db import connect
from chainofproof.schemas.scenario import AnswerKey, SupportingRef
from chainofproof.tools.norm_store import LATEST_RUNS

_SQL = (
    "SELECT e.*, m.source_key, m.locator, m.real_computer, m.real_timestamp, m.synth_only, "
    "m.pair_field, m.pair_value, m.raw_note FROM events e JOIN event_eval_meta m "
    "ON m.norm_run_id = e.norm_run_id AND m.event_uid = e.event_uid "
    f"WHERE e.norm_run_id IN ({LATEST_RUNS}) ORDER BY e.norm_run_id, e.ord"
)


@dataclass
class EvalIndex:
    """All events of a case's latest runs, addressable by (source_key, record id)."""

    case_id: str
    by_ref: dict[tuple[str, int], list[str]] = field(default_factory=dict)
    rows: dict[str, sqlite3.Row] = field(default_factory=dict)

    def uids(self, source_key: str, record_id: int) -> list[str]:
        """event_uid(s) for a reference (empty when it does not resolve)."""
        return self.by_ref.get((source_key, record_id), [])

    def row(self, uid: str) -> dict:
        """Joined agent-view + eval columns of one event, with the JSON fields decoded."""
        d = dict(self.rows[uid])
        d["fields"] = json.loads(d.pop("fields_json"))
        return d

    def by_source(self, source_key: str) -> list[str]:
        """All event_uids of a source in file order."""
        return [u for (s, _), us in self.by_ref.items() if s == source_key for u in us]


def build_index(paths: Paths, case_id: str) -> EvalIndex:
    """Index the latest completed normalization runs of ``case_id``."""
    idx = EvalIndex(case_id)
    with closing(connect(paths.db_path)) as conn:
        for r in conn.execute(_SQL, [case_id]):
            uid = r["event_uid"]
            idx.rows[uid] = r
            if r["record_id"] is not None:
                idx.by_ref.setdefault((r["source_key"], r["record_id"]), []).append(uid)
    return idx


def resolve_ref(idx: EvalIndex, ref: SupportingRef, conn_id: str | None = None) -> list[str]:
    """event_uid(s) of a key reference; with ``conn_id`` the event's conn_id must also match."""
    uids = idx.uids(ref.source_key, ref.event_record_id)
    if conn_id is not None:
        uids = [u for u in uids if idx.rows[u]["conn_id"] == conn_id]
    return uids


def key_action_refs(key: AnswerKey) -> Iterator[tuple[str, SupportingRef]]:
    """(GT-ACT id, ref) for every supporting reference of every action."""
    for a in key.actions:
        for r in a.supporting_refs:
            yield a.id, r


def contradiction_refs(key: AnswerKey) -> Iterator[tuple[str, str, int, bool]]:
    """(GT-CON id, source_key, record id, expected_present) for every line a contradiction names.

    Lines that the perturbation REMOVED are listed with ``expected_present`` False.
    """
    for c in key.contradictions:
        p = c.params
        for f in p.get("files", []):
            yield c.id, f["source_key"], f["record_id"], True
        for pl in p.get("paired_lines", []):
            yield c.id, p["source_key"], pl["seq"], True
            for rid in pl["real_record_ids"]:
                yield c.id, pl["real_source_key"], rid, True
        for pair in p.get("cross_host_pairs", []):
            for side in ("source_side", "dest_side"):
                yield c.id, pair[side]["source_key"], pair[side]["seq"], True
        for rid in p.get("real_record_ids_inside_window", []):
            yield c.id, p["real_source_key"], rid, True
        for um in p.get("unmatched_connections", []):
            yield c.id, um["present"]["source_key"], um["present"]["seq"], True
            yield c.id, um["missing"]["source_key"], um["missing"]["seq"], False
