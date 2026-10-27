"""Run one detector on a case, store the run and its hits, and read stored hits back.

Storage is insert-only; readers use the latest completed run per (case, detector). Each run is a
ledger-logged tool call with the sha256 of the normalized inputs, the parameters and the output.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from chainofproof.config import Paths, load_settings
from chainofproof.custody.db import connect
from chainofproof.custody.hashing import canonical_json, iso_utc, sha256_bytes, sha256_json, utc_now
from chainofproof.custody.ledger import Ledger
from chainofproof.custody.recorder import ToolRun
from chainofproof.errors import UserError
from chainofproof.ingest.store import EvidenceStore
from chainofproof.tools.detectors import DETECTORS
from chainofproof.tools.detectors.base import Hit
from chainofproof.tools.loader import load_case_events
from chainofproof.tools.norm_store import require_version
from chainofproof.tools.runs import display_path, new_run_dir

MAX_RETURNED = 50


class DetectorError(UserError):
    """Unknown detector or bad parameters."""


@dataclass
class DetectorRun:
    """Result of ``run_detector``."""

    run_id: str
    detector: str
    params: dict[str, Any]
    hits: list[Hit]
    input_sha256: str
    output_sha256: str
    ledger_id: str


def get_params(name: str, overrides: dict[str, Any] | None = None) -> BaseModel:
    """Default parameters of a detector from settings.yaml, with explicit overrides applied."""
    if name not in DETECTORS:
        raise DetectorError(f"unknown detector {name!r}; known: {', '.join(sorted(DETECTORS))}")
    base = getattr(load_settings().detectors, name)
    extra = set(overrides or {}) - set(type(base).model_fields)
    if extra:
        raise DetectorError(f"unknown parameter(s) for {name}: {', '.join(sorted(extra))}")
    try:
        return type(base).model_validate({**base.model_dump(), **(overrides or {})})
    except ValueError as e:
        raise DetectorError(f"invalid parameters for {name}: {e.__class__.__name__}") from None


def run_detector(
    paths: Paths, case_id: str, name: str, params: dict[str, Any] | None = None
) -> DetectorRun:
    """Load the case events, run the detector, store the run + hits, ledger the call."""
    require_version(paths, 3)
    model = get_params(name, params)
    events, input_sha = load_case_events(paths, case_id)
    hits = DETECTORS[name][0](events, model)
    run_id, run_dir = new_run_dir(paths)
    out = run_dir / f"detector_{name}_{case_id}.json"
    pdict = model.model_dump()
    command = f"detect {name} {case_id} -> {display_path(paths, out)}"
    with ToolRun(Ledger(paths), "detector", command, [input_sha]) as tr:
        data = (
            canonical_json(
                {"detector": name, "params": pdict, "hits": [h.model_dump() for h in hits]}
            )
            + "\n"
        ).encode()
        out.write_bytes(data)  # fmt: skip
        tr.output = data
        tr.details.update(
            {
                "run_id": run_id,
                "case_id": case_id,
                "detector": name,
                "hit_count": len(hits),
                "params_sha256": sha256_json(pdict),
            }
        )
    assert tr.entry is not None
    now = iso_utc(utc_now())
    with EvidenceStore(paths).transaction() as conn:
        _store(
            conn,
            (run_id, case_id, name),
            pdict,
            (input_sha, sha256_bytes(data)),
            tr.entry.ledger_id,
            hits,
            now,
        )
    return DetectorRun(run_id, name, pdict, hits, input_sha, sha256_bytes(data), tr.entry.ledger_id)


def _store(
    conn: sqlite3.Connection,
    ids: tuple[str, str, str],
    params: dict,
    shas: tuple[str, str],
    ledger_id: str,
    hits: list[Hit],
    now: str,
) -> None:
    run_id, case_id, name = ids
    input_sha, output_sha = shas
    conn.execute(
        "INSERT INTO detector_runs(run_id, case_id, detector, params_json, params_sha256, "
        "input_sha256, hit_count, output_sha256, ledger_id, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (run_id, case_id, name, canonical_json(params), sha256_json(params), input_sha, len(hits),
         output_sha, ledger_id, now),
    )  # fmt: skip
    n = (
        conn.execute(
            "SELECT MAX(CAST(SUBSTR(hit_id, 5) AS INTEGER)) FROM detector_hits"
        ).fetchone()[0]
        or 0
    )
    for h in hits:
        n += 1
        h.hit_id = f"HIT-{n:06d}"
        conn.execute(
            "INSERT INTO detector_hits(hit_id, run_id, case_id, hit_key, detector, kind, severity, "
            "hosts, evidence_labels, event_uids, measures, explanation, limitations, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (h.hit_id, run_id, case_id, h.hit_key, h.detector, h.kind, h.severity,
             json.dumps(h.hosts), json.dumps(h.evidence_labels), json.dumps(h.event_uids),
             canonical_json(h.measures), h.explanation, json.dumps(h.limitations), now),
        )  # fmt: skip


class HitPage(BaseModel):
    """Bounded page of stored hits from the latest run of each detector."""

    total_matches: int
    returned: int
    truncated: bool
    hits: list[Hit]


_LATEST = (
    "SELECT run_id FROM detector_runs r WHERE r.case_id = ? AND r.rowid = "
    "(SELECT MAX(x.rowid) FROM detector_runs x "
    "WHERE x.case_id = r.case_id AND x.detector = r.detector)"
)


def stored_hits(
    paths: Paths, case_id: str, detector: str | None = None, hit_id: str | None = None,
    limit: int | None = None,
) -> HitPage:  # fmt: skip
    """Stored hits of the latest completed run per detector (or one hit by id). Bounded to 50."""
    n = max(1, min(limit if limit is not None else 25, MAX_RETURNED))
    where, args = f"run_id IN ({_LATEST})", [case_id]
    if hit_id:
        where, args = "case_id = ? AND hit_id = ?", [case_id, hit_id]
    elif detector:
        where += " AND detector = ?"
        args.append(detector)
    with closing(connect(paths.db_path)) as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM detector_hits WHERE {where}", args).fetchone()[
            0
        ]  # noqa: S608
        rows = conn.execute(
            f"SELECT * FROM detector_hits WHERE {where} ORDER BY hit_id LIMIT ?",
            [*args, n],  # noqa: S608
        ).fetchall()
    hits = [
        Hit(hit_id=r["hit_id"], detector=r["detector"], kind=r["kind"], severity=r["severity"],
            hosts=json.loads(r["hosts"]), evidence_labels=json.loads(r["evidence_labels"]),
            event_uids=json.loads(r["event_uids"]), measures=json.loads(r["measures"]),
            explanation=r["explanation"], limitations=json.loads(r["limitations"]),
            hit_key=r["hit_key"])
        for r in rows
    ]  # fmt: skip
    return HitPage(total_matches=total, returned=len(hits), truncated=total > len(hits), hits=hits)
