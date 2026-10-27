"""Normalize one evidence item into agent-view events (+ eval layer) and record the run.

Reads ONLY the verified working copy. Output: ``data/runs/RUN-######/normalized_<EV>.jsonl``
(agent view, canonical JSON, file order, deterministic) plus database rows in ``events`` and
``event_eval_meta``. Nothing is deleted: a re-run adds a new ``norm_runs`` row and queries use the
latest completed run per evidence.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from chainofproof.config import Paths
from chainofproof.custody.hashing import canonical_json, sha256_bytes, sha256_file
from chainofproof.custody.ledger import Ledger
from chainofproof.custody.recorder import ToolRun
from chainofproof.errors import UserError
from chainofproof.eval.meta_store import write_eval_meta
from chainofproof.ingest.integrity import get_working_copy
from chainofproof.ingest.store import EvidenceStore
from chainofproof.scenarios.source_map import load_case_scenario, resolve_source_keys
from chainofproof.schemas.events import EventEvalMeta, NormalizedEvent, SourceKindName
from chainofproof.tools.alignment import build_context
from chainofproof.tools.auth_log_parser import iter_auth_log
from chainofproof.tools.evtx_parser import iter_evtx
from chainofproof.tools.fs_timeline_parser import iter_fs_timeline
from chainofproof.tools.norm_store import insert_events, insert_run, require_v2
from chainofproof.tools.parse_common import ParseContext
from chainofproof.tools.runs import display_path, new_run_dir

log = logging.getLogger(__name__)
NORM_VERSION = 1
Pair = tuple[NormalizedEvent, EventEvalMeta]
PARSERS: dict[SourceKindName, Callable[[Path, ParseContext], Iterator[Pair]]] = {
    SourceKindName.evtx: iter_evtx,
    SourceKindName.fs_timeline: iter_fs_timeline,
    SourceKindName.auth_log: iter_auth_log,
}


class NormalizationError(UserError):
    """Normalization failed (collision, unresolved source, unreadable file)."""


@dataclass
class NormResult:
    """Outcome of normalizing one evidence item."""

    run_id: str
    evidence_id: str
    case_id: str
    label: str
    source_kind: SourceKindName
    source_key: str
    hosts: list[str]
    events: list[NormalizedEvent]
    corrupt: int
    jsonl_path: Path
    jsonl_sha256: str
    ledger_id: str


def jsonl_bytes(events: list[NormalizedEvent]) -> bytes:
    """Deterministic JSONL (canonical JSON per event, file order, ``\\n`` line ends)."""
    return "".join(canonical_json(e.model_dump(mode="json")) + "\n" for e in events).encode()


def _collect(parser: Callable[..., Iterator[Pair]], work: Path, ctx: ParseContext):
    events: list[NormalizedEvent] = []
    metas: list[EventEvalMeta] = []
    seen: set[str] = set()
    for ev, meta in parser(work, ctx):
        if ev.event_uid in seen:
            raise NormalizationError("event_uid collision inside one evidence file; refusing")
        seen.add(ev.event_uid)
        events.append(ev)
        metas.append(meta)
    return events, metas


def normalize_evidence(
    paths: Paths, evidence_id: str, source_keys: dict[str, str] | None = None
) -> NormResult:
    """Normalize one evidence item (see module docstring). ``source_keys`` may be pre-resolved."""
    require_v2(paths)
    store = EvidenceStore(paths)
    rec = store.get_evidence(evidence_id)
    if rec is None:
        raise NormalizationError(f"unknown evidence id: {evidence_id}")
    keys = source_keys or resolve_source_keys(paths, rec.case_id)
    scenario, _ = load_case_scenario(rec.case_id)
    spec = scenario.source(keys[evidence_id])
    ctx = build_context(scenario, spec, evidence_id, rec.sha256)
    work = get_working_copy(paths, evidence_id)
    run_id, run_dir = new_run_dir(paths)
    out = run_dir / f"normalized_{evidence_id}.jsonl"
    command = f"normalize {evidence_id} -> {display_path(paths, out)}"
    with ToolRun(Ledger(paths), "normalizer", command, [sha256_file(work)]) as tr:
        events, metas = _collect(PARSERS[ctx.source_kind], work, ctx)
        data = jsonl_bytes(events)
        out.write_bytes(data)
        tr.output = data
        tr.details.update(
            {"run_id": run_id, "evidence_id": evidence_id, "norm_version": NORM_VERSION,
             "event_count": len(events), "corrupt_records": ctx.stats.corrupt}
        )  # fmt: skip
    assert tr.entry is not None
    digest = sha256_bytes(data)
    with store.transaction() as conn:
        insert_run(conn, run_id, evidence_id, rec.case_id, NORM_VERSION, digest, len(events),
                   tr.entry.ledger_id)  # fmt: skip
        insert_events(conn, run_id, events)
        write_eval_meta(conn, run_id, metas)
    log.info("normalized %s: %d events, %d corrupt", evidence_id, len(events), ctx.stats.corrupt)
    return NormResult(
        run_id, evidence_id, rec.case_id, ctx.label, ctx.source_kind, ctx.source_key,
        sorted({e.host for e in events}), events, ctx.stats.corrupt, out, digest,
        tr.entry.ledger_id,
    )  # fmt: skip
