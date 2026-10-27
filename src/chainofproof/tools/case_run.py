"""Case-level pipeline: normalize every evidence item, run Hayabusa on every EVTX, link detections.

Detections link to events by (evidence, RecordID, channel). The count of detections that could not
be linked is reported (never hidden). Hayabusa output stays in its run file; the database only
holds sanitized rule metadata.
"""

from __future__ import annotations

from dataclasses import dataclass

from chainofproof.config import Paths, ToolsSettings, load_settings
from chainofproof.ingest.store import EvidenceStore
from chainofproof.scenarios.source_map import resolve_source_keys
from chainofproof.schemas.events import Detection, SourceKindName
from chainofproof.tools.hayabusa import run_hayabusa
from chainofproof.tools.norm_store import insert_detections
from chainofproof.tools.normalize import NormResult, normalize_evidence


@dataclass
class CaseRow:
    """One line of the per-case report."""

    evidence_id: str
    label: str
    source_kind: str
    hosts: list[str]
    events: int
    detections: int
    unlinked: int
    corrupt: int
    norm_run_id: str
    hayabusa_run_id: str | None


def link_detections(res: NormResult, dets: list[Detection]) -> list[tuple[Detection, str | None]]:
    """Pair each detection with the event_uid of the same (RecordID, channel), or None."""
    index = {(e.record_id, (e.channel or "").lower()): e.event_uid for e in res.events}
    return [
        (d, index.get((d.record_id, (d.channel or "").lower())) if d.record_id else None)
        for d in dets
    ]


def normalize_case(
    paths: Paths, case_id: str, cfg: ToolsSettings | None = None, hayabusa: bool = True,
    only: str | None = None,
) -> list[CaseRow]:  # fmt: skip
    """Normalize all evidence of a case (or just ``only``) and run Hayabusa on each EVTX item."""
    cfg = cfg or load_settings().tools
    keys = resolve_source_keys(paths, case_id)  # refuses unknown evidence before any work
    store = EvidenceStore(paths)
    rows = []
    for rec in store.list_evidence(case_id):
        if only and rec.evidence_id != only:
            continue
        res = normalize_evidence(paths, rec.evidence_id, keys)
        n_det = n_unlinked = 0
        hrun = None
        if hayabusa and res.source_kind == SourceKindName.evtx:
            hres = run_hayabusa(paths, rec.evidence_id, cfg)
            linked = link_detections(res, hres.detections)
            with store.transaction() as conn:
                insert_detections(conn, res.run_id, hres.run_id, res.label, linked)
            n_det, n_unlinked = len(linked), sum(1 for _, u in linked if u is None)
            hrun = hres.run_id
        rows.append(
            CaseRow(rec.evidence_id, res.label, res.source_kind.value, res.hosts,
                    len(res.events), n_det, n_unlinked, res.corrupt, res.run_id, hrun)
        )  # fmt: skip
    return rows
