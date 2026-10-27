"""Evidence integrity checks and working copies."""

from __future__ import annotations

from pathlib import Path

from chainofproof.config import Paths
from chainofproof.custody.hashing import sha256_file, sha256_json
from chainofproof.custody.ledger import Ledger
from chainofproof.errors import UserError
from chainofproof.ingest.store import EvidenceStore
from chainofproof.ingest.vault import copy_atomic, is_read_only, make_read_only, remove_file
from chainofproof.schemas.custody import EvidenceRecord, IntegrityResult


class IntegrityError(UserError):
    """Evidence failed an integrity check or is unknown."""


def _get(store: EvidenceStore, evidence_id: str) -> EvidenceRecord:
    rec = store.get_evidence(evidence_id)
    if rec is None:
        raise IntegrityError(f"unknown evidence id: {evidence_id}")
    return rec


def _check(paths: Paths, rec: EvidenceRecord) -> list[str]:
    vault = paths.base_dir / rec.vault_path
    eid = rec.evidence_id
    if not vault.is_file():
        return [f"{eid}: vault file missing"]
    problems = []
    size = vault.stat().st_size
    if size != rec.size_bytes:
        problems.append(f"{eid}: size mismatch (stored {rec.size_bytes}, now {size})")
    if sha256_file(vault) != rec.sha256:
        problems.append(f"{eid}: sha256 mismatch (vault file was modified)")
    if not is_read_only(vault):
        problems.append(f"WARN: {eid}: vault file is no longer read-only")
    return problems


def _verify_record(paths: Paths, rec: EvidenceRecord) -> IntegrityResult:
    """Re-hash one vault file (no ledger entry). ``WARN:`` problems do not fail the check."""
    problems = _check(paths, rec)
    ok = all(p.startswith("WARN:") for p in problems)
    return IntegrityResult(ok=ok, checked=1, problems=problems)


def verify_evidence(paths: Paths, evidence_id: str) -> IntegrityResult:
    """Re-hash one vault file and compare with the stored hash and size; log to the ledger.

    Problems prefixed ``WARN:`` do not fail the check; all others do.
    """
    rec = _get(EvidenceStore(paths), evidence_id)
    res = _verify_record(paths, rec)
    Ledger(paths).append(
        "integrity",
        "verify_evidence",
        input_hashes=[rec.sha256],
        details={"evidence_id": evidence_id, "ok": res.ok, "problems": res.problems},
    )
    return res


def verify_all(paths: Paths, case_id: str | None = None) -> IntegrityResult:
    """Verify every evidence item (optionally one case); ONE summary ledger entry in total."""
    items = EvidenceStore(paths).list_evidence(case_id)
    results = {r.evidence_id: _verify_record(paths, r) for r in items}
    ok_count = sum(r.ok for r in results.values())
    Ledger(paths).append(
        "integrity",
        "verify_all",
        details={
            "case_id": case_id,
            "items_checked": len(items),
            "ok_count": ok_count,
            "problem_count": len(items) - ok_count,
            "results_sha256": sha256_json({k: [r.ok, r.problems] for k, r in results.items()}),
        },
    )
    return IntegrityResult(
        ok=ok_count == len(items),
        checked=len(items),
        problems=[p for r in results.values() for p in r.problems],
    )


def get_working_copy(paths: Paths, evidence_id: str) -> Path:
    """Verified, read-only working copy of an evidence file; all tools must read this path."""
    rec = _get(EvidenceStore(paths), evidence_id)
    res = verify_evidence(paths, evidence_id)
    if not res.ok:
        raise IntegrityError(f"{evidence_id} failed verification: {'; '.join(res.problems)}")
    vault = paths.base_dir / rec.vault_path
    work = paths.evidence_working / rec.case_id / vault.name
    if work.is_file() and sha256_file(work) == rec.sha256:
        return work
    remove_file(work)
    copy_atomic(vault, work)
    out = sha256_file(work)
    if out != rec.sha256:
        remove_file(work)
        raise IntegrityError(f"{evidence_id}: working copy hash differs from vault; removed")
    make_read_only(work)
    Ledger(paths).append(
        "integrity",
        "working_copy",
        input_hashes=[rec.sha256],
        output_hash=out,
        details={"evidence_id": evidence_id, "working_name": work.name},
    )
    return work
