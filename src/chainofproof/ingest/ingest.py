"""Evidence ingestion: hash, copy into the read-only vault, verify, register, log."""

from __future__ import annotations

import logging
from pathlib import Path

from chainofproof.config import Paths
from chainofproof.custody.hashing import sha256_file, sha256_json, utc_now
from chainofproof.custody.ledger import Ledger
from chainofproof.errors import UserError
from chainofproof.ingest.detect import detect_source_type
from chainofproof.ingest.store import EvidenceStore
from chainofproof.ingest.vault import copy_atomic, make_read_only, remove_file, sanitize_filename
from chainofproof.schemas.custody import EvidenceRecord, SourceType

__all__ = ["IngestError", "detect_source_type", "ingest_evidence"]

log = logging.getLogger(__name__)


class IngestError(UserError):
    """Ingestion failed or the input was rejected."""


def _validate_source(store: EvidenceStore, case_id: str, source: Path) -> None:
    if store.get_case(case_id) is None:
        raise IngestError(f"case {case_id!r} does not exist; create it first (case-create)")
    if source.is_symlink():
        raise IngestError(f"{source.name}: symlinks are not accepted as evidence")
    if not source.exists():
        raise IngestError(f"source file not found: {source}")
    if not source.is_file():
        raise IngestError(f"{source}: not a regular file (directories are not accepted)")
    try:
        with source.open("rb") as f:
            f.read(1)
    except OSError as e:
        raise IngestError(f"{source.name}: not readable ({e.strerror})") from e


def _log_failure(ledger: Ledger, case_id: str, name: str, sha: str, reason: str) -> None:
    try:
        ledger.append(
            "ingest",
            "ingest_failed",
            input_hashes=[sha],
            details={"case_id": case_id, "original_name": name, "reason": reason[:300]},
        )
    except Exception:
        log.exception("could not write ingest_failed ledger entry")


def _register(
    paths: Paths, store: EvidenceStore, ledger: Ledger, case_id: str, source: Path,
    sha: str, stype: SourceType, description: str, ingested_by: str,
) -> EvidenceRecord:  # fmt: skip
    """Copy, re-hash, lock, insert into SQLite and log. Cleans up after any failure."""
    evidence_id = store.next_evidence_id()
    vault = paths.evidence_raw / case_id / f"{evidence_id}__{sanitize_filename(source.name)}"
    registered = False
    try:
        copy_atomic(source, vault)
        if sha256_file(vault) != sha:
            raise IngestError(f"{source.name}: vault copy hash differs from source; aborted")
        make_read_only(vault)
        record = EvidenceRecord(
            evidence_id=evidence_id,
            case_id=case_id,
            original_name=source.name,
            original_path=str(source.resolve()),
            vault_path=vault.relative_to(paths.base_dir).as_posix(),
            size_bytes=vault.stat().st_size,
            sha256=sha,
            source_type=stype,
            description=description,
            ingested_at=utc_now(),
            ingested_by=ingested_by,
        )
        store.add_evidence(record)
        registered = True
        ledger.append(
            "ingest",
            "ingest",
            input_hashes=[sha],
            output_hash=sha256_json(record.model_dump(mode="json")),
            details={
                "evidence_id": evidence_id,
                "case_id": case_id,
                "original_name": source.name,
                "size_bytes": record.size_bytes,
                "source_type": stype.value,
            },
        )
    except BaseException as e:
        if registered:
            store.remove_evidence(evidence_id)
        remove_file(vault)
        _log_failure(ledger, case_id, source.name, sha, f"{type(e).__name__}: {e}")
        if isinstance(e, UserError) or not isinstance(e, Exception):
            raise
        raise IngestError(f"ingest of {source.name} failed: {type(e).__name__}: {e}") from e
    return record


def ingest_evidence(
    paths: Paths,
    case_id: str,
    source_path: Path,
    description: str = "",
    source_type: SourceType | None = None,
    ingested_by: str = "analyst",
) -> EvidenceRecord:
    """Ingest one file into the vault. Returns the new record, or the existing one if duplicate."""
    source = Path(source_path)
    store, ledger = EvidenceStore(paths), Ledger(paths)
    _validate_source(store, case_id, source)
    sha = sha256_file(source)
    existing = store.find_by_hash(case_id, sha)
    if existing:
        ledger.append(
            "ingest",
            "ingest_duplicate",
            input_hashes=[sha],
            details={
                "evidence_id": existing.evidence_id,
                "case_id": case_id,
                "original_name": source.name,
            },
        )
        log.warning("duplicate of %s: nothing copied", existing.evidence_id)
        return existing
    stype = source_type or detect_source_type(source)
    record = _register(paths, store, ledger, case_id, source, sha, stype, description, ingested_by)
    log.info("ingested %s (%s, %d bytes)", record.evidence_id, stype.value, record.size_bytes)
    return record
