"""Chain-of-custody schemas: evidence records, ledger entries, integrity results."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

EVIDENCE_ID_PATTERN = r"^EV-\d{6}$"
LEDGER_ID_PATTERN = r"^LED-\d{6}$"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
CASE_ID_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"
GENESIS_HASH = "0" * 64


def make_evidence_id(n: int) -> str:
    """Format a sequence number as an evidence ID (EV-000001)."""
    return f"EV-{n:06d}"


def make_ledger_id(n: int) -> str:
    """Format a sequence number as a ledger ID (LED-000001)."""
    return f"LED-{n:06d}"


class SourceType(StrEnum):
    """Kind of evidence file."""

    evtx = "evtx"
    memory_dump = "memory_dump"
    pcap = "pcap"
    disk_image = "disk_image"
    document = "document"
    log_text = "log_text"
    other = "other"


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")


class EvidenceRecord(_Strict):
    """One ingested evidence file (the vault copy is the authoritative one)."""

    evidence_id: str = Field(pattern=EVIDENCE_ID_PATTERN)
    case_id: str = Field(pattern=CASE_ID_PATTERN)
    original_name: str
    original_path: str
    vault_path: str  # relative to base_dir, forward slashes
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=SHA256_PATTERN)
    source_type: SourceType
    description: str = ""
    ingested_at: datetime
    ingested_by: str = "analyst"


class LedgerEntry(_Strict):
    """One hash-chained line of the append-only ledger."""

    ledger_id: str = Field(pattern=LEDGER_ID_PATTERN)
    timestamp: datetime
    actor: str
    action: str
    command: str | None = None
    input_hashes: list[str] = Field(default_factory=list)
    output_hash: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = Field(pattern=SHA256_PATTERN)
    entry_hash: str = Field(pattern=SHA256_PATTERN)


class IntegrityResult(_Strict):
    """Outcome of an integrity check."""

    ok: bool
    checked: int = 0
    problems: list[str] = Field(default_factory=list)


class CaseRecord(_Strict):
    """An investigation case; case_id doubles as a folder name."""

    case_id: str = Field(pattern=CASE_ID_PATTERN)
    title: str = ""
    description: str = ""
    created_at: datetime
