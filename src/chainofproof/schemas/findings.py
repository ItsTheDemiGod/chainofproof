"""Stored findings and the verifier's report (Phase 5).

``FindingInput`` is the checkable content of a finding (what the citation verifier reads).
``Finding`` is the stored form: system-assigned id, verification result, provenance. Rejected
findings are stored too (append-only) so a later evaluation can count them.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

CLAIM_MAX = 400  # = settings.agent.claim_max_chars default (a test pins the equality)
NEEDS_MAX = 3
FINDING_ID_RE = re.compile(r"^FND-\d{4,}$")
EVT_RE = re.compile(r"^EVT-[0-9a-f]{12}$")
HIT_RE = re.compile(r"^HIT-\d{6}$")

ClaimType = Literal["observation", "attack_action", "contradiction", "link", "anomaly"]
Confidence = Literal["high", "medium", "low"]
FindingStatus = Literal["verified", "downgraded", "rejected"]


class Strict(BaseModel):
    """Base: unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid")


class Entities(Strict):
    """Entities a claim names; each must be grounded in the cited records."""

    hosts: list[str] = Field(default_factory=list, max_length=8)
    users: list[str] = Field(default_factory=list, max_length=8)
    processes: list[str] = Field(default_factory=list, max_length=8)
    ips: list[str] = Field(default_factory=list, max_length=8)
    time_start: str | None = None  # virtual UTC ISO
    time_end: str | None = None


class Check(Strict):
    """One verifier check."""

    check: str
    passed: bool
    detail: str = ""


class VerificationReport(Strict):
    """Result of the deterministic citation verifier (templated problems: ids and fields only)."""

    status: FindingStatus
    checks: list[Check] = Field(default_factory=list)
    problems: list[str] = Field(default_factory=list)
    unsupported_entities: list[str] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)

    def codes(self) -> list[str]:
        """Problem codes (first word of each problem), in order."""
        return [p.split(" ", 1)[0] for p in self.problems]


class FindingInput(Strict):
    """The content of a finding that the verifier checks."""

    claim: str = Field(min_length=1, max_length=CLAIM_MAX)
    claim_type: ClaimType
    entities: Entities = Field(default_factory=Entities)
    cited_event_uids: list[str] = Field(default_factory=list, max_length=20)
    cited_hit_ids: list[str] = Field(default_factory=list, max_length=20)
    confidence: Confidence = "low"
    needs: list[str] = Field(default_factory=list, max_length=NEEDS_MAX)  # evidence that would help


class Finding(FindingInput):
    """A stored finding."""

    finding_id: str = Field(pattern=FINDING_ID_RE.pattern)
    run_id: str
    case_id: str
    worker_role: Literal["extractor", "correlator"]
    status: FindingStatus
    verification: VerificationReport
    revised_from: str | None = None
    created_at: str
