"""Shared pieces of the detectors: the Hit model, deterministic keys and small helpers.

A detector is a pure function ``(events, params) -> list[Hit]`` over agent-view events. It has no
randomness and never reads a clock; explanations are fixed templates over structured fields; each
hit lists what it cannot show (``limitations``).
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from chainofproof.custody.hashing import canonical_json, sha256_text
from chainofproof.schemas.events import NormalizedEvent

Severity = Literal["info", "low", "medium", "high"]
UID_CAP = 50
TS_FORMATS = ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ")


class Hit(BaseModel):
    """One detector finding. ``hit_id`` (HIT-######) is assigned when the hit is stored."""

    hit_id: str | None = None
    detector: str
    kind: str
    severity: Severity
    hosts: list[str]
    evidence_labels: list[str]
    event_uids: list[str] = Field(max_length=UID_CAP)
    measures: dict[str, Any]
    explanation: str
    limitations: list[str]
    hit_key: str


def _plain(value: Any) -> Any:
    """JSON-stable form of measures (floats rounded so keys do not depend on float noise)."""
    if isinstance(value, float):
        return round(value, 6)
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, list | tuple):
        return [_plain(v) for v in value]
    return value


def make_hit(
    detector: str, kind: str, severity: Severity, hosts: Iterable[str], labels: Iterable[str],
    event_uids: Iterable[str], measures: dict[str, Any], explanation: str, limitations: list[str],
) -> Hit:  # fmt: skip
    """Build a Hit; ``hit_key`` = sha256 of canonical JSON of (detector, kind, uids, measures)."""
    uids = sorted(set(event_uids))[:UID_CAP]
    m = _plain(measures)
    key = sha256_text(canonical_json([detector, kind, uids, m]))
    return Hit(
        detector=detector, kind=kind, severity=severity, hosts=sorted(set(hosts)),
        evidence_labels=sorted(set(labels)), event_uids=uids, measures=m,
        explanation=explanation, limitations=limitations, hit_key=key,
    )  # fmt: skip


def parse_ts(value: str) -> datetime | None:
    """Parse a virtual timestamp; None when malformed."""
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=UTC)
        except (ValueError, TypeError):
            continue
    return None


def ordered(events: Iterable[NormalizedEvent]) -> list[NormalizedEvent]:
    """Deterministic order: (timestamp, evidence_label, record_id, event_uid)."""
    return sorted(
        events, key=lambda e: (e.timestamp, e.evidence_label, e.record_id or 0, e.event_uid)
    )


def iso(dt: datetime) -> str:
    """Whole-second ISO form used in measures."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
