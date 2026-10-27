"""Types and helpers shared by the stage rules (see ``keyevents`` for the rule registry)."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from chainofproof.scenarios.evtx_meta import EvtxEvent
from chainofproof.schemas.scenario import Confidence

MAX_FACT_LEN = 200


@dataclass
class KeyEvent:
    """One event that is part of an attacker action (metadata only)."""

    record_id: int
    event_id: int
    channel: str
    real_time: str
    rationale: str
    supports: list[str]  # ATT&CK technique IDs this event supports
    facts: dict[str, str] = field(default_factory=dict)  # a few non-sensitive fields, truncated


@dataclass
class StageResult:
    """Outcome of one stage rule."""

    events: list[KeyEvent]
    technique_confidence: dict[str, Confidence]
    note: str
    technique_notes: dict[str, str] = field(
        default_factory=dict
    )  # overrides ``note`` per technique

    @property
    def unresolved(self) -> bool:
        """True when the rule found no clear key event."""
        return not self.events


Rule = Callable[[Iterable[EvtxEvent]], StageResult]


def make_key_event(e: EvtxEvent, why: str, supports: list[str], *fact_names: str) -> KeyEvent:
    """KeyEvent from a parsed event; only the named fields are kept (truncated)."""
    facts = {n: e.data[n][:MAX_FACT_LEN] for n in fact_names if e.data.get(n)}
    return KeyEvent(e.record_id, e.event_id, e.channel, e.time, why, supports, facts)


def unresolved(techs: list[str], what_it_has: str) -> StageResult:
    """Result for a stage whose rule found nothing clear (confidence low, nothing invented)."""
    note = f"no clear key event found by the rule; the file contains: {what_it_has}"
    return StageResult([], dict.fromkeys(techs, Confidence.low), note)


def summary(events: list[EvtxEvent]) -> str:
    """Record count and EventIDs of a file, for 'unresolved' notes."""
    ids = sorted({e.event_id for e in events})
    return f"{len(events)} records, EventIDs {ids}"


def base(p: str) -> str:
    """Lower-cased last path component (either slash style)."""
    return p.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def hex_norm(v: str) -> str:
    """Normalise a hex string (``0x001010`` -> ``0x1010``); other text is lower-cased."""
    try:
        return hex(int(v, 16))
    except ValueError:
        return v.lower()
