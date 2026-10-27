"""Shared inputs for the companion generators (scenario + inventory + seed; nothing else)."""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from chainofproof.scenarios.companions import Pairing
from chainofproof.scenarios.inventory import Inventory
from chainofproof.scenarios.keyevents import KeyEvent
from chainofproof.scenarios.keyevents_base import base
from chainofproof.schemas.scenario import Scenario, ScenarioError

REAL_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"


def parse_real(value: str) -> datetime:
    """Parse a real/virtual EVTX time (``...%fZ`` or whole seconds) as aware UTC."""
    fmt = REAL_FMT if "." in value else "%Y-%m-%dT%H:%M:%SZ"
    return datetime.strptime(value, fmt).replace(tzinfo=UTC)


@dataclass
class GenContext:
    """Deterministic generation context. No wall clock and no system randomness anywhere."""

    scenario: Scenario
    inventory: Inventory
    # virtual host -> lower-case pipe names present in its REAL events (benign pipes avoid them)
    real_pipes: dict[str, frozenset[str]] = field(default_factory=dict)

    @property
    def start(self) -> datetime:
        """Virtual start time of the scenario."""
        return parse_real(self.scenario.virtual_start_time)

    def rng(self, purpose: str) -> random.Random:
        """A PRNG seeded from the scenario seed and a purpose label (str seeds are stable)."""
        return random.Random(f"{self.scenario.seed}:{purpose}")

    def virt(self, source_key: str, real_time: str) -> datetime:
        """Real event time -> virtual time through the alignment layer (whole seconds)."""
        off = self.scenario.aligned(source_key).time_offset_seconds
        return (parse_real(real_time) + timedelta(seconds=off)).replace(microsecond=0)

    def pairing(
        self,
        stage_id: str,
        field: str,
        value: str,
        facts: tuple[str, ...],
        event_id: int | None = None,
        by_basename: bool = False,
    ) -> tuple[Pairing, KeyEvent, datetime]:
        """Pair a synthetic record with the real key events of a stage that share ``value``.

        Matches (case-insensitive) the named facts of the stage's key events, optionally as path
        basenames. Returns the Pairing (all matching record ids), the first match and its virtual
        time. Raises ScenarioError if no real event matches: a pairing must be real.
        """
        sk = self.inventory.keys_for(stage_id)
        want = value.lower()

        def hit(e: KeyEvent) -> bool:
            for f in facts:
                v = e.facts.get(f, "")
                if (base(v) if by_basename else v.lstrip("\\").lower()) == want:
                    return True
            return False

        found = [e for e in sk.result.events if hit(e) and event_id in (None, e.event_id)]
        if not found:
            raise ScenarioError(f"stage {stage_id}: no real event shares {field}={value!r}")
        ids = tuple(sorted({e.record_id for e in found}))
        pr = Pairing(field, value, sk.source_key, ids)
        return pr, found[0], self.virt(sk.source_key, found[0].real_time)

    def key_time(self, source_key: str, record_id: int) -> datetime:
        """Virtual (aligned) time of a real key event, whole seconds."""
        for sk in self.inventory.key_events:
            for e in sk.result.events:
                if sk.source_key == source_key and e.record_id == record_id:
                    return self.virt(source_key, e.real_time)
        raise ScenarioError(f"{source_key}: record {record_id} is not a key event")

    def first_key(
        self, stage_id: str, event_id: int | None = None, supports: str | None = None
    ) -> tuple[KeyEvent, datetime]:
        """First key event of a stage matching the filters, and its virtual time."""
        sk = self.inventory.keys_for(stage_id)
        for e in sk.result.events:
            if (event_id is None or e.event_id == event_id) and (
                supports is None or supports in e.supports
            ):
                return e, self.virt(sk.source_key, e.real_time)
        raise ScenarioError(f"stage {stage_id}: no key event matching the generator's needs")
