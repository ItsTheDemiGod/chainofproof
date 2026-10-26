"""Shared inputs for the companion generators (scenario + inventory + seed; nothing else)."""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from chainofproof.scenarios.inventory import Inventory
from chainofproof.scenarios.keyevents import KeyEvent
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
