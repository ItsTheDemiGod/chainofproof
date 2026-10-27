"""Adjudication list: how findings that are NOT in the answer key are scored (Phase 2.1).

Real captures contain events the key does not list. Entries here record a verdict for such
events so an evaluation can score an agent's extra findings consistently. ``decided_by`` says who
decided; drafts stay "pending human review" until a person signs them off.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from pydantic import Field, model_validator

from chainofproof.schemas.common import (
    ADJ_ID_PATTERN,
    ScenarioError,
    SourceKey,
    StrictModel,
    load_model,
    save_model,
)

if TYPE_CHECKING:
    from chainofproof.schemas.groundtruth import AnswerKey
    from chainofproof.schemas.scenario import Scenario

POLICY = (
    "A finding produced by an agent that is NOT in the answer key is scored by this list. "
    "Listed as true_finding: counts as a true positive. Listed as not_attack: counts as a false "
    "positive. Listed as unclear: reported separately and excluded from precision and recall. "
    "Not listed at all: counted as an unlisted finding, reported separately for manual review."
)
Scored = Literal["key", "true_positive", "false_positive", "unclear", "unlisted"]


class Verdict(StrEnum):
    """Verdict on an event that is not in the answer key."""

    true_finding = "true_finding"
    not_attack = "not_attack"
    unclear = "unclear"


class AdjudicationEntry(StrictModel):
    """One adjudicated event (a real EVTX record)."""

    id: str = Field(pattern=ADJ_ID_PATTERN)
    source_key: SourceKey
    event_record_id: int
    event_id: int
    verdict: Verdict
    reason: str = Field(min_length=1)
    decided_by: str = Field(min_length=1)


class Adjudication(StrictModel):
    """Contents of adjudication.yaml."""

    scenario_id: str
    policy: str
    entries: list[AdjudicationEntry]

    @model_validator(mode="after")
    def _unique(self) -> Adjudication:
        ids = [e.id for e in self.entries]
        evs = [(e.source_key, e.event_record_id) for e in self.entries]
        if len(set(ids)) != len(ids) or len(set(evs)) != len(evs):
            raise ValueError("duplicate adjudication id or event")
        if not self.policy.strip():
            raise ValueError("policy text is empty")
        return self

    def verdict_for(self, source_key: str, record_id: int) -> Verdict | None:
        """Verdict of an event, or None when it is not listed."""
        return next(
            (
                e.verdict
                for e in self.entries
                if e.source_key == source_key and e.event_record_id == record_id
            ),
            None,
        )

    def score(self, source_key: str, record_id: int, keys: list[AnswerKey]) -> Scored:
        """How a finding on this real event is scored under the policy.

        ``keys`` are the answer keys whose supporting refs count as "in the key".
        """
        in_key = any(
            r.source_key == source_key and r.event_record_id == record_id
            for k in keys
            for a in k.actions
            for r in a.supporting_refs
        )
        if in_key:
            return "key"
        v = self.verdict_for(source_key, record_id)
        return {
            None: "unlisted",
            Verdict.true_finding: "true_positive",
            Verdict.not_attack: "false_positive",
            Verdict.unclear: "unclear",
        }[v]

    def check_against(
        self,
        scenario: Scenario,
        keys: list[AnswerKey],
        known_events: dict[str, dict[int, int]] | None = None,
    ) -> None:
        """Raise ValueError unless entries are consistent with the scenario and the keys.

        ``known_events`` (source_key -> {record_id: event_id}) is optional extra validation.
        """
        if self.scenario_id != scenario.scenario_id:
            raise ValueError("adjudication belongs to a different scenario")
        real = {s.source_key for s in scenario.sources if not s.is_synthetic}
        for e in self.entries:
            if e.source_key not in real:
                raise ValueError(f"{e.id}: source {e.source_key} is not a real source")
            if self.score(e.source_key, e.event_record_id, keys) == "key":
                raise ValueError(f"{e.id}: event is already in the answer key")
            known = (known_events or {}).get(e.source_key)
            if known is not None and known.get(e.event_record_id) != e.event_id:
                raise ValueError(f"{e.id}: record/EventID not found in the inspected source")


def load_adjudication(
    path: Path,
    scenario: Scenario | None = None,
    keys: list[AnswerKey] | None = None,
    known_events: dict[str, dict[int, int]] | None = None,
) -> Adjudication:
    """Load adjudication.yaml; with a scenario and keys, also validate every entry."""
    adj = load_model(path, Adjudication)
    if scenario is not None:
        try:
            adj.check_against(scenario, keys or [], known_events)
        except ValueError as e:
            raise ScenarioError(f"{Path(path).name}: {e}") from e
    return adj


def save_adjudication(path: Path, adj: Adjudication) -> None:
    """Write adjudication.yaml."""
    save_model(path, adj)
