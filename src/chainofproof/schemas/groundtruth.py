"""Ground-truth (answer key) schemas: attacker actions, contradictions, decoys, missing evidence.

Pairing rule (Phase 2.1): every supporting ref that points at a SYNTHETIC record must either name
the real event(s) it is paired with and the shared field/value (``pairing_*``), or be marked
``synthetic_only``. Refs to real sources carry neither. See docs/scenarios.md.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import Field, model_validator

from chainofproof.schemas.common import (
    ACT_ID_PATTERN,
    CON_ID_PATTERN,
    CONN_ID_PATTERN,
    DEC_ID_PATTERN,
    INJ_ID_PATTERN,
    LNK_ID_PATTERN,
    MIS_ID_PATTERN,
    Confidence,
    ContradictionKind,
    LinkBasis,
    LinkKind,
    ScenarioError,
    SourceKey,
    SourceKind,
    StageId,
    StrictModel,
    Technique,
    UtcTs,
    Variant,
    load_model,
    save_model,
)

if TYPE_CHECKING:
    from chainofproof.schemas.scenario import Scenario


class SupportingRef(StrictModel):
    """Pointer to one event/line that supports a ground-truth label."""

    source_key: SourceKey
    event_record_id: int  # EVTX EventRecordID, or seq / record_id of a synthetic file
    event_id: int | None = None  # Windows EventID (real sources only)
    pairing_field: str | None = None  # synthetic refs: the field shared with a real event
    pairing_value: str | None = None  # ... and its value (a name, never free text)
    paired_source_key: SourceKey | None = None  # the real source holding the paired event(s)
    paired_record_ids: list[int] = []  # EventRecordIDs of the paired real event(s)
    synthetic_only: bool = False  # True: no real event shows this; labelled as a supplement

    @model_validator(mode="after")
    def _pairing_consistent(self) -> SupportingRef:
        paired = [self.pairing_field, self.pairing_value, self.paired_source_key]
        if self.synthetic_only and (any(paired) or self.paired_record_ids):
            raise ValueError("synthetic_only ref must not carry pairing fields")
        if any(paired) and not (all(paired) and self.paired_record_ids):
            raise ValueError("pairing needs field, value, paired source and record ids together")
        return self

    @property
    def is_paired(self) -> bool:
        """True when this synthetic ref is paired with real event(s)."""
        return self.pairing_field is not None


class LinkRef(SupportingRef):
    """A link reference: a real record, or a SYNTHETIC line with the ``conn_id`` it carries."""

    conn_id: str | None = Field(default=None, pattern=CONN_ID_PATTERN)


class GroundTruthLink(StrictModel):
    """A link between two stages/hosts and exactly what the evidence does and does not show."""

    id: str = Field(pattern=LNK_ID_PATTERN)
    from_host: str
    to_host: str
    kind: LinkKind
    basis: LinkBasis
    from_stage: StageId
    to_stage: StageId
    evidence_refs: list[LinkRef]
    real_evidence_note: str  # plain text: what the real files show and do NOT show
    expected_agent_statement: str  # one sentence a careful agent should say

    @model_validator(mode="after")
    def _basis_matches_refs(self) -> GroundTruthLink:
        refs = self.evidence_refs
        if not refs:
            raise ValueError(f"{self.id}: a link needs at least one evidence ref")
        if self.basis == LinkBasis.synthetic_only:
            conns = {r.conn_id for r in refs}
            if not all(r.synthetic_only for r in refs) or None in conns or len(conns) != 1:
                raise ValueError(
                    f"{self.id}: synthetic_only link needs synthetic_only refs, one conn_id"
                )
        elif any(r.synthetic_only or r.conn_id for r in refs):
            raise ValueError(f"{self.id}: alignment_constructed link must use real records only")
        return self


class GroundTruthAction(StrictModel):
    """An attacker action (one per key-event cluster)."""

    id: str = Field(pattern=ACT_ID_PATTERN)
    stage_id: StageId
    description: str
    attack_technique_id: Technique
    virtual_host: str
    account: str | None
    real_time: UtcTs
    virtual_time: UtcTs
    supporting_refs: list[SupportingRef]
    confidence: Confidence
    rationale: str


class GroundTruthContradiction(StrictModel):
    """A planted cross-source contradiction (perturbed variant only)."""

    id: str = Field(pattern=CON_ID_PATTERN)
    kind: ContradictionKind
    sources_involved: list[SourceKey]
    description: str
    magnitude: float
    magnitude_unit: str  # "seconds" or "count"
    params: dict[str, Any]  # exact, machine-checkable parameters (host, window, files...)
    detectable_by: str  # plain words; ONLY checks that tests/oracles.py proves to work
    checks: list[str] = []  # machine names of those checks (keys of tests/oracles.CHECKS)
    # log_gap only: benign conn_ids that lose exactly one end because the gap removed it
    expected_collateral_conn_ids: list[str] = []

    @model_validator(mode="after")
    def _collateral_valid(self) -> GroundTruthContradiction:
        ids = self.expected_collateral_conn_ids
        if ids and self.kind != ContradictionKind.log_gap:
            raise ValueError(f"{self.id}: collateral conn ids only belong to a log_gap")
        if ids != sorted(set(ids)) or not all(re.match(CONN_ID_PATTERN, i) for i in ids):
            raise ValueError(f"{self.id}: collateral conn ids must be sorted, unique CONN ids")
        return self


class GroundTruthDecoy(StrictModel):
    """A real source that belongs to an unrelated incident."""

    id: str = Field(pattern=DEC_ID_PATTERN)
    source_key: SourceKey
    why_out_of_scope: str


class GroundTruthInjection(StrictModel):
    """Reserved for Phase 7 (planted prompt injections)."""

    id: str = Field(pattern=INJ_ID_PATTERN)
    source_key: SourceKey
    description: str


class GroundTruthMissingEvidence(StrictModel):
    """Evidence that is NOT available and would be needed to be certain."""

    id: str = Field(pattern=MIS_ID_PATTERN)
    description: str
    confirms_claim: str


class AnswerKey(StrictModel):
    """Ground truth for one variant of a scenario."""

    scenario_id: str
    variant: Variant
    seed: int
    actions: list[GroundTruthAction]
    contradictions: list[GroundTruthContradiction]
    decoys: list[GroundTruthDecoy]
    injections: list[GroundTruthInjection]
    missing_evidence: list[GroundTruthMissingEvidence]
    generated_file_hashes: dict[str, str]  # published relative path -> sha256
    links: list[GroundTruthLink] = []

    @model_validator(mode="after")
    def _unique_ids(self) -> AnswerKey:
        groups = (
            self.actions,
            self.contradictions,
            self.decoys,
            self.injections,
            self.missing_evidence,
            self.links,
        )
        ids = [x.id for group in groups for x in group]
        dup = sorted({i for i in ids if ids.count(i) > 1})
        if dup:
            raise ValueError(f"duplicate ground-truth IDs: {dup}")
        return self

    def _check_ref(self, owner: str, r: SupportingRef, scenario: Scenario) -> None:
        kinds = {s.source_key: s.kind for s in scenario.sources}
        if r.source_key not in kinds:
            raise ValueError(f"{owner}: supporting_ref to undeclared source {r.source_key}")
        if kinds[r.source_key] == SourceKind.real_evtx:
            if r.is_paired or r.synthetic_only:
                raise ValueError(f"{owner}: a ref to real source {r.source_key} carries pairing")
        elif not (r.is_paired or r.synthetic_only):
            raise ValueError(f"{owner}: synthetic ref {r.source_key}:{r.event_record_id} unpaired")
        if r.paired_source_key and kinds.get(r.paired_source_key) != SourceKind.real_evtx:
            raise ValueError(f"{owner}: paired_source_key must be a declared real source")

    def check_against(self, scenario: Scenario) -> None:
        """Raise ValueError unless every reference points at something the scenario declares."""
        if self.scenario_id != scenario.scenario_id:
            raise ValueError("key belongs to a different scenario")
        keys = {s.source_key for s in scenario.sources}
        stages = {s.stage_id for s in scenario.stages}
        hosts = {h.hostname for h in scenario.virtual_hosts}
        for a in self.actions:
            if a.stage_id not in stages or a.virtual_host not in hosts:
                raise ValueError(f"{a.id}: unknown stage or host")
            for r in a.supporting_refs:
                self._check_ref(a.id, r, scenario)
        for ln in self.links:
            if (
                not {ln.from_host, ln.to_host} <= hosts
                or not {ln.from_stage, ln.to_stage} <= stages
            ):
                raise ValueError(f"{ln.id}: unknown stage or host")
            for r in ln.evidence_refs:
                self._check_ref(ln.id, r, scenario)
        refs = [s for c in self.contradictions for s in c.sources_involved]
        refs += [d.source_key for d in self.decoys] + [i.source_key for i in self.injections]
        for k in refs:
            if k not in keys:
                raise ValueError(f"reference to undeclared source {k}")


def load_key(path: Path, scenario: Scenario | None = None) -> AnswerKey:
    """Load an answer key; with a scenario, also check every reference."""
    key = load_model(path, AnswerKey)
    if scenario is not None:
        try:
            key.check_against(scenario)
        except ValueError as e:
            raise ScenarioError(f"{Path(path).name}: {e}") from e
    return key


def save_key(path: Path, key: AnswerKey) -> None:
    """Write an answer key."""
    save_model(path, key)
