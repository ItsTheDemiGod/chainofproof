"""Scenario schema: independent real EVTX captures plus SYNTHETIC companions in one storyline.

Everything synthetic is labelled as such. IDs, enums and the YAML helpers live in ``common``; the
answer-key models in ``groundtruth``. Both are re-exported here so callers can import everything
scenario-related from ``chainofproof.schemas.scenario``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from pydantic import Field, StringConstraints, model_validator

from chainofproof.schemas.common import (
    SHA256_RE,
    Confidence,
    ContradictionKind,
    Role,
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
from chainofproof.schemas.groundtruth import (
    AnswerKey,
    GroundTruthAction,
    GroundTruthContradiction,
    GroundTruthDecoy,
    GroundTruthInjection,
    GroundTruthMissingEvidence,
    SupportingRef,
    load_key,
    save_key,
)

__all__ = [
    "AnswerKey",
    "Confidence",
    "ContradictionKind",
    "GroundTruthAction",
    "GroundTruthContradiction",
    "GroundTruthDecoy",
    "GroundTruthInjection",
    "GroundTruthMissingEvidence",
    "Role",
    "Scenario",
    "ScenarioError",
    "SourceKind",
    "SupportingRef",
    "Variant",
    "load_key",
    "load_scenario",
    "save_key",
    "save_scenario",
]


class SourceSpec(StrictModel):
    """One evidence source of the scenario (real file or SYNTHETIC generated file)."""

    source_key: SourceKey
    kind: SourceKind
    relative_path: str  # real: under the dataset root; synthetic: under the variant folder
    stage_id: StageId | None
    sha256: Annotated[str, StringConstraints(pattern=SHA256_RE)] | None
    description: str
    is_synthetic: bool

    @model_validator(mode="after")
    def _kind_matches_flag(self) -> SourceSpec:
        if self.is_synthetic != (self.kind != SourceKind.real_evtx):
            raise ValueError(f"{self.source_key}: is_synthetic does not match kind {self.kind}")
        if self.kind == SourceKind.real_evtx and self.sha256 is None:
            raise ValueError(f"{self.source_key}: a real source needs a sha256")
        return self


class Stage(StrictModel):
    """One storyline stage (S*) or decoy (D*)."""

    stage_id: StageId
    name: str
    attack_technique_ids: list[Technique]
    description: str
    role: Role

    @model_validator(mode="after")
    def _prefix(self) -> Stage:
        if self.stage_id[0] != ("S" if self.role == Role.storyline else "D"):
            raise ValueError(f"{self.stage_id}: id prefix does not match role {self.role}")
        return self


class AlignmentEntry(StrictModel):
    """Per real source: how real capture time and host name map into the virtual timeline."""

    source_key: SourceKey
    real_first_key_event_time: UtcTs  # anchor: first key event of the stage's primary action
    virtual_first_key_event_time: UtcTs
    time_offset_seconds: int
    host_aliases: dict[str, str]  # real Computer name -> virtual hostname


class VirtualHost(StrictModel):
    """A virtual host of the scenario and its (synthetic, RFC 1918) address."""

    hostname: str
    role: str
    ip: str


class NoiseConfig(StrictModel):
    """Benign-noise knobs for the synthetic companions (in the scenario so hashes are stable)."""

    benign_fs_entries_per_host: int = Field(default=400, ge=0)
    benign_auth_lines_total: int = Field(default=800, ge=0)


class Provenance(StrictModel):
    """Where the real dataset came from."""

    repo_url: str
    clone_commit: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
    retrieved_at: str
    note: str


class Scenario(StrictModel):
    """A complete scenario definition (committed as scenario.yaml)."""

    scenario_id: Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]{1,48}$")]
    title: str
    description: str
    supersedes: str | None = None  # scenario_id this revision replaces (its cases stay as history)
    supersedes_reason: str | None = None
    dataset_provenance: Provenance
    seed: int
    virtual_start_time: UtcTs
    virtual_hosts: list[VirtualHost]
    noise: NoiseConfig = NoiseConfig()
    sources: list[SourceSpec]
    stages: list[Stage]
    alignment: list[AlignmentEntry]

    @model_validator(mode="after")
    def _consistent(self) -> Scenario:
        keys = [s.source_key for s in self.sources]
        stages = [s.stage_id for s in self.stages]
        for what, ids in (("source_key", keys), ("stage_id", stages)):
            if len(set(ids)) != len(ids):
                raise ValueError(f"duplicate {what}")
        for s in self.sources:
            if s.stage_id is not None and s.stage_id not in stages:
                raise ValueError(f"{s.source_key}: unknown stage {s.stage_id}")
        real = {s.source_key for s in self.sources if s.kind == SourceKind.real_evtx}
        aligned = [a.source_key for a in self.alignment]
        if set(aligned) != real or len(aligned) != len(real):
            raise ValueError("alignment must have exactly one entry per real source")
        hosts = {h.hostname for h in self.virtual_hosts}
        for a in self.alignment:
            if not set(a.host_aliases.values()) <= hosts:
                raise ValueError(f"{a.source_key}: alias to an undeclared virtual host")
        if (self.supersedes is None) != (self.supersedes_reason is None):
            raise ValueError("supersedes and supersedes_reason go together")
        return self

    def source(self, key: str) -> SourceSpec:
        """The source with this key (KeyError if unknown)."""
        return next(s for s in self.sources if s.source_key == key)

    def aligned(self, key: str) -> AlignmentEntry:
        """The alignment entry of a real source (KeyError if none)."""
        return next(a for a in self.alignment if a.source_key == key)


def load_scenario(path: Path) -> Scenario:
    """Load and validate scenario.yaml."""
    return load_model(path, Scenario)


def save_scenario(path: Path, scenario: Scenario) -> None:
    """Write scenario.yaml (field order is the model order: deterministic)."""
    save_model(path, scenario)
