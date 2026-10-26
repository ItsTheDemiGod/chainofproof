"""Scenario and ground-truth (answer key) schemas.

A scenario stitches independent real EVTX captures (plus SYNTHETIC companion sources) into one
storyline. Everything synthetic is labelled as such. IDs and patterns live here, in one place.
Models are strict; YAML is validated through JSON mode so enums/strings load cleanly.
"""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from chainofproof.errors import UserError

ACT_ID_PATTERN = r"^GT-ACT-\d{3}$"
CON_ID_PATTERN = r"^GT-CON-\d{3}$"
DEC_ID_PATTERN = r"^GT-DEC-\d{3}$"
INJ_ID_PATTERN = r"^GT-INJ-\d{3}$"
MIS_ID_PATTERN = r"^GT-MIS-\d{3}$"
STAGE_ID_PATTERN = r"^(S[1-9]|D[1-9])$"
SOURCE_KEY_PATTERN = r"^[a-z0-9_]{1,48}$"
TECHNIQUE_PATTERN = r"^T\d{4}(\.\d{3})?$"
UTC_TS_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$"
SHA256_RE = r"^[0-9a-f]{64}$"

UtcTs = Annotated[str, StringConstraints(pattern=UTC_TS_PATTERN)]
SourceKey = Annotated[str, StringConstraints(pattern=SOURCE_KEY_PATTERN)]
StageId = Annotated[str, StringConstraints(pattern=STAGE_ID_PATTERN)]
Technique = Annotated[str, StringConstraints(pattern=TECHNIQUE_PATTERN)]


class ScenarioError(UserError):
    """A scenario or answer key is missing, invalid or inconsistent."""


class SourceKind(StrEnum):
    """What a source file is."""

    real_evtx = "real_evtx"
    synthetic_file_timeline = "synthetic_file_timeline"
    synthetic_auth_log = "synthetic_auth_log"


class Role(StrEnum):
    """Stage role."""

    storyline = "storyline"
    decoy = "decoy"


class Confidence(StrEnum):
    """Confidence level of a ground-truth label."""

    high = "high"
    medium = "medium"
    low = "low"


class ContradictionKind(StrEnum):
    """Anti-forensic contradiction kinds."""

    timestomp = "timestomp"
    log_gap = "log_gap"
    clock_skew = "clock_skew"


class Variant(StrEnum):
    """Dataset variant."""

    clean = "clean"
    perturbed = "perturbed"


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")


class SourceSpec(_Strict):
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


class Stage(_Strict):
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


class AlignmentEntry(_Strict):
    """Per real source: how real capture time and host name map into the virtual timeline."""

    source_key: SourceKey
    real_first_key_event_time: UtcTs
    virtual_first_key_event_time: UtcTs
    time_offset_seconds: int
    host_aliases: dict[str, str]  # real Computer name -> virtual hostname


class VirtualHost(_Strict):
    """A virtual host of the scenario and its (synthetic, RFC 1918) address."""

    hostname: str
    role: str
    ip: str


class NoiseConfig(_Strict):
    """Benign-noise knobs for the synthetic companions (in the scenario so hashes are stable)."""

    benign_fs_entries_per_host: int = Field(default=400, ge=0)
    benign_auth_lines_total: int = Field(default=800, ge=0)


class Provenance(_Strict):
    """Where the real dataset came from."""

    repo_url: str
    clone_commit: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
    retrieved_at: str
    note: str


class Scenario(_Strict):
    """A complete scenario definition (committed as scenario.yaml)."""

    scenario_id: Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]{1,48}$")]
    title: str
    description: str
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
        return self

    def source(self, key: str) -> SourceSpec:
        """The source with this key (KeyError if unknown)."""
        return next(s for s in self.sources if s.source_key == key)

    def aligned(self, key: str) -> AlignmentEntry:
        """The alignment entry of a real source (KeyError if none)."""
        return next(a for a in self.alignment if a.source_key == key)


class SupportingRef(_Strict):
    """Pointer to one event/line that supports a ground-truth label."""

    source_key: SourceKey
    event_record_id: int  # EVTX EventRecordID, or seq / record_id of a synthetic file
    event_id: int | None = None  # Windows EventID (real sources only)


class GroundTruthAction(_Strict):
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


class GroundTruthContradiction(_Strict):
    """A planted cross-source contradiction (perturbed variant only)."""

    id: str = Field(pattern=CON_ID_PATTERN)
    kind: ContradictionKind
    sources_involved: list[SourceKey]
    description: str
    magnitude: float
    magnitude_unit: str  # "seconds" or "count"
    params: dict[str, Any]  # exact, machine-checkable parameters (host, window, files...)
    detectable_by: str


class GroundTruthDecoy(_Strict):
    """A real source that belongs to an unrelated incident."""

    id: str = Field(pattern=DEC_ID_PATTERN)
    source_key: SourceKey
    why_out_of_scope: str


class GroundTruthInjection(_Strict):
    """Reserved for Phase 7 (planted prompt injections)."""

    id: str = Field(pattern=INJ_ID_PATTERN)
    source_key: SourceKey
    description: str


class GroundTruthMissingEvidence(_Strict):
    """Evidence that is NOT available and would be needed to be certain."""

    id: str = Field(pattern=MIS_ID_PATTERN)
    description: str
    confirms_claim: str


class AnswerKey(_Strict):
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

    @model_validator(mode="after")
    def _unique_ids(self) -> AnswerKey:
        ids = [
            x.id
            for group in (
                self.actions,
                self.contradictions,
                self.decoys,
                self.injections,
                self.missing_evidence,
            )
            for x in group
        ]
        dup = sorted({i for i in ids if ids.count(i) > 1})
        if dup:
            raise ValueError(f"duplicate ground-truth IDs: {dup}")
        return self

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
                if r.source_key not in keys:
                    raise ValueError(f"{a.id}: supporting_ref to undeclared source {r.source_key}")
        refs = [s for c in self.contradictions for s in c.sources_involved]
        refs += [d.source_key for d in self.decoys] + [i.source_key for i in self.injections]
        for k in refs:
            if k not in keys:
                raise ValueError(f"reference to undeclared source {k}")


def _load(path: Path, model: type[_Strict]) -> Any:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return model.model_validate_json(json.dumps(data))
    except ValidationError as e:
        first = e.errors()[0]
        where = ".".join(str(x) for x in first["loc"])
        raise ScenarioError(
            f"{Path(path).name}: {where}: {first['msg']} ({e.error_count()} error(s))"
        ) from e
    except (OSError, ValueError, yaml.YAMLError) as e:
        raise ScenarioError(f"{Path(path).name}: {str(e).splitlines()[0]}") from e


def _save(path: Path, obj: _Strict) -> None:
    text = yaml.safe_dump(
        obj.model_dump(mode="json"), sort_keys=False, allow_unicode=True, width=100
    )
    Path(path).write_text(text, encoding="utf-8", newline="\n")


def load_scenario(path: Path) -> Scenario:
    """Load and validate scenario.yaml."""
    return _load(path, Scenario)


def save_scenario(path: Path, scenario: Scenario) -> None:
    """Write scenario.yaml (field order is the model order: deterministic)."""
    _save(path, scenario)


def load_key(path: Path, scenario: Scenario | None = None) -> AnswerKey:
    """Load an answer key; with a scenario, also check every reference."""
    key = _load(path, AnswerKey)
    if scenario is not None:
        try:
            key.check_against(scenario)
        except ValueError as e:
            raise ScenarioError(f"{Path(path).name}: {e}") from e
    return key


def save_key(path: Path, key: AnswerKey) -> None:
    """Write an answer key."""
    _save(path, key)
