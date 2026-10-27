"""Map the evidence items of a case to scenario source keys (by SHA-256).

The case id must be ``<scenario_id>_<variant>``. Real files are matched through the hashes in
scenario.yaml; generated companion files through ``generated_file_hashes`` of the variant's key
(only that hash table is read here, never the ground truth itself). Anything unresolved is an error.
"""

from __future__ import annotations

from chainofproof.config import Paths
from chainofproof.ingest.store import EvidenceStore
from chainofproof.scenarios.dataset import scenario_dir
from chainofproof.schemas.scenario import (
    Scenario,
    ScenarioError,
    SourceSpec,
    Variant,
    load_key,
    load_scenario,
)


def split_case_id(case_id: str) -> tuple[str, Variant]:
    """``credtheft_lateral_v3_clean`` -> (``credtheft_lateral_v3``, clean); else ScenarioError."""
    for v in Variant:
        sid = case_id.removesuffix(f"_{v.value}")
        if sid != case_id and (scenario_dir(sid) / "scenario.yaml").is_file():
            return sid, v
    raise ScenarioError(f"case {case_id!r} is not <scenario_id>_<variant> of a known scenario")


def load_case_scenario(case_id: str) -> tuple[Scenario, Variant]:
    """The scenario definition and variant a case was built from."""
    sid, variant = split_case_id(case_id)
    return load_scenario(scenario_dir(sid) / "scenario.yaml"), variant


def source_hashes(scenario: Scenario, variant: Variant) -> dict[str, SourceSpec]:
    """sha256 -> SourceSpec for every source of the scenario in this variant."""
    key = load_key(scenario_dir(scenario.scenario_id) / f"key_{variant.value}.yaml", scenario)
    by_path = {s.relative_path: s for s in scenario.sources if s.sha256 is None}
    out = {s.sha256: s for s in scenario.sources if s.sha256 is not None}
    for rel, sha in key.generated_file_hashes.items():
        if rel in by_path:
            out[sha] = by_path[rel]
    return out


def resolve_source_keys(paths: Paths, case_id: str) -> dict[str, str]:
    """evidence_id -> source_key for every evidence item of the case; refuses anything unknown."""
    scenario, variant = load_case_scenario(case_id)
    items = EvidenceStore(paths).list_evidence(case_id)
    if not items:
        raise ScenarioError(f"case {case_id!r} has no evidence")
    by_hash = source_hashes(scenario, variant)
    out: dict[str, str] = {}
    unknown = [i.evidence_id for i in items if i.sha256 not in by_hash]
    if unknown:
        raise ScenarioError(
            f"{len(unknown)} evidence item(s) not part of {scenario.scenario_id} "
            f"{variant.value}: {', '.join(unknown)}"
        )
    for i in items:
        out[i.evidence_id] = by_hash[i.sha256].source_key
    return out
