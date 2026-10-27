"""Map the evidence items of a case to scenario source keys (by SHA-256).

The case id must be ``<scenario_id>_<variant>`` or, for a seed case,
``<scenario_id>_s<seed>_<variant>``. Real files are matched through the hashes in scenario.yaml;
generated companion files through ``generated_file_hashes`` of the variant's key (only that hash
table is read here, never the ground truth itself). Anything unresolved is an error.
"""

from __future__ import annotations

import re
from pathlib import Path

from chainofproof.config import Paths
from chainofproof.ingest.store import EvidenceStore
from chainofproof.scenarios.dataset import key_file, scenario_dir
from chainofproof.schemas.scenario import (
    Scenario,
    ScenarioError,
    SourceSpec,
    Variant,
    load_key,
    load_scenario,
)

_SEED = re.compile(r"^(?P<sid>.+)_s(?P<seed>\d+)$")


def parse_case_id(case_id: str) -> tuple[str, int | None, Variant]:
    """``credtheft_lateral_v4_s201_clean`` -> (scenario id, 201, clean); base cases have no seed."""
    for v in Variant:
        head = case_id.removesuffix(f"_{v.value}")
        if head == case_id:
            continue
        m = _SEED.match(head)
        sid, seed = (m["sid"], int(m["seed"])) if m else (head, None)
        if (scenario_dir(sid) / "scenario.yaml").is_file():
            return sid, seed, v
    raise ScenarioError(f"case {case_id!r} is not <scenario_id>_<variant> of a known scenario")


def split_case_id(case_id: str) -> tuple[str, Variant]:
    """``credtheft_lateral_v3_clean`` -> (``credtheft_lateral_v3``, clean); else ScenarioError."""
    sid, _, variant = parse_case_id(case_id)
    return sid, variant


def case_key_path(case_id: str) -> Path:
    """Path of the answer key of a case (base or seed key)."""
    sid, seed, variant = parse_case_id(case_id)
    return key_file(sid, variant.value, seed)


def load_case_scenario(case_id: str) -> tuple[Scenario, Variant]:
    """The scenario definition (with the case's seed applied) and variant a case was built from."""
    sid, seed, variant = parse_case_id(case_id)
    scn = load_scenario(scenario_dir(sid) / "scenario.yaml")
    return (scn if seed is None else scn.model_copy(update={"seed": seed})), variant


def source_hashes(
    scenario: Scenario, variant: Variant, seed: int | None = None
) -> dict[str, SourceSpec]:
    """sha256 -> SourceSpec for every source of the scenario in this variant (and seed)."""
    key = load_key(key_file(scenario.scenario_id, variant.value, seed), scenario)
    by_path = {s.relative_path: s for s in scenario.sources if s.sha256 is None}
    out = {s.sha256: s for s in scenario.sources if s.sha256 is not None}
    for rel, sha in key.generated_file_hashes.items():
        if rel in by_path:
            out[sha] = by_path[rel]
    return out


def resolve_source_keys(paths: Paths, case_id: str) -> dict[str, str]:
    """evidence_id -> source_key for every evidence item of the case; refuses anything unknown."""
    scenario, variant = load_case_scenario(case_id)
    seed = parse_case_id(case_id)[1]
    items = EvidenceStore(paths).list_evidence(case_id)
    if not items:
        raise ScenarioError(f"case {case_id!r} has no evidence")
    by_hash = source_hashes(scenario, variant, seed)
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
