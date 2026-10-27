"""Scenario workflows: inventory, keys, generate, build (ingest) and verify."""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from chainofproof.config import Paths
from chainofproof.custody.hashing import sha256_file
from chainofproof.ingest.ingest import ingest_evidence
from chainofproof.ingest.store import EvidenceStore
from chainofproof.scenarios.dataset import (
    dataset_root,
    generated_dir,
    require_dataset,
    scenario_dir,
    scenarios_root,
    verify_dataset,
)
from chainofproof.scenarios.fieldscan import load_known_events
from chainofproof.scenarios.gen_context import REAL_FMT, parse_real
from chainofproof.scenarios.generator import GenResult, generate_variant
from chainofproof.scenarios.inventory import (
    Inventory,
    load_inventory,
    run_inventory,
    save_inventory,
)
from chainofproof.scenarios.keyevents import APPENDED
from chainofproof.scenarios.keys import build_key
from chainofproof.schemas.adjudication import load_adjudication
from chainofproof.schemas.scenario import (
    AnswerKey,
    Scenario,
    ScenarioError,
    SourceKind,
    Variant,
    load_key,
    load_scenario,
    save_key,
)

KEY_FILES = {Variant.clean: "key_clean.yaml", Variant.perturbed: "key_perturbed.yaml"}


def load_all(scenario_id: str) -> tuple[Scenario, Inventory]:
    """Load scenario.yaml and inventory.json of a scenario."""
    d = scenario_dir(scenario_id)
    if not (d / "scenario.yaml").is_file():
        raise ScenarioError(f"unknown scenario {scenario_id!r}")
    inv = d / "inventory.json"
    if not inv.is_file():
        raise ScenarioError(f"{scenario_id}: inventory.json missing; run scenario-inventory first")
    return load_scenario(d / "scenario.yaml"), load_inventory(inv)


def list_scenarios() -> list[tuple[str, str, str]]:
    """(scenario_id, title, variants) for every scenario folder."""
    out = []
    for f in sorted(scenarios_root().glob("*/scenario.yaml")):
        sc = load_scenario(f)
        have = [v.value for v, name in KEY_FILES.items() if (f.parent / name).is_file()]
        title = sc.title + (f" [supersedes {sc.supersedes}]" if sc.supersedes else "")
        out.append((sc.scenario_id, title, ", ".join(have) or "(no keys yet)"))
    return out


def inventory_scenario(paths: Paths, scenario_id: str, force: bool = False) -> Inventory:
    """Run the inventory + key-event discovery and write inventory.json (never silently)."""
    d = scenario_dir(scenario_id)
    scenario = load_scenario(d / "scenario.yaml")
    out = d / "inventory.json"
    if out.exists() and not force:
        raise ScenarioError(f"{out.name} exists (committed output); use --force to overwrite")
    root = dataset_root(paths)
    require_dataset(scenario, root)
    inv = run_inventory(scenario, root)
    save_inventory(out, inv)
    return inv


def check_alignment(scenario: Scenario, inv: Inventory) -> list[str]:
    """Alignment must agree with the discovered key events (virtual = real + offset)."""
    problems = []
    for a in scenario.alignment:
        off = timedelta(seconds=a.time_offset_seconds)
        virt = (parse_real(a.real_first_key_event_time) + off).strftime(REAL_FMT)
        if virt != a.virtual_first_key_event_time:
            problems.append(f"{a.source_key}: virtual time != real time + offset")
        st = next((k for k in inv.key_events if k.source_key == a.source_key), None)
        anchors = (
            [e.real_time for e in st.result.events if set(e.supports) - APPENDED] if st else []
        )
        if anchors:
            first = min(anchors)
            if first != a.real_first_key_event_time:
                problems.append(f"{a.source_key}: alignment anchor differs from first key event")
    return problems


def generate(
    paths: Paths, scenario_id: str, variant: Variant, force: bool = False
) -> tuple[Path, GenResult]:
    """Generate one variant's companion files into the gitignored generated folder."""
    scenario, inv = load_all(scenario_id)
    out = generated_dir(paths, scenario_id, variant.value)
    keyfile = scenario_dir(scenario_id) / KEY_FILES[variant]
    if out.is_dir() and any(out.iterdir()) and not force and keyfile.is_file():
        known = load_key(keyfile, scenario).generated_file_hashes
        stale = [r for r, h in known.items() if (out / r).is_file() and sha256_file(out / r) != h]
        if stale:
            raise ScenarioError(f"generated files differ from the key: {stale}; use --force")
    return out, generate_variant(scenario, inv, variant, out)


def write_keys(scenario_id: str) -> list[Path]:
    """(Re)write key_clean.yaml and key_perturbed.yaml from a fresh generator run."""
    scenario, inv = load_all(scenario_id)
    written = []
    for variant in Variant:
        with tempfile.TemporaryDirectory(prefix="cop_keys_") as tmp:
            gen = generate_variant(scenario, inv, variant, Path(tmp))
        path = scenario_dir(scenario_id) / KEY_FILES[variant]
        save_key(path, build_key(scenario, inv, variant, gen))
        written.append(path)
    return written


@dataclass
class BuiltItem:
    """One ingested source."""

    evidence_id: str
    source_key: str
    source_type: str
    size_bytes: int
    sha256: str


def build_case(
    paths: Paths, scenario_id: str, variant: Variant, force: bool = False
) -> tuple[str, list[BuiltItem]]:
    """Verify dataset, generate companions, create the case and ingest every source."""
    scenario, _ = load_all(scenario_id)
    require_dataset(scenario, dataset_root(paths))
    gen_dir, _ = generate(paths, scenario_id, variant, force)
    case_id = f"{scenario_id}_{variant.value}"
    store = EvidenceStore(paths)
    label = f"{scenario.scenario_id} ({variant.value})"
    existing = store.get_case(case_id)
    if existing is None:
        store.create_case(case_id, scenario.title, label)
    elif existing.description != label:  # never mix evidence of different scenario revisions
        raise ScenarioError(f"case {case_id} exists but was created for another scenario")
    items = []
    for s in scenario.sources:
        real = s.kind == SourceKind.real_evtx
        src = (dataset_root(paths) if real else gen_dir) / s.relative_path
        desc = f"[{s.source_key}] {'SYNTHETIC ' if s.is_synthetic else ''}{s.description}"
        sha = sha256_file(src)
        rec = store.find_by_hash(case_id, sha) or ingest_evidence(
            paths, case_id, src, desc, ingested_by="scenario-build"
        )
        items.append(
            BuiltItem(
                rec.evidence_id, s.source_key, rec.source_type.value, rec.size_bytes, rec.sha256
            )
        )
    return case_id, items


def verify_scenario(paths: Paths, scenario_id: str) -> list[str]:
    """Full check: dataset hashes, alignment, key validity, regeneration determinism."""
    d = scenario_dir(scenario_id)
    scenario, inv = load_all(scenario_id)
    problems = verify_dataset(scenario, dataset_root(paths))
    problems += check_alignment(scenario, inv)
    keys: list[AnswerKey] = []
    for variant in Variant:
        kf = d / KEY_FILES[variant]
        if not kf.is_file():
            problems.append(f"{kf.name}: missing")
            continue
        try:
            key = load_key(kf, scenario)
        except ScenarioError as e:
            problems.append(str(e))
            continue
        keys.append(key)
        problems += _check_determinism(scenario, inv, variant, key)
    return problems + _check_adjudication(d, scenario, keys)


def _check_adjudication(d: Path, scenario: Scenario, keys: list[AnswerKey]) -> list[str]:
    """adjudication.yaml must exist and agree with the scenario, the keys and the inspection."""
    adj, insp = d / "adjudication.yaml", d / "field_inspection.json"
    if not adj.is_file() or not insp.is_file():
        return ["adjudication.yaml / field_inspection.json: missing"]
    try:
        load_adjudication(adj, scenario, keys, load_known_events(insp))
    except (ScenarioError, ValueError, KeyError) as e:
        return [str(e)]
    return []


def _check_determinism(
    scenario: Scenario, inv: Inventory, variant: Variant, key: AnswerKey
) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="cop_verify_") as tmp:
        gen = generate_variant(scenario, inv, variant, Path(tmp))
    out = [
        f"{variant.value}/{rel}: hash differs from key"
        for rel, h in key.generated_file_hashes.items()
        if gen.hashes.get(rel) != h
    ]
    if set(gen.hashes) != set(key.generated_file_hashes):
        out.append(f"{variant.value}: generated file set differs from key")
    rebuilt = json.dumps(build_key(scenario, inv, variant, gen).model_dump(mode="json"))
    if rebuilt != json.dumps(key.model_dump(mode="json")):
        out.append(f"{variant.value}: key content differs from a fresh build (stale key?)")
    return out
