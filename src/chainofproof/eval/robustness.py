"""EVALUATION ONLY: re-run the detectors on freshly generated synthetic data for other seeds.

For each seed the SYNTHETIC files are generated into a TEMP directory (nothing is ingested, no
committed file or generated folder is touched), parsed with the pure parsers (same alignment as the
normalizer), combined with the real EVTX events of the existing case read from the agent view, and
scored in memory against the key built for that seed.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from chainofproof.config import Paths
from chainofproof.custody.hashing import sha256_file
from chainofproof.eval.detector_eval import match_hits
from chainofproof.eval.gt_link import build_index
from chainofproof.scenarios.build import real_pipes
from chainofproof.scenarios.dataset import scenario_dir
from chainofproof.scenarios.generator import generate_variant
from chainofproof.scenarios.inventory import load_inventory
from chainofproof.scenarios.keys import build_key
from chainofproof.scenarios.source_map import load_case_scenario
from chainofproof.schemas.events import NormalizedEvent, SourceKindName
from chainofproof.schemas.scenario import Scenario, Variant
from chainofproof.tools.alignment import build_context
from chainofproof.tools.auth_log_parser import iter_auth_log
from chainofproof.tools.detectors import DETECTORS
from chainofproof.tools.detectors.base import Hit
from chainofproof.tools.detectors.runner import get_params
from chainofproof.tools.fs_timeline_parser import iter_fs_timeline
from chainofproof.tools.loader import load_case_events

SEEDS = (101, 102, 103, 104, 105)


@dataclass
class SeedRow:
    """Result of one (seed, variant) run."""

    seed: int
    variant: str
    found: dict[str, bool] = field(default_factory=dict)
    unexpected: list[str] = field(default_factory=list)
    collateral: tuple[int, int] = (0, 0)  # (explained collateral hits, collateral ids in the key)
    error: str | None = None


def _synthetic(scn: Scenario, folder: Path):
    """Parse every synthetic file of the generated folder: events + (source_key, id) -> uids."""
    events: list[NormalizedEvent] = []
    refs: dict[tuple[str, int], list[str]] = {}
    labels: dict[str, str] = {}
    for spec in scn.sources:
        if not spec.is_synthetic:
            continue
        path = folder / spec.relative_path
        ctx = build_context(scn, spec, "EV-000000", sha256_file(path))
        parser = (
            iter_fs_timeline if ctx.source_kind == SourceKindName.fs_timeline else iter_auth_log
        )
        for ev, meta in parser(path, ctx):
            events.append(ev)
            refs.setdefault((meta.source_key, ev.record_id or 0), []).append(ev.event_uid)
            labels[meta.source_key] = ev.evidence_label
    return events, refs, labels


def run_robustness(paths: Paths, case_prefix: str, seeds: tuple[int, ...] = SEEDS) -> list[SeedRow]:
    """Seeds x variants. ``case_prefix`` = scenario id; its cases must already be normalized."""
    rows: list[SeedRow] = []
    for variant in Variant:
        case_id = f"{case_prefix}_{variant.value}"
        scn, _ = load_case_scenario(case_id)
        inv = load_inventory(scenario_dir(scn.scenario_id) / "inventory.json")
        real = [
            e for e in load_case_events(paths, case_id)[0] if e.source_kind == SourceKindName.evtx
        ]
        idx = build_index(paths, case_id)
        for seed in seeds:
            rows.append(_one(scn, inv, variant, seed, real, idx))
    return sorted(rows, key=lambda r: (r.variant, r.seed))


def _one(scn: Scenario, inv, variant: Variant, seed: int, real, idx) -> SeedRow:
    row = SeedRow(seed, variant.value)
    seeded = scn.model_copy(update={"seed": seed})
    try:
        with tempfile.TemporaryDirectory(prefix="cop_robust_") as tmp:
            pipes = real_pipes(scn.scenario_id, scn)
            gen = generate_variant(seeded, inv, variant, Path(tmp), pipes)
            key = build_key(seeded, inv, variant, gen)
            events, refs, labels = _synthetic(seeded, Path(tmp))
    except Exception as e:  # noqa: BLE001 - report, never hide, a generator failure
        row.error = type(e).__name__
        return row
    allev = [*real, *events]
    hits: list[Hit] = []
    for name, (fn, _) in DETECTORS.items():
        hits += fn(allev, get_params(name))

    def resolve(sk: str, rid: int) -> list[str]:
        return refs.get((sk, rid)) or idx.uids(sk, rid)

    def label_of(sk: str) -> str | None:
        return labels.get(sk)

    ev = match_hits(key, hits, resolve, label_of, variant, f"seed{seed}")
    row.found = {c.con_id: c.found for c in ev.cons}
    row.unexpected = [f"{h.detector}/{h.kind}" for h in ev.unexpected]
    row.collateral = (len(ev.explained), len(ev.collateral_ids))
    return row
