"""EVALUATION ONLY: does the normalized data still carry everything the answer key points at?

Checks (a non-zero ``unresolved`` is a bug to fix, never to hide):
* key coverage: every GT-ACT / GT-LNK / contradiction / adjudication reference resolves to events;
* count check: events per real source equal the inventory record counts;
* alignment: real references land exactly on the key's virtual time;
* perturbations survive: the planted clock skew, timestomping and removed lines are still there.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from chainofproof.config import Paths
from chainofproof.eval.gt_link import (
    EvalIndex,
    build_index,
    contradiction_refs,
    key_action_refs,
    resolve_ref,
)
from chainofproof.scenarios.dataset import scenario_dir
from chainofproof.scenarios.inventory import load_inventory
from chainofproof.scenarios.source_map import load_case_scenario
from chainofproof.schemas.adjudication import Adjudication, load_adjudication
from chainofproof.schemas.scenario import AnswerKey, Scenario, SourceKind, Variant, load_key

TS = "%Y-%m-%dT%H:%M:%S.%fZ"


@dataclass
class CoverageReport:
    """Result of ``run_coverage`` for one case (every list should be empty)."""

    case_id: str
    variant: Variant
    refs_checked: int = 0
    unresolved: list[str] = field(default_factory=list)
    count_mismatches: list[str] = field(default_factory=list)
    event_counts: dict[str, int] = field(default_factory=dict)
    alignment_problems: list[str] = field(default_factory=list)
    alignment_checked: int = 0
    perturbations: dict[str, str] = field(default_factory=dict)  # name -> "ok" or a problem

    @property
    def ok(self) -> bool:
        """True when nothing is unresolved, mismatched or broken."""
        return not (
            self.unresolved
            or self.count_mismatches
            or self.alignment_problems
            or any(v != "ok" for v in self.perturbations.values())
        )


def _t(idx: EvalIndex, source_key: str, rid: int) -> datetime | None:
    uids = idx.uids(source_key, rid)
    return datetime.strptime(idx.rows[uids[0]]["timestamp"], TS) if uids else None


def check_key_refs(rep: CoverageReport, idx: EvalIndex, key: AnswerKey, adj: Adjudication) -> None:
    """Every reference of the key and the adjudication list must resolve to a normalized event."""
    for owner, r in key_action_refs(key):
        rep.refs_checked += 1
        if not resolve_ref(idx, r):
            rep.unresolved.append(f"{owner}: {r.source_key}:{r.event_record_id}")
    for ln in key.links:
        for r in ln.evidence_refs:
            rep.refs_checked += 1
            if not resolve_ref(idx, r, r.conn_id):
                rep.unresolved.append(f"{ln.id}: {r.source_key}:{r.event_record_id} {r.conn_id}")
    for owner, sk, rid, expected in contradiction_refs(key):
        rep.refs_checked += 1
        if bool(idx.uids(sk, rid)) != expected:
            what = "missing" if expected else "present but should be removed"
            rep.unresolved.append(f"{owner}: {sk}:{rid} {what}")
    for e in adj.entries:
        rep.refs_checked += 1
        uids = idx.uids(e.source_key, e.event_record_id)
        if not uids or idx.rows[uids[0]]["event_id"] != e.event_id:
            rep.unresolved.append(f"{e.id}: {e.source_key}:{e.event_record_id}")


def check_counts(rep: CoverageReport, idx: EvalIndex, scn: Scenario, case_id: str) -> None:
    """Events per real source must equal the inventory record counts."""
    inv = load_inventory(scenario_dir(scn.scenario_id) / "inventory.json")
    for s in inv.sources:
        n = len(idx.by_source(s.source_key))
        rep.event_counts[s.source_key] = n
        if n != s.record_count:
            rep.count_mismatches.append(f"{s.source_key}: {n} events, inventory {s.record_count}")


def check_alignment(rep: CoverageReport, idx: EvalIndex, key: AnswerKey, scn: Scenario) -> None:
    """The earliest real reference of each action sits exactly at the key's virtual_time."""
    real = {s.source_key for s in scn.sources if s.kind == SourceKind.real_evtx}
    for a in key.actions:
        times = [t for r in a.supporting_refs if r.source_key in real
                 if (t := _t(idx, r.source_key, r.event_record_id))]  # fmt: skip
        if not times:
            continue
        rep.alignment_checked += 1
        if min(times).strftime(TS) != a.virtual_time:
            rep.alignment_problems.append(f"{a.id}: {min(times).strftime(TS)} != {a.virtual_time}")


def check_perturbations(rep: CoverageReport, idx: EvalIndex, key: AnswerKey) -> None:
    """Skew, timestomp and removed lines must still be present after normalization."""
    for c in key.contradictions:
        p = c.params
        if c.kind.value == "timestomp":
            bad = []
            for f in p["files"]:
                uids = idx.uids(f["source_key"], f["record_id"])
                fl = idx.row(uids[0])["fields"] if uids else {}
                gap = _gap(fl.get("fn_created"), fl.get("si_created"))
                if gap != f["delta_seconds"] or gap < 86400:
                    bad.append(str(f["record_id"]))
            rep.perturbations[c.id] = "ok" if not bad else f"timestomp lost for {bad}"
        elif c.kind.value == "clock_skew":
            rep.perturbations[c.id] = _skew(idx, p)
        elif c.kind.value == "log_gap":
            rng = range(p["first_removed_seq"], p["last_removed_seq"] + 1)
            still = [s for s in rng if idx.uids(p["source_key"], s)]
            around = (p["first_removed_seq"] - 1, p["last_removed_seq"] + 1)
            edges = all(idx.uids(p["source_key"], s) for s in around)
            ok = not still and edges
            rep.perturbations[c.id] = (
                "ok" if ok else f"gap changed (present: {still}, edges {edges})"
            )


def _gap(a: str | None, b: str | None) -> int:
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return (
        int((datetime.strptime(a, fmt) - datetime.strptime(b, fmt)).total_seconds())
        if a and b
        else -1
    )


def _skew(idx: EvalIndex, p: dict) -> str:
    bad = []
    for pl in p["paired_lines"]:
        auth, real = (
            _t(idx, p["source_key"], pl["seq"]),
            _t(idx, pl["real_source_key"], pl["real_record_ids"][0]),
        )
        delta = int((auth - real.replace(microsecond=0)).total_seconds()) if auth and real else None
        if delta != pl["perturbed_delta_seconds"]:
            bad.append(f"seq {pl['seq']} delta {delta}")
    for pair in p.get("cross_host_pairs", []):
        s, d = (
            _t(idx, pair[k]["source_key"], pair[k]["seq"]) for k in ("source_side", "dest_side")
        )
        if not (s and d) or int((d - s).total_seconds()) != pair["perturbed_delta_seconds"]:
            bad.append(f"{pair['conn_id']} delta")
    return "ok" if not bad else "skew changed: " + "; ".join(bad)


def run_coverage(
    paths: Paths, case_id: str
) -> tuple[CoverageReport, EvalIndex, AnswerKey, Adjudication, Scenario]:
    """Run all coverage checks for a normalized case."""
    scn, variant = load_case_scenario(case_id)
    d = scenario_dir(scn.scenario_id)
    key = load_key(d / f"key_{variant.value}.yaml", scn)
    adj = load_adjudication(d / "adjudication.yaml")
    idx = build_index(paths, case_id)
    rep = CoverageReport(case_id, variant)
    check_key_refs(rep, idx, key, adj)
    check_counts(rep, idx, scn, case_id)
    check_alignment(rep, idx, key, scn)
    check_perturbations(rep, idx, key)
    return rep, idx, key, adj, scn
