"""EVALUATION ONLY, PRELIMINARY: does an agent run touch the planted truth? (mechanics check)

This is NOT the Phase 9 evaluation: no precision/recall, no baseline, no calibration. It answers
"did the cited events map onto the key's supporting references" so a developer can see that the
pipeline works end to end. Never use it to tune prompts or parameters. Agents never import this.
"""

from __future__ import annotations

from collections import Counter
from contextlib import closing
from dataclasses import dataclass, field

from chainofproof.agents import store
from chainofproof.config import Paths
from chainofproof.custody.db import connect
from chainofproof.eval.detector_eval import index_resolvers, match_hits
from chainofproof.eval.gt_link import EvalIndex, build_index, resolve_ref
from chainofproof.scenarios.dataset import scenario_dir
from chainofproof.scenarios.source_map import load_case_scenario
from chainofproof.schemas.adjudication import Verdict, load_adjudication
from chainofproof.schemas.findings import Finding
from chainofproof.schemas.scenario import load_key
from chainofproof.tools.detectors.runner import hit_from_row

COUNTED = ("verified", "downgraded")


@dataclass
class PeekReport:
    """Everything ``agent-peek`` prints."""

    run_id: str
    case_id: str
    by_status: Counter = field(default_factory=Counter)
    codes: Counter = field(default_factory=Counter)
    rows: list[tuple[str, str, bool, str]] = field(default_factory=list)  # (id, kind, hit, note)
    decoy_findings: int = 0
    detectors: Counter = field(default_factory=Counter)


def _cites(findings: list[Finding], uids: set[str]) -> int:
    return sum(bool(set(f.cited_event_uids) & uids) for f in findings if f.status in COUNTED)


def _agent_hits(paths: Paths, scope: str):
    with closing(connect(paths.db_path)) as conn:
        rows = conn.execute(
            "SELECT * FROM detector_hits WHERE origin = 'agent' AND agent_run_id = ? "
            "ORDER BY hit_id", (scope,)).fetchall()  # fmt: skip
    return [hit_from_row(r) for r in rows]


def _contradictions(paths, case, key, idx: EvalIndex, variant, scope, findings, rep) -> None:
    hits = _agent_hits(paths, scope)
    resolve, label_of = index_resolvers(idx)
    ev = match_hits(key, hits, resolve, label_of, variant, case)
    cited = {h for f in findings if f.status in COUNTED for h in f.cited_hit_ids}
    for c in ev.cons:
        ran = c.kind in rep.detectors
        got = bool(set(c.hit_ids) & cited)
        rep.rows.append(
            (
                c.con_id,
                "contradiction",
                got,
                f"detector run: {ran}; matching hit found: {c.found}; cited: {got}",
            )
        )


def peek(paths: Paths, run_id: str) -> PeekReport:
    """Compare one run's findings with the answer key of its case."""
    row = store.get_run(paths, run_id)
    case = row["case_id"]
    scope = store.root_run(paths, run_id)
    findings = store.list_findings(paths, run_id)
    rep = PeekReport(run_id, case)
    rep.by_status.update(f.status for f in findings)
    for f in findings:
        rep.codes.update(f.verification.codes())
    with closing(connect(paths.db_path)) as conn:
        for (name,) in conn.execute(
            "SELECT name FROM agent_calls WHERE run_id = ? AND kind = 'tool' "
            "AND name LIKE 'detect\\_%' ESCAPE '\\'", (run_id,)):  # fmt: skip
            rep.detectors[name.removeprefix("detect_")] += 1
    scn, variant = load_case_scenario(case)
    d = scenario_dir(scn.scenario_id)
    key = load_key(d / f"key_{variant.value}.yaml", scn)
    adj = load_adjudication(d / "adjudication.yaml")
    idx = build_index(paths, case)
    for a in key.actions:
        uids = {u for r in a.supporting_refs for u in resolve_ref(idx, r)}
        n = _cites(findings, uids)
        rep.rows.append((a.id, "action", n > 0, f"{n} finding(s) cite its events"))
    for ln in key.links:
        uids = {u for r in ln.evidence_refs for u in resolve_ref(idx, r, r.conn_id)}
        n = _cites(findings, uids)
        rep.rows.append((ln.id, "link", n > 0, f"{n} finding(s) cite its events"))
    for e in adj.entries:
        if e.verdict == Verdict.true_finding:
            n = _cites(findings, set(idx.uids(e.source_key, e.event_record_id)))
            rep.rows.append((e.id, "adjudicated true_finding", n > 0, f"{n} finding(s)"))
    if key.contradictions:
        _contradictions(paths, case, key, idx, variant, scope, findings, rep)
    decoy = {u for dc in key.decoys for u in idx.by_source(dc.source_key)}
    rep.decoy_findings = sum(bool(set(f.cited_event_uids) & decoy) for f in findings)
    return rep


def render(r: PeekReport) -> str:
    """Plain-text report (ids, counts and flags only)."""
    lines = [f"PRELIMINARY mechanics check for {r.run_id} ({r.case_id}); not the Phase 9 eval",
             f"findings by status: {dict(r.by_status) or 'none'}",
             f"verifier problem codes: {dict(sorted(r.codes.items())) or 'none'}"]  # fmt: skip
    for id_, kind, hit, note in r.rows:
        lines.append(f"  {id_} ({kind}): {'HIT' if hit else 'miss'}  {note}")
    hit_n = sum(h for _, _, h, _ in r.rows)
    lines.append(f"key items touched: {hit_n} of {len(r.rows)}")
    lines.append(f"findings citing events of decoy sources: {r.decoy_findings} (manual review)")
    lines.append(f"detector tools the agent chose to run: {dict(r.detectors) or 'none'}")
    return "\n".join(lines)
