"""EVALUATION ONLY: score detector hits against the answer key.

Matching rules (written before the first run):
* timestomp (si_fn_mismatch): found when the set of event_uids of all such hits equals EXACTLY the
  set of the key's files.
* clock skew (source_offset): found when a hit names the key's evidence label and host and its
  offset is within +/-1 s of the key magnitude.
* log gap (sequence_gap): found when a hit names the key's label and host and its missing seq range
  equals the key's range EXACTLY.
* audit_log_cleared hits match the key's T1070.001 action (an "action indicator", not a
  contradiction). missing_counterpart hits match the key's unmatched connection ids (the GT-LNK-004
  connection).
* missing_counterpart hits on conn_ids in the log gap's expected_collateral_conn_ids are EXPLAINED
  COLLATERAL: benign connections whose DC-01 end the gap removed. They are reported separately,
  are neither unexpected hits nor contradictions, and are left out of the precision denominator.
* Every other hit is UNEXPECTED.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field

from chainofproof.config import Paths
from chainofproof.eval.gt_link import EvalIndex, build_index
from chainofproof.scenarios.source_map import case_key_path, load_case_scenario
from chainofproof.schemas.scenario import AnswerKey, Variant, load_key
from chainofproof.tools.detectors import DETECTORS
from chainofproof.tools.detectors.base import Hit
from chainofproof.tools.detectors.runner import run_detector

Resolve = Callable[[str, int], list[str]]
LabelOf = Callable[[str], str | None]


@dataclass
class ConResult:
    """Outcome for one planted contradiction."""

    con_id: str
    kind: str
    found: bool
    hit_ids: list[str]
    measured: str
    key_value: str


@dataclass
class CaseEval:
    """Scoring of all detector hits of one case."""

    case_id: str
    variant: Variant
    hits: list[Hit]
    cons: list[ConResult] = field(default_factory=list)
    indicators: list[tuple[str, str]] = field(default_factory=list)  # (GT-ACT id, hit id)
    matched: set[int] = field(default_factory=set)  # indexes into hits
    explained: set[int] = field(default_factory=set)  # hits on expected collateral conn_ids
    collateral_ids: list[str] = field(default_factory=list)  # the key's expected collateral
    unexpected: list[Hit] = field(default_factory=list)
    link_flags: list[tuple[str, str, bool]] = field(default_factory=list)  # (GT-LNK, conn, flagged)

    def precision(self) -> dict[str, tuple[int, int]]:
        """Per detector: (matched hits, total hits); explained collateral is not counted."""
        out: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for i, h in enumerate(self.hits):
            if i in self.explained:
                continue
            out[h.detector][1] += 1
            out[h.detector][0] += i in self.matched
        return {k: (v[0], v[1]) for k, v in sorted(out.items())}

    def collateral_missed(self) -> list[str]:
        """Expected collateral conn_ids that no unmatched_connection hit flagged."""
        seen = {self.hits[i].measures.get("conn_id") for i in self.explained}
        return [c for c in self.collateral_ids if c not in seen]

    def summary_text(self) -> str:
        """Plain-text report (ids, kinds, numbers only)."""
        found = sum(c.found for c in self.cons)
        lines = [f"{self.case_id}: recall {found}/{len(self.cons)} contradictions, "
                 f"{len(self.hits)} hits, {len(self.unexpected)} unexpected"]  # fmt: skip
        for c in self.cons:
            lines.append(f"  {c.con_id} {c.kind}: {'FOUND' if c.found else 'missed'} "
                         f"{c.hit_ids} measured {c.measured} (key {c.key_value})")  # fmt: skip
        lines += [f"  action indicator {a} <- {h}" for a, h in self.indicators]
        lines += [f"  precision {d}: {m}/{t}" for d, (m, t) in self.precision().items()]
        if self.collateral_ids:
            lines.append(f"  explained collateral: {len(self.explained)} of "
                         f"{len(self.collateral_ids)} expected conn_ids flagged "
                         f"(missed: {self.collateral_missed() or 'none'})")  # fmt: skip
        for lid, cid, flagged in self.link_flags:
            lines.append(f"  {lid} {cid}: unmatched_connection flagged={flagged}")
        for h in self.unexpected:
            lines.append(f"  UNEXPECTED {h.hit_id} {h.detector}/{h.kind} {h.severity} "
                         f"hosts={h.hosts} {_brief(h)}")  # fmt: skip
        return "\n".join(lines)


def _brief(h: Hit) -> str:
    m = h.measures
    keys = ("label", "file", "conn_id", "key", "offset_seconds", "missing_count", "delta_seconds")
    return " ".join(f"{k}={m[k]}" for k in keys if k in m)


def match_hits(
    key: AnswerKey, hits: list[Hit], resolve: Resolve, label_of: LabelOf, variant: Variant,
    case_id: str,
) -> CaseEval:  # fmt: skip
    """Score ``hits`` against ``key``. ``resolve``: (source_key, record id) -> event_uids."""
    ev = CaseEval(case_id, variant, hits)
    for c in key.contradictions:
        p = c.params
        if c.kind.value == "timestomp":
            ev.cons.append(_stomp(ev, c, p, resolve))
        elif c.kind.value == "clock_skew":
            ev.cons.append(_skew(ev, c, p, label_of))
        elif c.kind.value == "log_gap":
            ev.cons.append(_gap(ev, c, p, label_of))
    conns = {
        u["conn_id"] for c in key.contradictions for u in c.params.get("unmatched_connections", [])
    }
    ev.collateral_ids = sorted(
        {i for c in key.contradictions for i in c.expected_collateral_conn_ids}
    )
    clear_uids = {
        u
        for a in key.actions
        if a.attack_technique_id == "T1070.001"
        for r in a.supporting_refs
        for u in resolve(r.source_key, r.event_record_id)
    }
    for i, h in enumerate(hits):
        if h.detector == "unmatched_connection" and h.measures.get("conn_id") in conns:
            ev.matched.add(i)
        elif (
            h.detector == "unmatched_connection" and h.measures.get("conn_id") in ev.collateral_ids
        ):
            ev.explained.add(i)
        elif h.kind == "audit_log_cleared" and clear_uids & set(h.event_uids):
            ev.matched.add(i)
            act = next(a.id for a in key.actions if a.attack_technique_id == "T1070.001")
            ev.indicators.append((act, h.hit_id or h.hit_key[:8]))
    ev.unexpected = [h for i, h in enumerate(hits) if i not in ev.matched and i not in ev.explained]
    seen = {h.measures.get("conn_id") for h in hits if h.detector == "unmatched_connection"}
    for ln in key.links:
        for cid in sorted({r.conn_id for r in ln.evidence_refs if r.conn_id}):
            ev.link_flags.append((ln.id, cid, cid in seen))
    return ev


def _hid(h: Hit) -> str:
    return h.hit_id or h.hit_key[:8]


def _stomp(ev: CaseEval, c, p, resolve: Resolve) -> ConResult:
    want = {u for f in p["files"] for u in resolve(f["source_key"], f["record_id"])}
    mine = [(i, h) for i, h in enumerate(ev.hits) if h.kind == "si_fn_mismatch"]
    got = {u for _, h in mine for u in h.event_uids}
    ev.matched.update(i for i, h in mine if set(h.event_uids) <= want)
    deltas = sorted(h.measures["max_delta_seconds"] for _, h in mine)
    key_d = sorted(f["delta_seconds"] for f in p["files"])
    measured = f"{len(mine)} files, max deltas {deltas}"
    key_text = f"{c.magnitude:g} files, deltas {key_d}"
    found = got == want and bool(want)
    return ConResult(c.id, "timestomp", found, [_hid(h) for _, h in mine], measured, key_text)


def _skew(ev: CaseEval, c, p, label_of: LabelOf) -> ConResult:
    label = label_of(p["source_key"])
    cand = [(i, h) for i, h in enumerate(ev.hits) if h.kind == "source_offset"
            and h.measures["label"] == label and p["host"] in h.measures["hosts"]]  # fmt: skip
    good = [(i, h) for i, h in cand if abs(h.measures["offset_seconds"] - c.magnitude) <= 1.0]
    ev.matched.update(i for i, _ in good)
    meas = [h.measures["offset_seconds"] for _, h in cand]
    return ConResult(c.id, "clock_skew", bool(good), [_hid(h) for _, h in good],
                     f"offsets {meas}", f"{c.magnitude:g} s")  # fmt: skip


def _gap(ev: CaseEval, c, p, label_of: LabelOf) -> ConResult:
    label = label_of(p["source_key"])
    cand = [(i, h) for i, h in enumerate(ev.hits) if h.kind == "sequence_gap"
            and h.measures["label"] == label and h.measures["host"] == p["host"]]  # fmt: skip
    rng = (p["first_removed_seq"], p["last_removed_seq"])
    good = [
        (i, h)
        for i, h in cand
        if (h.measures["first_missing_seq"], h.measures["last_missing_seq"]) == rng
    ]
    ev.matched.update(i for i, _ in good)
    got = [(h.measures["first_missing_seq"], h.measures["last_missing_seq"]) for _, h in cand]
    return ConResult(c.id, "log_gap", bool(good), [_hid(h) for _, h in good],
                     f"ranges {got}", f"seq {rng[0]}-{rng[1]}")  # fmt: skip


def index_resolvers(idx: EvalIndex) -> tuple[Resolve, LabelOf]:
    """Resolvers backed by the database eval index."""

    def label_of(source_key: str) -> str | None:
        uids = idx.by_source(source_key)
        return idx.rows[uids[0]]["evidence_label"] if uids else None

    return idx.uids, label_of


def run_all_stored(paths: Paths, case_id: str) -> list[Hit]:
    """Run every detector with default parameters (stored runs); returns hits with HIT ids."""
    return [h for name in DETECTORS for h in run_detector(paths, case_id, name).hits]


def evaluate_case(paths: Paths, case_id: str) -> CaseEval:
    """Run all detectors on a real case and score them against its answer key."""
    scn, variant = load_case_scenario(case_id)
    key = load_key(case_key_path(case_id), scn)
    resolve, label_of = index_resolvers(build_index(paths, case_id))
    return match_hits(key, run_all_stored(paths, case_id), resolve, label_of, variant, case_id)
