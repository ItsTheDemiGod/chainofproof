"""Deterministic citation verifier (rule A6: plain code, no LLM). Rules V1-V6: docs/verifier.md.

Reads only agent-view data (events of the latest normalization runs of the case, and detector hits
that belong to THIS agent run). Output order is deterministic. Problems are templated strings made
of a code (``V1``..``V6`` + name) and ids / field names; a model-provided name is only echoed after
``safe_name``.
"""

from __future__ import annotations

from contextlib import closing
from datetime import datetime

from chainofproof.agents import entities as ent
from chainofproof.config import Paths
from chainofproof.custody.db import connect, restricted_reads
from chainofproof.schemas.events import NormalizedEvent
from chainofproof.schemas.findings import (
    EVT_RE,
    HIT_RE,
    Check,
    FindingInput,
    VerificationReport,
)
from chainofproof.tools.detectors.base import Hit
from chainofproof.tools.detectors.runner import hit_from_row
from chainofproof.tools.norm_store import LATEST_RUNS
from chainofproof.tools.query import event_from_row


def _marks(n: int) -> str:
    return ",".join("?" * n)


def load_cited(
    paths: Paths, case_id: str, agent_run_id: str, uids: list[str], hit_ids: list[str]
) -> tuple[dict[str, NormalizedEvent], dict[str, Hit], list[str]]:
    """(events by id, hits by id, all hosts of the case). Hits resolve only inside the agent run."""
    with restricted_reads(), closing(connect(paths.db_path)) as conn:
        ev = (
            conn.execute(
                f"SELECT e.* FROM events e WHERE e.norm_run_id IN ({LATEST_RUNS}) "  # noqa: S608
                f"AND e.event_uid IN ({_marks(len(uids))})",
                [case_id, *uids],
            ).fetchall()
            if uids
            else []
        )
        hs = (
            conn.execute(
                "SELECT * FROM detector_hits WHERE case_id = ? AND origin = 'agent' AND "  # noqa: S608
                f"agent_run_id = ? AND hit_id IN ({_marks(len(hit_ids))})",
                [case_id, agent_run_id, *hit_ids],
            ).fetchall()
            if hit_ids
            else []
        )
        hosts = [r[0] for r in conn.execute(
            f"SELECT DISTINCT host FROM events WHERE norm_run_id IN ({LATEST_RUNS}) ORDER BY 1",  # noqa: S608
            [case_id],
        )]  # fmt: skip
    events = {e.event_uid: e for e in map(event_from_row, ev)}
    return events, {h.hit_id: h for h in map(hit_from_row, hs) if h.hit_id}, hosts


class _Acc:
    """Collects checks, problems and unsupported entities of one verification."""

    def __init__(self) -> None:
        self.checks: list[Check] = []
        self.problems: list[str] = []
        self.unsupported: list[str] = []
        self.counts: dict[str, int] = {}

    def check(self, name: str, problems: list[str]) -> bool:
        self.checks.append(
            Check(check=name, passed=not problems, detail=f"{len(problems)} problem(s)")
        )
        self.problems += problems
        return not problems

    def report(self, status: str) -> VerificationReport:
        return VerificationReport(
            status=status,
            checks=self.checks,
            problems=self.problems,
            unsupported_entities=self.unsupported,
            counts=self.counts,
        )  # type: ignore[arg-type]


def _v1(f: FindingInput, events: dict, hits: dict) -> list[str]:
    out = []
    for kind, ids, found, rx in (("event", f.cited_event_uids, events, EVT_RE),
                                 ("hit", f.cited_hit_ids, hits, HIT_RE)):  # fmt: skip
        for i in sorted(set(ids)):
            if not rx.match(i):
                out.append(f"V1 malformed_{kind}_id")
            elif i not in found:
                out.append(f"V1 unknown_{kind} {i}")
    return out


def _v2(f: FindingInput, events: dict, hits: dict) -> list[str]:
    t, n_e, n_h = f.claim_type, len(events), len(hits)
    if t == "contradiction":
        labels = {e.evidence_label for e in events.values()}
        return (
            []
            if n_h >= 1 or (n_e >= 2 and len(labels) >= 2)
            else ["V2 contradiction_needs_hit_or_two_sources"]
        )
    if t == "link":
        if len(set(f.entities.hosts)) < 2:
            return ["V2 link_needs_two_hosts"]
        covered = {e.host for e in events.values()} | {h for x in hits.values() for h in x.hosts}
        return [f"V2 link_host_not_covered {ent.safe_name(h)}"
                for h in sorted(set(f.entities.hosts)) if h not in covered]  # fmt: skip
    return [] if n_e + n_h >= 1 else ["V2 needs_one_citation"]


def _procs(x: NormalizedEvent) -> tuple[str | None, ...]:
    return (x.process_image, x.parent_image, x.target_image, x.service_name)


def _v3(f: FindingInput, events: dict, hits: dict, acc: _Acc) -> list[str]:
    e, evs = f.entities, list(events.values())
    covered = {x.host for x in evs} | {h for x in hits.values() for h in x.hosts}
    pairs = [(x, ent.fields_blob(x)) for x in evs]
    bad: list[tuple[str, str]] = []
    bad += [("host", h) for h in e.hosts if h not in covered]
    for u in e.users:
        nu = ent.norm_user(u)
        if not any((x.user and ent.norm_user(x.user) == nu) or ent.has_token(b, nu)
                   for x, b in pairs):  # fmt: skip
            bad.append(("user", u))
    for p in e.processes:
        np_ = ent.norm_proc(p)
        names = {np_, np_ + ".exe"} if "." not in np_ else {np_}
        by_field = any(v and ent.norm_proc(v) in names for x, _ in pairs for v in _procs(x))
        if not by_field and not any(ent.has_token(b, n) for _, b in pairs for n in names):
            bad.append(("process", p))
    for ip in e.ips:
        s = ip.strip().lower()
        if not any(s in (x.src_ip, x.dst_ip) or ent.has_token(b, s) for x, b in pairs):
            bad.append(("ip", ip))
    acc.counts["entities_checked"] = len(e.hosts) + len(e.users) + len(e.processes) + len(e.ips)
    acc.counts["entities_unsupported"] = len(bad)
    acc.unsupported = [f"{k}:{ent.safe_name(v)}" for k, v in bad]
    return [f"V3 unsupported_entity {u}" for u in acc.unsupported]


def _refs(events: dict, hits: dict) -> list[datetime]:
    ts = [t for x in events.values() if (t := ent.parse_time(x.timestamp))]
    return ts + [t for h in hits.values() for t in ent.hit_times(h)]


def _v4(f: FindingInput, events: dict, hits: dict) -> list[str]:
    out, refs = [], _refs(events, hits)
    win = ent.window(refs)
    for name in ("time_start", "time_end"):
        raw = getattr(f.entities, name)
        if raw is None:
            continue
        t = ent.parse_time(raw)
        if t is None:
            out.append(f"V4 unparsable_time {name}")
        elif win is None:
            out.append(f"V4 no_reference_time {name}")
        elif not win[0] <= t <= win[1]:
            out.append(f"V4 time_outside_window {name}")
    return out


def _v5(f: FindingInput, events: dict, hits: dict, hosts: list[str], acc: _Acc) -> list[str]:
    tok = ent.claim_tokens(f.claim, hosts, f.claim_type == "contradiction")
    evs, hts = list(events.values()), list(hits.values())
    blob = " ".join([*(ent.event_blob(x) for x in evs), *(ent.hit_blob(h) for h in hts)])
    cited_hosts = {x.host for x in evs} | {x.dst_host for x in evs if x.dst_host}
    cited_hosts |= {h for x in hts for h in x.hosts}
    refs, nums = _refs(events, hits), [n for h in hts for n in ent.hit_numbers(h)]
    bad: list[str] = []
    bad += [f"ip {t}" for t in tok["ip"] if not ent.has_token(blob, t)]
    bad += [f"host {t}" for t in tok["host"] if t not in cited_hosts]
    bad += [f"id {t}" for t in tok["evt"] if t not in events]
    bad += [f"id {t}" for t in tok["hit"] if t not in hits]
    bad += [
        f"time {ent.safe_name(t)}"
        for t in [*tok["iso"], *tok["hms"]]
        if not ent.time_supported(t, refs)
    ]
    bad += [f"exe {t}" for t in tok["exe"] if not ent.has_token(blob, t)]
    bad += [
        f"number {ent.safe_name(txt)}" for n, txt in tok["num"] if not ent.number_supported(n, nums)
    ]
    acc.counts["tokens_checked"] = sum(len(v) for v in tok.values())
    acc.counts["tokens_unsupported"] = len(bad)
    return [f"V5 unsupported_token {b}" for b in bad]


def verify_finding(
    paths: Paths, case_id: str, agent_run_id: str, finding: FindingInput
) -> VerificationReport:
    """Verify one finding against the evidence; returns the report (never raises on bad input)."""
    acc = _Acc()
    uids, hit_ids = sorted(set(finding.cited_event_uids)), sorted(set(finding.cited_hit_ids))
    acc.counts.update(cited_events=len(uids), cited_hits=len(hit_ids))
    if not uids and not hit_ids:
        acc.check("V6_has_citation", ["V6 no_citation"])
        return acc.report("rejected")
    acc.check("V6_has_citation", [])
    good_u = [u for u in uids if EVT_RE.match(u)]
    good_h = [h for h in hit_ids if HIT_RE.match(h)]
    events, hits, hosts = load_cited(paths, case_id, agent_run_id, good_u, good_h)
    if not acc.check("V1_citations_exist", _v1(finding, events, hits)):
        return acc.report("rejected")
    if not acc.check("V2_min_support", _v2(finding, events, hits)):
        return acc.report("rejected")
    ok3 = acc.check("V3_entity_grounding", _v3(finding, events, hits, acc))
    ok4 = acc.check("V4_time_grounding", _v4(finding, events, hits))
    ok5 = acc.check("V5_claim_scan", _v5(finding, events, hits, hosts, acc))
    return acc.report("verified" if ok3 and ok4 and ok5 else "downgraded")
