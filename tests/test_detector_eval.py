"""Detector evaluation: matching rules and the end-to-end fixture (synthetic v4 sources)."""

import pytest

from chainofproof.eval.detector_eval import index_resolvers, match_hits
from chainofproof.eval.gt_link import build_index
from chainofproof.schemas.scenario import Variant
from chainofproof.tools.detectors import DETECTORS
from chainofproof.tools.detectors.base import Hit, make_hit
from chainofproof.tools.detectors.runner import get_params
from chainofproof.tools.loader import load_case_events
from evfactory import ev

CLEAN, PERT = "credtheft_lateral_v4_clean", "credtheft_lateral_v4_perturbed"


def fake_hit(detector, kind, uids=("EVT-000000000001",), **measures):
    return make_hit(detector, kind, "medium", ["H"], ["L"], uids, measures, "x", ["y"])


@pytest.fixture
def key(v4):
    return v4.keys[Variant.perturbed]


def run_match(key, hits, resolve=None, label_of=None):
    return match_hits(key, hits, resolve or (lambda s, r: [f"EVT-{s}:{r}"]),
                      label_of or (lambda s: f"L-{s}"), Variant.perturbed, "t")  # fmt: skip


def files(key):
    return key.contradictions[0].params["files"]


def test_timestomp_needs_the_exact_file_set(key):
    resolve = lambda s, r: [f"{s}:{r}"]  # noqa: E731
    both = [fake_hit("timestomp", "si_fn_mismatch", [f"{f['source_key']}:{f['record_id']}"],
                     max_delta_seconds=f["delta_seconds"]) for f in files(key)]  # fmt: skip
    assert run_match(key, both, resolve).cons[0].found
    assert not run_match(key, both[:1], resolve).cons[0].found  # one file missing
    extra = both + [fake_hit("timestomp", "si_fn_mismatch", ["other:1"], max_delta_seconds=9999)]
    r = run_match(key, extra, resolve)
    assert not r.cons[0].found and len(r.unexpected) == 1  # an extra file breaks exactness


def test_skew_requires_label_host_and_one_second_tolerance(key):
    p = key.contradictions[1].params
    label = f"L-{p['source_key']}"

    def hit(off, lab=label, host=p["host"]):
        return fake_hit("clock_skew", "source_offset", label=lab, hosts=[host], offset_seconds=off)

    found = lambda h: run_match(key, [h]).cons[1].found  # noqa: E731
    assert found(hit(420.0)) and found(hit(419.2)) and found(hit(420.9))
    assert not found(hit(422.0)) and not found(hit(418.5))
    assert not found(hit(420.0, lab="L-other")) and not found(hit(420.0, host="DC-01"))


def test_gap_range_must_match_exactly(key):
    p = key.contradictions[2].params

    def hit(a, b, host=p["host"]):
        return fake_hit("log_gap", "sequence_gap", label=f"L-{p['source_key']}", host=host,
                        first_missing_seq=a, last_missing_seq=b)  # fmt: skip

    a, b = p["first_removed_seq"], p["last_removed_seq"]
    found = lambda h: run_match(key, [h]).cons[2].found  # noqa: E731
    assert found(hit(a, b))
    assert (
        not found(hit(a, b - 1)) and not found(hit(a + 1, b)) and not found(hit(a, b, "WS-FIN-07"))
    )


def test_other_hits_are_unexpected_and_precision_counts(key):
    conn = key.contradictions[2].params["unmatched_connections"][0]["conn_id"]
    hits = [
        fake_hit("unmatched_connection", "missing_counterpart", conn_id=conn),
        fake_hit("unmatched_connection", "missing_counterpart", conn_id="CONN-999"),
        fake_hit("clock_skew", "pair_time_offset", key="k", delta_seconds=5),
    ]
    r = run_match(key, hits)
    assert [h.measures.get("conn_id", h.kind) for h in r.unexpected] == [
        "CONN-999",
        "pair_time_offset",
    ]
    assert r.precision()["unmatched_connection"] == (1, 2)
    assert dict((lid, flagged) for lid, cid, flagged in r.link_flags)["GT-LNK-004"] is True


def test_collateral_hits_are_explained_not_unexpected_and_left_out_of_precision(key):
    gap = key.contradictions[2]
    col = gap.expected_collateral_conn_ids
    link_b = gap.params["unmatched_connections"][0]["conn_id"]
    assert len(col) >= 1
    hits = [fake_hit("unmatched_connection", "missing_counterpart", conn_id=c) for c in col]
    hits += [
        fake_hit("unmatched_connection", "missing_counterpart", conn_id=link_b),
        fake_hit("unmatched_connection", "missing_counterpart", conn_id="CONN-9999"),
    ]
    r = run_match(key, hits)
    assert len(r.explained) == len(col) and r.collateral_missed() == []
    assert [h.measures["conn_id"] for h in r.unexpected] == ["CONN-9999"]
    assert r.precision()["unmatched_connection"] == (
        1,
        2,
    )  # link B matched; bogus id; no collateral
    assert "explained collateral" in r.summary_text()
    short = run_match(key, hits[1:])  # one collateral id not flagged by any detector
    assert short.collateral_missed() == col[:1]


# ---- end to end on the synthetic v4 sources ---------------------------------------------------
def with_real_side(paths, case, clean_events, real_names):
    """Synthetic events of ``case`` plus fabricated EVTX pipe events copied from the CLEAN data.

    The fabricated events stand in for the real S4 pipe events (the key's paired pipe names, clean
    times); benign pipe lines have no real counterpart and get none.
    """
    events, _ = load_case_events(paths, case)
    pipes = [e for e in clean_events if e.source_kind == "auth_log" and e.pipe_name in real_names]
    fake = [
        ev("EVTX-ffffff", e.timestamp, e.host, "pipe_connected", pipe_name="\\" + e.pipe_name,
            record_id=i, event_id=18)
        for i, e in enumerate(pipes)
    ]  # fmt: skip
    return [*events, *fake]


def detect_all(events):
    return [h for n, (fn, _) in DETECTORS.items() for h in fn(events, get_params(n))]


def test_end_to_end_perturbed_finds_exactly_the_planted_three_and_clean_none(synth_norm, v4):
    paths, _ = synth_norm
    clean_events, _ = load_case_events(paths, CLEAN)
    skew = next(
        c for c in v4.keys[Variant.perturbed].contradictions if c.kind.value == "clock_skew"
    )
    names = {p["pairing_value"] for p in skew.params["paired_lines"]}
    results = {}
    for variant, case in ((Variant.clean, CLEAN), (Variant.perturbed, PERT)):
        hits = detect_all(with_real_side(paths, case, clean_events, names))
        resolve, label_of = index_resolvers(build_index(paths, case))
        results[variant] = match_hits(v4.keys[variant], hits, resolve, label_of, variant, case)
    clean, pert = results[Variant.clean], results[Variant.perturbed]
    assert clean.hits == [] and clean.unexpected == []  # no log_clear in the synthetic fixture
    assert [c.found for c in pert.cons] == [True, True, True]
    assert pert.unexpected == []
    gap = next(c for c in v4.keys[Variant.perturbed].contradictions if c.kind.value == "log_gap")
    assert len(pert.explained) == len(gap.expected_collateral_conn_ids) > 0
    assert pert.collateral_missed() == []
    assert isinstance(pert.hits[0], Hit)
    assert dict((lid, f) for lid, _, f in pert.link_flags) == {
        "GT-LNK-002": False,
        "GT-LNK-004": True,
    }
    assert all(not f for _, _, f in clean.link_flags)
