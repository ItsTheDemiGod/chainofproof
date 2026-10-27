"""The five detectors on small hand-built event lists (no database)."""

import pytest

from chainofproof.config import (
    ClockSkewParams,
    LogClearParams,
    LogGapParams,
    TimestompParams,
    UnmatchedConnectionParams,
    load_settings,
)
from chainofproof.tools.detectors import DETECTORS
from chainofproof.tools.detectors.clock_skew import detect_clock_skew
from chainofproof.tools.detectors.log_clear import detect_log_clear
from chainofproof.tools.detectors.log_gap import detect_log_gap
from chainofproof.tools.detectors.timestomp import detect_timestomp
from chainofproof.tools.detectors.unmatched_conn import detect_unmatched_connection
from evfactory import auth, ev, fs

SI, FN = "2021-06-15T12:00:00Z", "2024-03-12T09:00:00Z"


def t(sec, minute=0):
    return f"2024-03-12T09:{minute:02d}:{sec:02d}.000000Z"


# ---- config ----------------------------------------------------------------------------------
def test_param_defaults_equal_settings_yaml():
    d = load_settings().detectors
    assert d.timestomp == TimestompParams() and d.clock_skew == ClockSkewParams()
    assert d.log_gap == LogGapParams() and d.log_clear == LogClearParams()
    assert d.unmatched_connection == UnmatchedConnectionParams()
    assert (d.timestomp.min_delta_seconds, d.clock_skew.min_abs_delta_seconds) == (3600, 2.0)


@pytest.mark.parametrize("name", sorted(DETECTORS))
def test_empty_input_gives_no_hits(name):
    fn, model = DETECTORS[name]
    assert fn([], model()) == []


# ---- timestomp -----------------------------------------------------------------------------
def test_timestomp_positive_and_explanation():
    (h,) = detect_timestomp([fs(7, SI, FN, "C:\\Windows\\PsExec.exe")], TimestompParams())
    assert (h.kind, h.severity, h.measures["file"], h.measures["record_id"]) == (
        "si_fn_mismatch", "high", "PsExec.exe", 7)  # fmt: skip
    assert h.measures["direction"] == "si_earlier_than_fn" and h.measures["max_delta_seconds"] > 8e7
    assert len(h.event_uids) == 1 and len(h.hit_key) == 64
    text = " ".join([h.explanation, *h.limitations]).lower()
    assert "legitimate file moves" in h.limitations[0]
    assert "other source" not in text and "corroborat" not in text and "cross-source" not in text


def test_timestomp_negative_boundary():
    def at(delta):
        s = "2024-03-12T08:00:00Z"
        fn = f"2024-03-12T{8 + delta // 3600:02d}:{delta % 3600 // 60:02d}:00Z"
        return detect_timestomp([fs(1, s, fn)], TimestompParams())

    assert at(0) == [] and at(3540) == []  # 59 minutes: below the 3600 s threshold
    assert len(at(3600)) == 1  # exactly the threshold: reported (>=)
    p = TimestompParams(min_delta_seconds=7200)
    assert detect_timestomp([fs(1, "2024-03-12T08:00:00Z", "2024-03-12T09:00:00Z")], p) == []


def test_timestomp_direction_and_tolerates_bad_rows():
    later = detect_timestomp([fs(1, FN, SI)], TimestompParams())[0]
    assert later.measures["direction"] == "si_later_than_fn" and later.severity == "medium"
    bad = fs(2, SI, FN)
    bad.fields["si_created"] = "garbage"
    missing = fs(3, SI, FN)
    del missing.fields["fn_changed"]
    assert detect_timestomp([bad, missing, ev(etype="process_create")], TimestompParams()) == []


def test_timestomp_hit_keys_are_deterministic():
    rows = [fs(1, SI, FN), fs(2, SI, FN, "C:\\x\\y.exe")]
    a = detect_timestomp(rows, TimestompParams())
    b = detect_timestomp(list(reversed(rows)), TimestompParams())
    assert [h.hit_key for h in a] == [h.hit_key for h in b]


# ---- log_gap -------------------------------------------------------------------------------
def lines(seqs, label="AUTH-aaaaaa", host="H1", start=0):
    """Auth lines 10 s apart (seq i at :00, :10, :20 ...)."""
    return [
        auth(s, t(i * 10 % 60, start + i * 10 // 60), host, label=label) for i, s in enumerate(seqs)
    ]


def test_log_gap_positive_with_other_source_events_inside():
    log = lines([1, 2, 3, 7, 8])
    other = ev("EVTX-cccccc", t(25), "H1", "process_create", record_id=1)
    elsewhere = ev("EVTX-cccccc", t(25), "H2", "process_create", record_id=2)
    (h,) = detect_log_gap([*log, other, elsewhere], LogGapParams())
    m = h.measures
    assert (m["first_missing_seq"], m["last_missing_seq"], m["missing_count"]) == (4, 6, 3)
    assert h.severity == "high" and m["other_source_event_total"] == 1
    assert m["other_source_events_inside"] == {"EVTX-cccccc/process_create": 1}
    assert other.event_uid in h.event_uids and elsewhere.event_uid not in h.event_uids


def test_log_gap_medium_without_other_events_and_multiple_gaps():
    hits = detect_log_gap(lines([1, 3, 4, 9]), LogGapParams())
    assert [(h.measures["first_missing_seq"], h.severity) for h in hits] == [
        (2, "medium"),
        (5, "medium"),
    ]


def test_log_gap_edges_and_complete_logs_do_not_hit():
    assert detect_log_gap(lines([1, 2, 3, 4]), LogGapParams()) == []
    assert detect_log_gap(lines([5, 6, 7]), LogGapParams()) == []  # start gap is invisible
    assert detect_log_gap([auth(1, t(0))], LogGapParams()) == []


def test_log_gap_ignores_file_timelines_and_tolerates_missing_record_ids():
    rows = [fs(1, FN, FN), fs(9, FN, FN, "C:\\q.exe")]
    assert detect_log_gap(rows, LogGapParams()) == []
    assert detect_log_gap([ev("AUTH-aaaaaa", etype="auth_logon")], LogGapParams()) == []


def test_log_gap_limits_listed_events():
    log = lines([1, 5])
    crowd = [
        ev("EVTX-cccccc", t(1 + i % 3), "H1", "process_create", record_id=i) for i in range(30)
    ]
    assert all(c.timestamp > log[0].timestamp for c in crowd)
    (h,) = detect_log_gap([*log, *crowd], LogGapParams(max_other_events_listed=4))
    assert h.measures["other_source_event_total"] == 30 and len(h.event_uids) == 6


# ---- log_clear -----------------------------------------------------------------------------
def test_log_clear_with_following_context_and_window():
    clear = ev("EVTX-cccccc", t(0), "H1", "audit_log_cleared", event_id=1102, channel="Security")
    near = ev("EVTX-cccccc", t(30), "H1", "logon", event_id=4624)
    far = ev("EVTX-cccccc", t(0, 5), "H1", "logon", event_id=4624)
    before = ev("EVTX-cccccc", "2024-03-12T08:59:00.000000Z", "H1", "logon")
    other_host = ev("EVTX-cccccc", t(10), "H2", "logon")
    (h,) = detect_log_clear([clear, near, far, before, other_host], LogClearParams())
    assert h.measures["context_event_count"] == 1 and near.event_uid in h.event_uids
    assert far.event_uid not in h.event_uids and "routine administration" in h.limitations[0]
    (h2,) = detect_log_clear([clear, far], LogClearParams(window_seconds=400))
    assert h2.measures["context_event_count"] == 1
    assert detect_log_clear([near], LogClearParams()) == []


# ---- unmatched_connection ----------------------------------------------------------------------
def conn_pair(cid="CONN-001", t1=None, t2=None):
    t1, t2 = t1 or t(0), t2 or t(0)
    return [
        auth(1, t1, "A", "CONN_OUT", label="AUTH-aaaaaa", conn_id=cid, dst_host="B"),
        auth(1, t2, "B", "CONN_ACCEPTED", label="AUTH-bbbbbb", conn_id=cid, dst_host="B"),
    ]


def test_unmatched_both_ends_present_no_hit_and_one_end_hit():
    assert detect_unmatched_connection(conn_pair(), UnmatchedConnectionParams()) == []
    (h,) = detect_unmatched_connection(conn_pair()[:1], UnmatchedConnectionParams())
    m = h.measures
    assert (m["conn_id"], m["present_end"], m["expected_missing_host"]) == (
        "CONN-001",
        "source",
        "B",
    )
    assert h.severity == "medium" and m["possible_explanation_hit_key"] is None
    (h2,) = detect_unmatched_connection(conn_pair()[1:], UnmatchedConnectionParams())
    assert (
        h2.measures["present_end"] == "destination" and h2.measures["expected_missing_host"] is None
    )
    logon = auth(2, t(0), "B", "LOGON_SUCCESS", label="AUTH-bbbbbb", conn_id="C9", dst_host="B")
    assert len(detect_unmatched_connection([logon], UnmatchedConnectionParams())) == 1


def test_unmatched_annotated_with_gap_explanation():
    b_log = [auth(s, t(0, m), "B", label="AUTH-bbbbbb") for s, m in ((1, 0), (2, 1), (9, 8))]
    src = auth(1, t(0, 4), "A", "CONN_OUT", label="AUTH-aaaaaa", conn_id="CONN-002", dst_host="B")
    gap = detect_log_gap(b_log, LogGapParams())[0]
    (h,) = detect_unmatched_connection([*b_log, src], UnmatchedConnectionParams())
    assert h.measures["possible_explanation_hit_key"] == gap.hit_key and h.severity == "low"
    assert "sequence gap" in h.explanation
    outside = auth(
        1, t(0, 30), "A", "CONN_OUT", label="AUTH-aaaaaa", conn_id="CONN-003", dst_host="B"
    )
    (h3,) = detect_unmatched_connection([*b_log, outside], UnmatchedConnectionParams())
    assert h3.measures["possible_explanation_hit_key"] is None


# ---- clock_skew ----------------------------------------------------------------------------
def pipe(label, ts, name, host="H1", rid=1):
    return ev(label, ts, host, "pipe_created", pipe_name=name, record_id=rid)


def skew_events(offset=420, n=3):
    out = []
    for i in range(n):
        out.append(pipe("EVTX-cccccc", t(10 + i, 10), f"\\svc-{i}", rid=i))
        out.append(
            pipe("AUTH-aaaaaa", t(10 + i + offset % 60, 10 + offset // 60), f"svc-{i}", rid=i)
        )
    return out


def test_skew_pair_discovery_by_pipe_and_conn_id_and_backslash_normalization():
    hits = detect_clock_skew(skew_events(), ClockSkewParams())
    (h,) = [x for x in hits if x.kind == "source_offset"]
    m = h.measures
    assert (m["label"], m["offset_seconds"], m["direction"], m["pair_count"]) == (
        "AUTH-aaaaaa", 420.0, "late", 3)  # fmt: skip
    assert m["partner_labels"] == ["EVTX-cccccc"] and len(m["shared_keys"]) == 3
    assert h.severity == "high" and "cannot tell which" in h.limitations[0].lower()
    assert all(x.kind != "pair_time_offset" for x in hits)  # mirror and pairs are explained


def test_skew_requires_two_independent_pairs_single_pair_is_low_pair_hit():
    hits = detect_clock_skew(skew_events(n=1), ClockSkewParams())
    assert [(h.kind, h.severity) for h in hits] == [("pair_time_offset", "low")]
    assert (
        hits[0].measures["delta_seconds"] == 420
        and hits[0].measures["later_label"] == "AUTH-aaaaaa"
    )


def test_skew_two_keys_one_partner_ok_and_conn_id_pair():
    evs = skew_events(n=2)
    (h,) = [x for x in detect_clock_skew(evs, ClockSkewParams()) if x.kind == "source_offset"]
    assert h.measures["pair_count"] == 2
    conn = conn_pair(t1=t(0), t2=t(0, 7))  # B later than A by 420 s through a conn_id
    hits = detect_clock_skew(conn, ClockSkewParams())
    assert [x.kind for x in hits] == ["pair_time_offset"] and hits[0].measures[
        "key_kind"
    ] == "conn_id"


def test_skew_boundaries_and_symmetric_direction():
    below = detect_clock_skew(skew_events(offset=1), ClockSkewParams())
    assert below == []  # |delta| 1 s < 2 s
    at = detect_clock_skew(skew_events(offset=2), ClockSkewParams())
    assert any(h.kind == "source_offset" for h in at)
    early = detect_clock_skew(skew_events(offset=-420), ClockSkewParams())
    (h,) = [x for x in early if x.kind == "source_offset"]
    assert h.measures["direction"] == "early" and h.measures["offset_seconds"] == -420.0


def test_skew_pairs_disagreeing_by_more_than_agreement_are_not_aggregated():
    evs = [
        pipe("EVTX-cccccc", t(0), "p1"), pipe("AUTH-aaaaaa", t(30), "p1"),
        pipe("EVTX-cccccc", t(0), "p2"), pipe("AUTH-aaaaaa", t(0, 2), "p2"),
    ]  # fmt: skip
    hits = detect_clock_skew(evs, ClockSkewParams())
    assert {h.kind for h in hits} == {"pair_time_offset"} and len(hits) == 2


def test_skew_two_partners_pick_the_common_party():
    evs = []
    for i, partner in enumerate(("EVTX-cccccc", "AUTH-dddddd")):
        evs += [pipe(partner, t(5), f"k{i}a"), pipe("AUTH-aaaaaa", t(5, 5), f"k{i}a")]
    hits = [h for h in detect_clock_skew(evs, ClockSkewParams()) if h.kind == "source_offset"]
    assert [h.measures["label"] for h in hits] == ["AUTH-aaaaaa"]
    assert sorted(hits[0].measures["partner_labels"]) == ["AUTH-dddddd", "EVTX-cccccc"]


def test_skew_hit_keys_deterministic_and_input_order_independent():
    evs = skew_events()
    a = [h.hit_key for h in detect_clock_skew(evs, ClockSkewParams())]
    b = [h.hit_key for h in detect_clock_skew(list(reversed(evs)), ClockSkewParams())]
    assert a == b and a == [h.hit_key for h in detect_clock_skew(evs, ClockSkewParams())]
