"""clock_skew pairing guard for repeated pipe names (Phase 4.1): same host, 900 s, one-to-one.

Ordinary pipe names (spoolss, srvsvc...) repeat all day on every host in realistic benign data, so
pairing by pipe name alone would manufacture clock disagreements. conn_id pairing is unchanged.
"""

from chainofproof.config import ClockSkewParams, load_settings
from chainofproof.tools.detectors.clock_skew import detect_clock_skew, discover_pairs
from evfactory import auth, ev


def t(sec, minute=0):
    return f"2024-03-12T09:{minute:02d}:{sec:02d}.000000Z"


def pipe(label, ts, name, host="H1", rid=1):
    return ev(label, ts, host, "pipe_created", pipe_name=name, record_id=rid)


def conn_pair(t1, t2, cid="CONN-0001"):
    return [
        auth(1, t1, "A", "CONN_OUT", label="AUTH-aaaaaa", conn_id=cid, dst_host="B"),
        auth(1, t2, "B", "CONN_ACCEPTED", label="AUTH-bbbbbb", conn_id=cid, dst_host="B"),
    ]


def test_pair_window_default_is_900_seconds_in_settings():
    assert (
        ClockSkewParams().pair_window_seconds
        == load_settings().detectors.clock_skew.pair_window_seconds
        == 900
    )


def test_benign_repeated_pipe_names_on_different_hosts_produce_no_pairs():
    evs = []  # the same ordinary pipe name, within minutes, in two sources on DIFFERENT hosts
    for i, host in enumerate(("H1", "H2", "H3")):
        evs += [pipe("AUTH-aaaaaa", t(i, 3 * i), "spoolss", host=host, rid=i)]
        evs += [pipe("AUTH-bbbbbb", t(i, 3 * ((i + 1) % 3) + 1), "spoolss", host=host, rid=9 - i)]
    assert all(p.host_a == p.host_b for p in discover_pairs(evs, ClockSkewParams()))
    cross = [
        pipe("EVTX-cccccc", t(0), "\\spoolss", host="H1"),
        pipe("AUTH-aaaaaa", t(5), "spoolss", host="H2"),
    ]
    assert discover_pairs(cross, ClockSkewParams()) == []
    assert detect_clock_skew(cross, ClockSkewParams()) == []


def test_pipe_pair_inside_the_window_pairs_and_outside_does_not():
    def pairs(gap_seconds: int):
        late = t(gap_seconds % 60, gap_seconds // 60)
        evs = [pipe("EVTX-cccccc", t(0), "\\p"), pipe("AUTH-aaaaaa", late, "p")]
        return discover_pairs(evs, ClockSkewParams())

    assert len(pairs(420)) == 1 and abs(pairs(420)[0].delta) == 420
    assert len(pairs(900)) == 1  # the window is inclusive
    assert pairs(901) == []


def test_pipe_pairs_are_one_to_one_nearest_time():
    evs = [
        pipe("EVTX-cccccc", t(0), "\\p", rid=1), pipe("EVTX-cccccc", t(40), "\\p", rid=2),
        pipe("AUTH-aaaaaa", t(0, 7), "p", rid=1), pipe("AUTH-aaaaaa", t(20, 8), "p", rid=2),
    ]  # fmt: skip
    pairs = discover_pairs(evs, ClockSkewParams())
    used = [u for p in pairs for u in (p.uid_a, p.uid_b)]
    assert len(pairs) == 2 and len(set(used)) == 4  # nobody is used twice
    assert sorted(abs(p.delta) for p in pairs) == [380, 500]  # closest first, then what is left


def test_conn_id_pairs_keep_their_old_rules_no_window_no_host_restriction():
    far = detect_clock_skew(conn_pair(t(0), t(0, 40)), ClockSkewParams())  # 2400 s apart
    assert [(h.kind, h.measures["delta_seconds"]) for h in far] == [("pair_time_offset", 2400)]


def test_guard_does_not_change_the_other_thresholds():
    p = ClockSkewParams()
    assert (p.min_abs_delta_seconds, p.min_independent_pairs, p.agreement_seconds) == (2.0, 2, 1.0)
