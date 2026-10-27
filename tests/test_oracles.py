"""The answer key agrees with the data: oracles find exactly the three planted contradictions."""

from chainofproof.scenarios.companions import parse_auth_log
from chainofproof.schemas.scenario import Variant
from oracles import (
    CHECKS,
    Case,
    all_auth_lines,
    oracle_clock_skew,
    oracle_cross_host_pair_delta,
    oracle_log_gap,
    oracle_timestomp,
    oracle_unmatched_connections,
)


def _case(v3, claim) -> Case:
    pipes = {
        ("pipe_name", r["pipe_name"].lstrip("\\")): v3.aligned("s4_renamed_psexec", r)
        for r in v3.rows("s4_renamed_psexec")
        if r["event_id"] == 18 and "pipe_name" in r
    }
    s5 = {r["record_id"]: v3.aligned("s5_dcsync", r) for r in v3.rows("s5_dcsync")}
    return Case(v3.dirs[Variant.clean], v3.dirs[Variant.perturbed], pipes, s5, claim)


def test_clean_variant_has_no_contradiction(v3):
    d = v3.dirs[Variant.clean]
    assert v3.keys[Variant.clean].contradictions == []
    for h in ("ws_fin_07", "srv_file_02", "dc_01"):
        assert oracle_timestomp(d / f"fs_{h}.csv") == []
        assert oracle_log_gap(d / f"auth_{h}.log", []) == []
    case = _case(v3, v3.keys[Variant.perturbed].contradictions[0])
    deltas = oracle_clock_skew(case.real_times, parse_auth_log(d / "auth_srv_file_02.log"))
    assert deltas == {"SRV-FILE-02": [0, 0, 0]}
    # new Phase 2.2 oracles: every connection has both ends, 0 s apart, nothing unmatched
    assert oracle_cross_host_pair_delta(all_auth_lines(d)) == {"CONN-001": 0, "CONN-002": 0}
    assert oracle_unmatched_connections(all_auth_lines(d)) == []


def test_perturbed_variant_oracles_find_exactly_the_key(v3):
    cons = {c.kind.value: c for c in v3.keys[Variant.perturbed].contradictions}
    assert sorted(cons) == ["clock_skew", "log_gap", "timestomp"]
    d = v3.dirs[Variant.perturbed]
    # P1: the same two files, same deltas, same host; nothing else on any host
    found = oracle_timestomp(d / "fs_srv_file_02.csv")
    want = cons["timestomp"].params["files"]
    assert [(f["record_id"], f["path"]) for f in found] == [
        (w["record_id"], w["path"]) for w in want
    ]
    assert oracle_timestomp(d / "fs_ws_fin_07.csv") == oracle_timestomp(d / "fs_dc_01.csv") == []
    # P2: only SRV-FILE-02 is skewed, by exactly the key's magnitude, for exactly the key's lines
    case = _case(v3, cons["clock_skew"])
    deltas = oracle_clock_skew(case.real_times, parse_auth_log(d / "auth_srv_file_02.log"))
    assert deltas == {"SRV-FILE-02": [int(cons["clock_skew"].magnitude)] * 3}
    assert len(cons["clock_skew"].params["paired_lines"]) == 3
    # P3: exactly one gap, on DC-01, with the key's sequence range and real events inside it
    gaps = oracle_log_gap(d / "auth_dc_01.log", list(case.s5_times.values()))
    p3 = cons["log_gap"].params
    assert [(g["host"], g["first_missing_seq"], g["last_missing_seq"]) for g in gaps] == [
        (p3["host"], p3["first_removed_seq"], p3["last_removed_seq"])
    ]
    assert gaps[0]["real_events_inside"] == len(p3["real_record_ids_inside_window"]) == 3
    for h in ("ws_fin_07", "srv_file_02"):
        assert oracle_log_gap(d / f"auth_{h}.log", list(case.s5_times.values())) == []
    # Phase 2.2: CONN-001 is +420 s apart (and the only such pair); CONN-002 lost its DC-01 end
    pair = cons["clock_skew"].params["cross_host_pairs"]
    assert (
        oracle_cross_host_pair_delta(all_auth_lines(d))
        == {p["conn_id"]: p["perturbed_delta_seconds"] for p in pair}
        == {"CONN-001": int(cons["clock_skew"].magnitude)}
    )
    lost = oracle_unmatched_connections(all_auth_lines(d))
    assert [(u["conn_id"], u["present_side"], u["host"]) for u in lost] == [
        ("CONN-002", "source", "SRV-FILE-02")
    ]
    assert lost[0]["seq"] == p3["unmatched_connections"][0]["present"]["seq"]


def test_every_check_claimed_in_the_key_is_proven(v3):
    claimed = {}
    for c in v3.keys[Variant.perturbed].contradictions:
        assert c.checks, f"{c.id}: no machine-readable checks"
        for name in c.checks:
            assert name in CHECKS, f"{c.id}: unknown check {name}"
            assert CHECKS[name](_case(v3, c)), f"{c.id}: check {name} does not hold"
            claimed.setdefault(c.kind.value, []).append(name)
    # P1 claims ONLY the single-source check: no real event records those files' creation
    assert claimed["timestomp"] == ["si_fn_mismatch"]
    assert claimed["clock_skew"] == ["paired_line_time_delta", "cross_host_pair_delta"]
    assert claimed["log_gap"] == [
        "seq_discontinuity",
        "real_events_inside_gap",
        "unmatched_connection",
    ]


def test_p1_has_no_cross_source_creation_event(v3):
    """Honesty check behind P1's detectable_by: no real Sysmon 11 / 7045 / 4697 in S3 or S4."""
    for sk in ("s3_psexec_smb", "s4_renamed_psexec"):
        counts = v3.insp["sources"][sk]["event_id_counts"]
        assert not {"11", "7045", "4697"} & set(counts)


def test_p2_pairing_is_exact(v3):
    """Each paired line names a pipe that a real S4 Sysmon 18 event shows, by record id."""
    p2 = next(c for c in v3.keys[Variant.perturbed].contradictions if c.kind.value == "clock_skew")
    rows = {r["record_id"]: r for r in v3.rows("s4_renamed_psexec")}
    lines = {
        int(r["seq"]): r
        for r in parse_auth_log(v3.dirs[Variant.perturbed] / "auth_srv_file_02.log")
    }
    for pl in p2.params["paired_lines"]:
        assert pl["pairing_field"] == "pipe_name" and pl["real_source_key"] == "s4_renamed_psexec"
        assert pl["clean_delta_seconds"] == 0 and pl["perturbed_delta_seconds"] == 420
        assert lines[pl["seq"]]["pair"] == f"pipe_name:{pl['pairing_value']}"
        for rid in pl["real_record_ids"]:
            assert rows[rid]["event_id"] == 18
            assert rows[rid]["pipe_name"].lstrip("\\") == pl["pairing_value"]
