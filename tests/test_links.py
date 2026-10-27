"""Phase 2.2: cross-host synthetic links, link ground truth, and the checks the key claims.

Every test runs on the small fixture scenario AND on the committed credtheft_lateral_v4 files
(generated into a temp dir; no EVTX dataset needed).
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path

import pytest
from pydantic import ValidationError

from chainofproof.scenarios.companions import (
    CompanionParseError,
    parse_auth_log,
    parse_auth_text,
    parse_ts,
    row_marker,
)
from chainofproof.scenarios.generator import generate_variant
from chainofproof.scenarios.inventory import Inventory
from chainofproof.scenarios.keylinks import check_link_refs
from chainofproof.scenarios.keys import build_key
from chainofproof.schemas.scenario import (
    AnswerKey,
    GroundTruthLink,
    LinkBasis,
    LinkKind,
    LinkRef,
    Scenario,
    Variant,
)
from oracles import (
    CHECKS,
    Case,
    all_auth_lines,
    oracle_cross_host_pair_delta,
    oracle_unmatched_connections,
)
from scenario_fixture import build_fixture


@dataclass
class World:
    """A scenario with both generated variants and their keys."""

    scn: Scenario
    inv: Inventory
    dirs: dict[Variant, Path]
    keys: dict[Variant, AnswerKey]


@pytest.fixture(scope="module", params=["fixture", "v4"])
def world(request, tmp_path_factory, v4) -> World:
    if request.param == "v4":
        return World(v4.scn, v4.inv, v4.dirs, v4.keys)
    root = tmp_path_factory.mktemp("links")
    scn, inv, _, _ = build_fixture(root)
    dirs, keys = {}, {}
    for v in Variant:
        dirs[v] = root / "gen" / v.value
        keys[v] = build_key(scn, inv, v, generate_variant(scn, inv, v, dirs[v]))
    return World(scn, inv, dirs, keys)


def _by_conn(world: World, variant: Variant) -> dict[str, list[dict[str, str]]]:
    out: dict[str, list[dict[str, str]]] = {}
    for ln in all_auth_lines(world.dirs[variant]):
        if "conn_id" in ln:
            out.setdefault(ln["conn_id"], []).append(ln)
    return out


def link_ids(world: World) -> tuple[str, str]:
    """(conn_id of GT-LNK-002, conn_id of GT-LNK-004), read from the clean key."""
    links = {k.id: k for k in world.keys[Variant.clean].links}
    return (
        links["GT-LNK-002"].evidence_refs[0].conn_id,
        links["GT-LNK-004"].evidence_refs[0].conn_id,
    )


def collateral(world: World) -> list[str]:
    """expected_collateral_conn_ids of the perturbed key's log gap."""
    gap = next(c for c in world.keys[Variant.perturbed].contradictions if c.kind == "log_gap")
    return gap.expected_collateral_conn_ids


# ---- R1 and parsers -------------------------------------------------------------------------
@pytest.mark.parametrize("variant", list(Variant))
def test_only_the_key_links_carry_markers_benign_connections_carry_none(world, variant):
    lines = all_auth_lines(world.dirs[variant])
    conn_lines = [ln for ln in lines if "conn_id" in ln]
    assert len(conn_lines) > 100  # benign pairs plus the two key links
    marked = [ln for ln in conn_lines if row_marker(ln) is not None]
    assert {ln["conn_id"] for ln in marked} <= set(link_ids(world))
    for ln in marked:
        assert row_marker(ln) is True and "pair" not in ln  # synth_only, never paired
    for ln in lines:
        assert re.fullmatch(r"CONN-\d{4}", ln.get("conn_id", "CONN-0001"))
        if "conn_id" not in ln:  # no other line claims to be a connection end
            assert ln["event"] not in ("CONN_OUT", "CONN_ACCEPTED")
            assert row_marker(ln) is not True


def test_parser_reads_marker_and_conn_id_and_rejects_bad_conn_id():
    ok = "seq=1 ts=2024-03-12T09:00:00Z host=H event=CONN_OUT conn_id=CONN-0007 synth_only=1"
    row = parse_auth_text(ok)[0]
    assert row["conn_id"] == "CONN-0007" and row_marker(row) is True
    for bad in ("C7", "CONN-007", "CONN-00007"):  # one pattern: CONN- and exactly four digits
        with pytest.raises(CompanionParseError, match="conn_id"):
            parse_auth_text(ok.replace("CONN-0007", bad))


# ---- the connections ------------------------------------------------------------------------
def test_clean_both_ends_exist_and_delta_is_zero(world):
    clean = _by_conn(world, Variant.clean)
    assert set(link_ids(world)) <= set(clean) and len(clean) >= 60
    assert all(len(v) == 2 for v in clean.values())
    deltas = oracle_cross_host_pair_delta(all_auth_lines(world.dirs[Variant.clean]))
    assert set(deltas) == set(clean) and set(deltas.values()) == {0}
    assert oracle_unmatched_connections(all_auth_lines(world.dirs[Variant.clean])) == []


def test_clean_link_a_shape(world):
    a = {ln["event"]: ln for ln in _by_conn(world, Variant.clean)[link_ids(world)[0]]}
    src, dst = a["CONN_OUT"], a["LOGON_SUCCESS"]
    assert (src["host"], src["dst_host"], src["service"]) == ("WS-FIN-07", "SRV-FILE-02", "smb")
    assert (dst["host"], dst["user"], dst["logon_type"]) == ("SRV-FILE-02", "user01", "3")
    assert dst["src_ip"] == src["src_ip"]  # the synthetic address of WS-FIN-07


def test_clean_link_b_shape(world):
    b = {ln["event"]: ln for ln in _by_conn(world, Variant.clean)[link_ids(world)[1]]}
    src, dst = b["CONN_OUT"], b["CONN_ACCEPTED"]
    assert (src["host"], src["dst_host"], src["service"]) == ("SRV-FILE-02", "DC-01", "drsuapi")
    assert (dst["host"], dst["service"]) == ("DC-01", "drsuapi")
    assert dst["src_ip"] == src["src_ip"]


def test_perturbed_link_a_delta_is_exactly_420(world):
    lines = all_auth_lines(world.dirs[Variant.perturbed])
    assert oracle_cross_host_pair_delta(lines)[link_ids(world)[0]] == 420


def test_perturbed_link_b_destination_absent_source_present(world):
    conn_b = link_ids(world)[1]
    b = _by_conn(world, Variant.perturbed)[conn_b]
    assert [(ln["host"], ln["event"]) for ln in b] == [("SRV-FILE-02", "CONN_OUT")]
    un = oracle_unmatched_connections(all_auth_lines(world.dirs[Variant.perturbed]))
    assert {u["conn_id"] for u in un} == {conn_b, *collateral(world)}
    assert next(u for u in un if u["conn_id"] == conn_b)["present_side"] == "source"


def test_collateral_connections_lost_exactly_their_dc_end(world):
    clean, pert = _by_conn(world, Variant.clean), _by_conn(world, Variant.perturbed)
    assert collateral(world)  # the window sits in a busy part of the DC log
    for cid in collateral(world):
        assert len(clean[cid]) == 2 and len(pert[cid]) == 1
        assert pert[cid][0]["host"] != "DC-01"
        assert {ln["host"] for ln in clean[cid]} >= {"DC-01"}


@pytest.mark.parametrize("variant", list(Variant))
def test_seq_is_contiguous_per_host_except_the_dc_gap(world, variant):
    for host in ("ws_fin_07", "srv_file_02", "dc_01"):
        seqs = [
            int(ln["seq"])
            for ln in all_auth_lines(world.dirs[variant])
            if ln["host"].lower().replace("-", "_") == host
        ]
        jumps = [(a, b) for a, b in zip(seqs, seqs[1:], strict=False) if b != a + 1]
        assert seqs[0] == 1
        assert len(jumps) == (1 if (variant == Variant.perturbed and host == "dc_01") else 0)


def test_p2_shifts_every_srv_line_including_link_lines(world):
    c = parse_auth_log(world.dirs[Variant.clean] / "auth_srv_file_02.log")
    p = parse_auth_log(world.dirs[Variant.perturbed] / "auth_srv_file_02.log")
    assert [x["seq"] for x in c] == [x["seq"] for x in p]
    assert {
        (parse_ts(b["ts"]) - parse_ts(a["ts"])).total_seconds() for a, b in zip(c, p, strict=True)
    } == {420}
    conn_a, conn_b = link_ids(world)  # LINK-A destination and LINK-B source are on this host
    assert {x["conn_id"] for x in p if "conn_id" in x} >= {conn_a, conn_b}
    p2 = next(k for k in world.keys[Variant.perturbed].contradictions if k.kind == "clock_skew")
    assert p2.params["lines_shifted"] == len(p)


# ---- the checks claimed in the key are proven -----------------------------------------------
def test_new_checks_are_claimed_and_proven(world):
    cons = {c.kind.value: c for c in world.keys[Variant.perturbed].contradictions}
    assert "cross_host_pair_delta" in cons["clock_skew"].checks
    assert "unmatched_connection" in cons["log_gap"].checks
    for claim, name in (
        (cons["clock_skew"], "cross_host_pair_delta"),
        (cons["log_gap"], "unmatched_connection"),
    ):
        case = Case(world.dirs[Variant.clean], world.dirs[Variant.perturbed], {}, {}, claim)
        assert CHECKS[name](case), name
    assert "synthetic" in cons["clock_skew"].detectable_by.lower()
    assert world.keys[Variant.clean].contradictions == []


# ---- link ground truth ----------------------------------------------------------------------
EXPECT = {
    "GT-LNK-001": ("WS-FIN-07", "WS-FIN-07", "stage_continuation", "alignment_constructed"),
    "GT-LNK-002": ("WS-FIN-07", "SRV-FILE-02", "lateral_movement", "synthetic_only"),
    "GT-LNK-003": ("SRV-FILE-02", "SRV-FILE-02", "stage_continuation", "alignment_constructed"),
    "GT-LNK-004": ("SRV-FILE-02", "DC-01", "remote_replication", "synthetic_only"),
}


@pytest.mark.parametrize("variant", list(Variant))
def test_four_links_validate_and_resolve(world, variant):
    key = world.keys[variant]
    key.check_against(world.scn)
    got = {k.id: (k.from_host, k.to_host, k.kind.value, k.basis.value) for k in key.links}
    assert got == EXPECT
    assert check_link_refs(key, world.scn, world.inv, world.dirs[variant]) == []
    for ln in key.links:
        assert ln.real_evidence_note and ln.expected_agent_statement
        real_only = all(not world.scn.source(r.source_key).is_synthetic for r in ln.evidence_refs)
        assert real_only == (ln.basis == LinkBasis.alignment_constructed)


def test_link_refs_follow_the_variant(world):
    conns = {
        v: {k.id: [r.event_record_id for r in k.evidence_refs] for k in world.keys[v].links}
        for v in Variant
    }
    assert len(conns[Variant.clean]["GT-LNK-004"]) == 2  # both ends exist
    assert len(conns[Variant.perturbed]["GT-LNK-004"]) == 1  # DC-01 end removed by the gap
    assert "log gap" in world.keys[Variant.perturbed].links[3].real_evidence_note
    assert conns[Variant.clean]["GT-LNK-002"] == conns[Variant.perturbed]["GT-LNK-002"]


def _link(data: dict) -> GroundTruthLink:
    return GroundTruthLink.model_validate_json(json.dumps(data))


def _mutated(world, fn) -> AnswerKey:
    key = world.keys[Variant.clean].model_copy(deep=True)
    fn(key)
    return key


def test_key_rejects_link_to_undeclared_source(world):
    def bad(key):
        key.links[1].evidence_refs[0].source_key = "auth_nowhere"

    with pytest.raises(ValueError, match="undeclared source"):
        _mutated(world, bad).check_against(world.scn)


def test_key_rejects_missing_conn_id_and_unresolvable_conn_id(world):
    def no_conn(key):
        key.links[1].evidence_refs[0].conn_id = None

    with pytest.raises(ValueError, match="one conn_id"):
        # model validators only run on construction: re-validate the mutated link
        _link(_mutated(world, no_conn).links[1].model_dump(mode="json"))

    def wrong_conn(key):
        key.links[1].evidence_refs[0].conn_id = "CONN-9999"

    key = _mutated(world, wrong_conn)
    problems = check_link_refs(key, world.scn, world.inv, world.dirs[Variant.clean])
    assert len(problems) == 1 and "conn_id" in problems[0]

    def wrong_seq(key):
        key.links[1].evidence_refs[0].event_record_id = 999999

    key = _mutated(world, wrong_seq)
    assert (
        "no such line" in check_link_refs(key, world.scn, world.inv, world.dirs[Variant.clean])[0]
    )


def test_link_schema_rules(world):
    base = world.keys[Variant.clean].links[1].model_dump(mode="json")
    _link(base)
    with pytest.raises(ValidationError):
        _link({**base, "id": "GT-LNK-1"})
    with pytest.raises(ValidationError):
        _link({**base, "evidence_refs": []})
    with pytest.raises(ValidationError):  # alignment_constructed must use real records only
        _link({**base, "basis": "alignment_constructed"})
    with pytest.raises(ValidationError):
        LinkRef(source_key="x", event_record_id=1, synthetic_only=True, conn_id="CONN-1")
    assert LinkKind("credential_reuse")  # the fourth kind is allowed even if unused here


def test_duplicate_link_ids_are_rejected(world):
    key = world.keys[Variant.clean].model_copy(deep=True)
    key.links[1].id = "GT-LNK-001"
    with pytest.raises(ValueError, match="duplicate"):
        AnswerKey.model_validate_json(key.model_dump_json())


def test_links_present_in_both_committed_keys(v4):
    for variant in Variant:
        assert [k.id for k in v4.keys[variant].links] == list(EXPECT)
    note = v4.keys[Variant.clean].missing_evidence[3]
    assert "still absent" in note.description and "stand in" in note.description
