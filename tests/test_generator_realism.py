"""Phase 4.1 generator invariants: benign background shares the key lines' vocabulary (G1), time-
ordered connection ids (G2), realistic times (G3), filesystem vocabulary (G4), perturbation
exactness and the collateral of the log gap (G5). Small fixture scenario AND committed v4 files."""

import json
import ntpath
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from chainofproof.scenarios.companions import parse_auth_log, parse_fs_csv, parse_ts, row_marker
from chainofproof.scenarios.fieldscan import load_real_pipes
from chainofproof.scenarios.gen_context import parse_real
from chainofproof.scenarios.gen_vocab import HOSTS
from chainofproof.scenarios.generator import generate_variant
from chainofproof.scenarios.inventory import Inventory
from chainofproof.scenarios.keylinks import check_collateral
from chainofproof.scenarios.keys import build_key
from chainofproof.schemas.scenario import AnswerKey, Scenario, Variant
from conftest import V4_DIR
from oracles import all_auth_lines, oracle_unmatched_connections
from scenario_fixture import build_fixture

GUARD_SECONDS = 300
FIELDS = ("event", "user", "service", "logon_type", "dst_host", "src_ip")


@dataclass
class World:
    """A scenario with both generated variants and their keys."""

    name: str
    scn: Scenario
    inv: Inventory
    dirs: dict[Variant, Path]
    keys: dict[Variant, AnswerKey]


@pytest.fixture(scope="module", params=["fixture", "v4"])
def world(request, tmp_path_factory, v4) -> World:
    if request.param == "v4":
        return World("v4", v4.scn, v4.inv, v4.dirs, v4.keys)
    root = tmp_path_factory.mktemp("realism")
    scn, inv, _, _ = build_fixture(root)
    dirs, keys = {}, {}
    for v in Variant:
        dirs[v] = root / "gen" / v.value
        keys[v] = build_key(scn, inv, v, generate_variant(scn, inv, v, dirs[v]))
    return World("fixture", scn, inv, dirs, keys)


def _link_ids(world: World) -> set[str]:
    links = {k.id: k for k in world.keys[Variant.clean].links}
    return {links[i].evidence_refs[0].conn_id for i in ("GT-LNK-002", "GT-LNK-004")}


# ---- G1 vocabulary --------------------------------------------------------------------------
@pytest.mark.parametrize("variant", list(Variant))
def test_every_value_on_a_key_line_also_appears_on_at_least_five_benign_lines(world, variant):
    """Exceptions by design: conn_id, logon_id and the pipe names paired with real pipe events."""
    lines = all_auth_lines(world.dirs[variant])
    for host in HOSTS:
        mine = [ln for ln in lines if ln["host"] == host]
        benign = [ln for ln in mine if row_marker(ln) is None]
        ref = [ln for ln in mine if row_marker(ln) is not None]
        assert ref or host == "SRV-FILE-02" or variant == Variant.perturbed
        for field in FIELDS:
            counts = Counter(ln[field] for ln in benign if field in ln)
            for ln in ref:
                if field in ln:
                    assert counts[ln[field]] >= 5, (
                        f"{host}.{field}={ln[field]}: {counts[ln[field]]}"
                    )


def test_benign_users_per_host_are_about_eight_and_include_user01(world):
    for host in HOSTS:
        users = {
            ln["user"]
            for ln in all_auth_lines(world.dirs[Variant.clean])
            if ln["host"] == host and row_marker(ln) is None and ln["user"] != "unknown"
        }
        assert 7 <= len(users) <= 10 and "user01" in users, host


def test_connection_lines_use_user_unknown_in_benign_and_key_lines(world):
    for ln in all_auth_lines(world.dirs[Variant.clean]):
        if ln["event"] in ("CONN_OUT", "CONN_ACCEPTED"):
            assert ln["user"] == "unknown"


def test_benign_pipe_names_avoid_the_real_pipe_names_of_the_guard(world, tmp_path):
    """With real names handed in, no benign pipe line on that host carries one of them."""
    ordinary = frozenset({"srvsvc", "spoolss", "atsvc", "lsarpc"})
    generate_variant(world.scn, world.inv, Variant.clean, tmp_path, {"SRV-FILE-02": ordinary})
    for ln in parse_auth_log(tmp_path / "auth_srv_file_02.log"):
        if "pipe" in ln and row_marker(ln) is None:
            assert ln["pipe"].lower() not in ordinary


def test_pipe_guard_changes_nothing_on_the_committed_data(world):
    if world.name != "v4":
        pytest.skip("committed v4 files only")
    pipes = load_real_pipes(V4_DIR / "field_inspection.json", world.scn)
    assert pipes["SRV-FILE-02"]  # the real S3/S4 pipe names
    for v in Variant:
        got = generate_variant(world.scn, world.inv, v, world.dirs[v] / "again", pipes).hashes
        assert got == world.keys[v].generated_file_hashes


# ---- G2 connections ---------------------------------------------------------------------------
def test_connections_have_two_ends_between_logged_hosts_and_time_ordered_ids(world):
    by = defaultdict(list)
    for ln in all_auth_lines(world.dirs[Variant.clean]):
        if "conn_id" in ln:
            by[ln["conn_id"]].append(ln)
    assert all(len(v) == 2 for v in by.values())
    for ends in by.values():
        src = next(e for e in ends if e["event"] == "CONN_OUT")
        dst = next(e for e in ends if e is not src)
        assert src["host"] in HOSTS and src["dst_host"] in HOSTS and dst["host"] == src["dst_host"]
        assert src["ts"] == dst["ts"]
    ids = sorted(by)
    stamps = [by[c][0]["ts"] for c in ids]
    assert stamps == sorted(stamps)  # ids increase with time
    assert not _link_ids(world) & {ids[0], ids[-1]}  # key ids are ordinary, mid-sequence ids
    assert len(ids) >= 60


def test_no_benign_connection_with_a_key_triple_near_a_key_link(world):
    by = defaultdict(list)
    for ln in all_auth_lines(world.dirs[Variant.clean]):
        if ln["event"] == "CONN_OUT":
            by[ln["conn_id"]] = ln
    keys = [by[c] for c in _link_ids(world)]
    for cid, ln in by.items():
        if cid in _link_ids(world):
            continue
        for k in keys:
            if (ln["host"], ln["dst_host"], ln["service"]) == (
                k["host"],
                k["dst_host"],
                k["service"],
            ):
                gap = abs((parse_ts(ln["ts"]) - parse_ts(k["ts"])).total_seconds())
                assert gap > GUARD_SECONDS, cid


# ---- G3 time realism (committed v4 only: the fixture keeps round stage times) -----------------
def _v4_only(world: World) -> None:
    if world.name != "v4":
        pytest.skip("stage times of the fixture are round on purpose")


def test_stage_times_are_not_round_and_keep_the_real_microseconds(world):
    _v4_only(world)
    for a in world.scn.alignment:
        virt, real = (
            parse_real(a.virtual_first_key_event_time),
            parse_real(a.real_first_key_event_time),
        )
        assert virt.second != 0 and virt.microsecond == real.microsecond
    first = {a.source_key: a.virtual_first_key_event_time[11:19] for a in world.scn.alignment}
    assert first["s1_lsass_mimikatz"] == "09:03:17" and first["d2_rundll32_lolbin"] == "14:08:49"


def _position(lines: list[dict[str, str]], ln: dict[str, str]) -> float:
    lo, hi = parse_ts(lines[0]["ts"]), parse_ts(lines[-1]["ts"])
    return (parse_ts(ln["ts"]) - lo) / (hi - lo)


def test_referenced_lines_are_spread_over_time_positions_and_seconds(world):
    _v4_only(world)
    deciles, seconds = set(), set()
    for host in HOSTS:
        lines = [ln for ln in all_auth_lines(world.dirs[Variant.clean]) if ln["host"] == host]
        ref = [ln for ln in lines if row_marker(ln) is not None]
        pos = [_position(lines, ln) for ln in ref]
        assert not all(0.4 <= p <= 0.6 for p in pos), host  # not all in the middle 20%
        deciles |= {min(int(p * 10), 9) for p in pos}
        seconds |= {parse_ts(ln["ts"]).second for ln in ref}
        sec = Counter(parse_ts(ln["ts"]).second for ln in lines if row_marker(ln) is None)
        assert len(sec) >= 55 and sec[0] / sum(sec.values()) < 0.05, host  # no :00 habit
    assert len(deciles) >= 4 and seconds != {0} and len(seconds) >= 3


def test_p3_window_is_720_s_contains_dcsync_and_does_not_start_on_a_minute(world):
    gap = next(c for c in world.keys[Variant.perturbed].contradictions if c.kind == "log_gap")
    lo, hi = parse_ts(gap.params["window_start"]), parse_ts(gap.params["window_end"])
    assert (hi - lo) == timedelta(seconds=720) == timedelta(seconds=gap.magnitude)
    assert lo.second != 0
    dc = [ln for ln in all_auth_lines(world.dirs[Variant.clean]) if ln["host"] == "DC-01"]
    dcsync = next(ln for ln in dc if ln.get("pair", "").startswith("logon_id:"))
    t = parse_ts(dcsync["ts"])
    assert lo <= t < hi and 200 <= (t - lo).total_seconds() <= 520
    assert gap.params["first_removed_seq"] <= int(dcsync["seq"]) <= gap.params["last_removed_seq"]


# ---- G4 filesystem -----------------------------------------------------------------------------
def _stem(path: str) -> str:
    return re.sub(r"[\d_\-\.]+$|\d+", "", ntpath.splitext(ntpath.basename(path.lower()))[0])


def _fs_rows(world: World, variant: Variant) -> tuple[list[dict], list[dict]]:
    rows = [
        r
        for h in HOSTS
        for r in parse_fs_csv(world.dirs[variant] / f"fs_{h.lower().replace('-', '_')}.csv")
    ]
    return [r for r in rows if not r["note"]], [r for r in rows if r["note"]]


def test_benign_rows_include_system32_svchost_and_powershell_in_normal_places(world):
    benign, _ = _fs_rows(world, Variant.clean)
    paths = {r["path"].lower() for r in benign}
    assert r"c:\windows\system32\svchost.exe" in paths
    assert r"c:\windows\system32\windowspowershell\v1.0\powershell.exe" in paths


def test_no_extension_prefix_or_depth_is_exclusive_to_referenced_rows(world):
    benign, ref = _fs_rows(world, Variant.clean)
    assert len(ref) == 5
    ext = lambda p: ntpath.splitext(p)[1].lower()  # noqa: E731
    prefix = lambda p: "\\".join(p.lower().split("\\")[:3])  # noqa: E731
    seen = {
        "ext": {ext(r["path"]) for r in benign},
        "depth": {r["path"].count("\\") for r in benign},
        "prefix": {prefix(r["path"]) for r in benign},
        "stem": {_stem(r["path"]) for r in benign},
    }
    for r in ref:
        p = r["path"]
        assert ext(p) in seen["ext"] and p.count("\\") in seen["depth"], p
        if p.count("\\") > 2:  # at depth 2 the 3-component prefix IS the path: documented tell
            assert prefix(p) in seen["prefix"], p
        if not r["note"].startswith("pair=image_basename"):  # names paired with real images
            assert _stem(p) in seen["stem"], p


def test_credential_dump_file_has_an_innocuous_name_and_the_key_says_so(world):
    _, ref = _fs_rows(world, Variant.clean)
    (dump,) = [r for r in ref if r["note"] == "synth_only=1"]
    name = ntpath.basename(dump["path"]).lower()
    assert not re.search(r"sekurlsa|dump|cred|mimi|lsass|pass|hash|secret", name)
    act = next(a for a in world.keys[Variant.clean].actions if a.attack_technique_id == "T1003.001")
    assert "innocuous" in act.description and any(r.synthetic_only for r in act.supporting_refs)


# ---- G5 perturbations on v4 ----------------------------------------------------------------------
def test_p1_changes_exactly_two_files_si_only_and_benign_jitter_stays_within_seconds(world):
    clean, _ = _fs_rows(world, Variant.clean)
    pert_all = [
        r
        for h in HOSTS
        for r in parse_fs_csv(
            world.dirs[Variant.perturbed] / f"fs_{h.lower().replace('-', '_')}.csv"
        )
    ]
    p1 = next(c for c in world.keys[Variant.perturbed].contradictions if c.kind == "timestomp")
    want = {(f["record_id"], f["delta_seconds"]) for f in p1.params["files"]}
    got = set()
    for r in pert_all:
        d = (parse_ts(r["fn_created"]) - parse_ts(r["si_created"])).total_seconds()
        if abs(d) > 3600:
            got.add((int(r["record_id"]), int(d)))
            assert r["si_created"].startswith("2021-06-15") and r["fn_created"].startswith(
                "2024-03-12"
            )
        else:
            assert abs(d) <= 3
    assert got == want and len(want) == p1.magnitude == 2 and clean


def test_collateral_equals_the_unmatched_ids_minus_the_link_and_is_absent_in_clean(world):
    key = world.keys[Variant.perturbed]
    gap = next(c for c in key.contradictions if c.kind == "log_gap")
    assert (
        check_collateral(key, world.scn, world.dirs[Variant.clean], world.dirs[Variant.perturbed])
        == []
    )
    link_b = next(k for k in key.links if k.id == "GT-LNK-004").evidence_refs[0].conn_id
    unmatched = {
        u["conn_id"]
        for u in oracle_unmatched_connections(all_auth_lines(world.dirs[Variant.perturbed]))
    }
    assert unmatched - {link_b} == set(gap.expected_collateral_conn_ids)
    assert oracle_unmatched_connections(all_auth_lines(world.dirs[Variant.clean])) == []


def test_check_collateral_rejects_a_wrong_list(world):
    key = world.keys[Variant.perturbed].model_copy(deep=True)
    gap = next(c for c in key.contradictions if c.kind == "log_gap")
    d = (world.dirs[Variant.clean], world.dirs[Variant.perturbed])
    gap.expected_collateral_conn_ids = [*gap.expected_collateral_conn_ids, "CONN-9999"]
    assert check_collateral(key, world.scn, *d)
    gap.expected_collateral_conn_ids = []
    assert check_collateral(key, world.scn, *d)  # one-ended ids exist that the key does not list


def test_collateral_schema_validation(world):
    gap = next(c for c in world.keys[Variant.perturbed].contradictions if c.kind == "log_gap")
    cls = type(gap)

    def build(model, **over):
        return cls.model_validate_json(json.dumps({**model.model_dump(mode="json"), **over}))

    build(gap)
    for bad in (["CONN-0002", "CONN-0001"], ["CONN-0001", "CONN-0001"], ["CONN-001"]):
        with pytest.raises(ValidationError):
            build(gap, expected_collateral_conn_ids=bad)
    skew = next(c for c in world.keys[Variant.perturbed].contradictions if c.kind == "clock_skew")
    with pytest.raises(ValidationError, match="log_gap"):
        build(skew, expected_collateral_conn_ids=["CONN-0001"])
    assert "collateral" in gap.detectable_by.lower()
