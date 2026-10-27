"""TEST-ONLY detection oracles. NOT product code and NOT the Phase 4 detectors.

These are deliberately simple helpers that prove each planted contradiction is detectable from the
generated files (plus real-event times). They exist so the answer key can be checked against the
data: on the perturbed variant they must find exactly what the key says, on the clean variant
nothing. ``CHECKS`` maps the check names used in the key (``checks``) to a runnable proof.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from chainofproof.scenarios.companions import (
    parse_auth_log,
    parse_fs_csv,
    parse_ts,
    row_marker,
)
from chainofproof.schemas.groundtruth import GroundTruthContradiction

TIMESTOMP_THRESHOLD = timedelta(days=1)


def oracle_timestomp(fs_csv: Path, threshold: timedelta = TIMESTOMP_THRESHOLD) -> list[dict]:
    """Records whose SI created/modified differs from FN by more than ``threshold``."""
    out = []
    for r in parse_fs_csv(fs_csv):
        d = max(
            abs(parse_ts(r[f"fn_{k}"]) - parse_ts(r[f"si_{k}"])) for k in ("created", "modified")
        )
        if d > threshold:
            out.append({"record_id": int(r["record_id"]), "path": r["path"], "delta": d})
    return out


def oracle_clock_skew(
    real_times: dict[tuple[str, str], datetime], auth_lines: list[dict[str, str]]
) -> dict[str, list[int]]:
    """Per-host deltas (seconds) between paired auth lines and the aligned real event times.

    ``real_times`` maps (pair_field, pair_value) to the real event time after the alignment layer
    (whole seconds). Lines without a pairing marker, or whose pairing is unknown, are ignored.
    """
    out: dict[str, list[int]] = {}
    for ln in auth_lines:
        mk = row_marker(ln)
        if isinstance(mk, tuple) and mk in real_times:
            delta = int((parse_ts(ln["ts"]) - real_times[mk]).total_seconds())
            out.setdefault(ln["host"], []).append(delta)
    return out


def oracle_log_gap(auth_log: Path, real_times: list[datetime]) -> list[dict]:
    """Discontinuities in ``seq`` per host, with the real events inside the missing window."""
    by_host: dict[str, list[dict[str, str]]] = {}
    for ln in parse_auth_log(auth_log):
        by_host.setdefault(ln["host"], []).append(ln)
    gaps = []
    for host, lines in by_host.items():
        lines.sort(key=lambda x: int(x["seq"]))
        for a, b in zip(lines, lines[1:], strict=False):
            if int(b["seq"]) != int(a["seq"]) + 1:
                lo, hi = parse_ts(a["ts"]), parse_ts(b["ts"])
                gaps.append(
                    {
                        "host": host,
                        "first_missing_seq": int(a["seq"]) + 1,
                        "last_missing_seq": int(b["seq"]) - 1,
                        "real_events_inside": sum(lo < t < hi for t in real_times),
                    }
                )
    return gaps


def _connection_ends(lines: list[dict[str, str]]) -> dict[str, dict[str, dict[str, str]]]:
    """conn_id -> {"source": CONN_OUT line, "dest": the other end}, over lines of all hosts."""
    out: dict[str, dict[str, dict[str, str]]] = {}
    for ln in lines:
        if "conn_id" in ln:
            out.setdefault(ln["conn_id"], {})["source" if ln["event"] == "CONN_OUT" else "dest"] = (
                ln
            )
    return out


def oracle_cross_host_pair_delta(lines: list[dict[str, str]]) -> dict[str, int]:
    """conn_id -> seconds by which the destination-side line is later than the source-side line.

    Only connections with both ends on different hosts. Synthetic vs synthetic: no real event.
    """
    return {
        cid: int((parse_ts(e["dest"]["ts"]) - parse_ts(e["source"]["ts"])).total_seconds())
        for cid, e in _connection_ends(lines).items()
        if {"source", "dest"} <= set(e) and e["source"]["host"] != e["dest"]["host"]
    }


def oracle_unmatched_connections(lines: list[dict[str, str]]) -> list[dict]:
    """Connections that have only one end: which side is present, on which host, at which seq."""
    return [
        {"conn_id": cid, "present_side": side, "host": e[side]["host"], "seq": int(e[side]["seq"])}
        for cid, e in sorted(_connection_ends(lines).items())
        for side in e
        if len(e) == 1
    ]


def all_auth_lines(folder: Path) -> list[dict[str, str]]:
    """Every auth line of the three hosts of a generated variant."""
    return [
        ln
        for h in ("ws_fin_07", "srv_file_02", "dc_01")
        for ln in parse_auth_log(folder / f"auth_{h}.log")
    ]


@dataclass
class Case:
    """Everything a check needs: generated dirs, scenario, field inspection, the key's claim."""

    clean: Path
    perturbed: Path
    real_times: dict[tuple[str, str], datetime]  # aligned real times by pairing (field, value)
    s5_times: dict[int, datetime]  # aligned real S5 event times by record id
    claim: GroundTruthContradiction


def _check_si_fn(c: Case) -> bool:
    p = c.claim.params
    found = oracle_timestomp(c.perturbed / "fs_srv_file_02.csv")
    want = {(f["record_id"], f["path"], f["delta_seconds"]) for f in p["files"]}
    got = {(f["record_id"], f["path"], int(f["delta"].total_seconds())) for f in found}
    clean_ok = not oracle_timestomp(c.clean / "fs_srv_file_02.csv")
    other_ok = not any(
        oracle_timestomp(c.perturbed / f"fs_{h}.csv") for h in ("ws_fin_07", "dc_01")
    )
    return got == want and clean_ok and other_ok and len(want) == c.claim.magnitude


def _check_paired_delta(c: Case) -> bool:
    p = c.claim.params
    logs = {
        v: parse_auth_log(d / "auth_srv_file_02.log")
        for v, d in (("c", c.clean), ("p", c.perturbed))
    }
    clean = oracle_clock_skew(c.real_times, logs["c"]).get(p["host"], [])
    pert = oracle_clock_skew(c.real_times, logs["p"]).get(p["host"], [])
    n = len(p["paired_lines"])
    return n >= 2 and clean == [0] * n and pert == [int(c.claim.magnitude)] * n


def _gaps(c: Case) -> list[dict]:
    times = list(c.s5_times.values())
    return oracle_log_gap(c.perturbed / "auth_dc_01.log", times)


def _check_seq_gap(c: Case) -> bool:
    p = c.claim.params
    gaps = _gaps(c)
    clean_ok = not oracle_log_gap(c.clean / "auth_dc_01.log", [])
    return (
        len(gaps) == 1
        and (gaps[0]["host"], gaps[0]["first_missing_seq"], gaps[0]["last_missing_seq"])
        == (p["host"], p["first_removed_seq"], p["last_removed_seq"])
        and clean_ok
    )


def _check_real_in_gap(c: Case) -> bool:
    p = c.claim.params
    gaps = _gaps(c)
    inside = [rid for rid, t in c.s5_times.items() if parse_ts_window(p, t)]
    return (
        len(gaps) == 1
        and gaps[0]["real_events_inside"] == len(p["real_record_ids_inside_window"]) > 0
        and sorted(inside) == sorted(p["real_record_ids_inside_window"])
    )


def expected_pair_deltas(lines: list[dict[str, str]], host: str, shift: int) -> dict[str, int]:
    """conn_id -> delta after ``host`` is shifted: +shift if it holds the destination end, -shift
    if it holds the source end, 0 otherwise (cross-host connections only)."""
    out = {}
    for cid, e in _connection_ends(lines).items():
        if {"source", "dest"} <= set(e) and e["source"]["host"] != e["dest"]["host"]:
            out[cid] = shift * ((e["dest"]["host"] == host) - (e["source"]["host"] == host))
    return out


def _deltas_as_expected(
    clean_lines: list[dict[str, str]], pert: dict[str, int], host: str, shift: int
) -> bool:
    """Perturbed pair deltas equal the expectation for every connection that still has both ends
    (the gap removed one end of some; those are not pairs any more)."""
    want = expected_pair_deltas(clean_lines, host, shift)
    return set(pert) <= set(want) and all(pert[k] == want[k] for k in pert)


def _check_cross_pair(c: Case) -> bool:
    pairs = c.claim.params["cross_host_pairs"]
    shift = int(c.claim.magnitude)
    clean_lines = all_auth_lines(c.clean)
    clean = oracle_cross_host_pair_delta(clean_lines)
    pert = oracle_cross_host_pair_delta(all_auth_lines(c.perturbed))
    want = {p["conn_id"]: p["perturbed_delta_seconds"] for p in pairs}
    return (
        bool(pairs)
        and set(clean.values()) == {0}  # clean: every connection has both ends, 0 s apart
        and {p["conn_id"]: p["clean_delta_seconds"] for p in pairs} == {k: 0 for k in want}
        # perturbed: the skewed host's connections (benign ones included) move by +/- the shift
        and _deltas_as_expected(clean_lines, pert, c.claim.params["host"], shift)
        and all(pert[k] == v for k, v in want.items())  # the planted pair at the key's magnitude
        and set(want.values()) == {shift}
    )


def _check_unmatched(c: Case) -> bool:
    want = c.claim.params["unmatched_connections"]
    found = oracle_unmatched_connections(all_auth_lines(c.perturbed))
    got = {f["conn_id"]: (f["present_side"], _auth_key(f["host"]), f["seq"]) for f in found}
    exp = {
        w["conn_id"]: (w["present_side"], w["present"]["source_key"], w["present"]["seq"])
        for w in want
    }
    collateral = set(c.claim.expected_collateral_conn_ids)
    return (
        oracle_unmatched_connections(all_auth_lines(c.clean)) == []
        and bool(exp)
        and {k: got[k] for k in exp} == exp  # the planted connection, exactly as the key says
        and set(got) == set(exp) | collateral  # nothing else is one-ended
    )


def _auth_key(host: str) -> str:
    return f"auth_{host.lower().replace('-', '_')}"


def parse_ts_window(p: dict[str, Any], t: datetime) -> bool:
    """True when ``t`` lies in the key's removed window [window_start, window_end)."""
    return parse_ts(p["window_start"]) <= t < parse_ts(p["window_end"])


CHECKS: dict[str, Callable[[Case], bool]] = {
    "si_fn_mismatch": _check_si_fn,
    "paired_line_time_delta": _check_paired_delta,
    "seq_discontinuity": _check_seq_gap,
    "real_events_inside_gap": _check_real_in_gap,
    "cross_host_pair_delta": _check_cross_pair,
    "unmatched_connection": _check_unmatched,
}
