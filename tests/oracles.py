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


def parse_ts_window(p: dict[str, Any], t: datetime) -> bool:
    """True when ``t`` lies in the key's removed window [window_start, window_end)."""
    return parse_ts(p["window_start"]) <= t < parse_ts(p["window_end"])


CHECKS: dict[str, Callable[[Case], bool]] = {
    "si_fn_mismatch": _check_si_fn,
    "paired_line_time_delta": _check_paired_delta,
    "seq_discontinuity": _check_seq_gap,
    "real_events_inside_gap": _check_real_in_gap,
}
