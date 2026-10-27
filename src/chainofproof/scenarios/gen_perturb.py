"""The three recorded perturbations (P1 timestomp, P2 clock skew, P3 log gap) and their key entries.

* P1 timestomp: si_created/si_modified of the two S4 PsExec binaries on SRV-FILE-02 (the renamed
  svchost.exe and PsExec.exe) moved back to 2021-06-15 while fn_* keep the true drop time.
* P2 clock skew: every auth line of SRV-FILE-02 (benign lines included) shifted +420 s.
* P3 log gap: all DC-01 auth lines in a 720 s window containing the DCSync event removed (the
  window start is DCSync time minus a seeded 200-520 s, never on a minute boundary; seq is NOT
  renumbered, so the jump is visible). Benign connections whose DC-01 end falls in the window lose
  one end: they are recorded as expected collateral.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from chainofproof.scenarios.companions import fmt_ts, parse_ts
from chainofproof.scenarios.gen_auth import AuthResult
from chainofproof.scenarios.gen_context import GenContext
from chainofproof.scenarios.gen_fs import ATTACKER_DATE, FsResult
from chainofproof.schemas.scenario import ContradictionKind, GroundTruthContradiction

SKEW_SECONDS = 420
GAP_LENGTH = timedelta(minutes=12)
GAP_BEFORE_RANGE = (200, 520)  # seconds before the DCSync time at which the window starts
STOMPED_TAGS = ("renamed_svchost", "psexec_client")
# check names that tests/oracles.py proves to work on the generated data
CHECK_SI_FN, CHECK_PAIRED_DELTA = "si_fn_mismatch", "paired_line_time_delta"
CHECK_SEQ_GAP, CHECK_REAL_IN_GAP = "seq_discontinuity", "real_events_inside_gap"
CHECK_CROSS_PAIR, CHECK_UNMATCHED = "cross_host_pair_delta", "unmatched_connection"


def slug(host: str) -> str:
    """Host name -> source_key suffix (WS-FIN-07 -> ws_fin_07)."""
    return host.lower().replace("-", "_")


def line_at(auth: AuthResult, tag: str) -> dict[str, str]:
    """The line of an auth log that carries a link tag (looked up by its seq)."""
    seq = auth.link_seq[tag]
    return next(ln for ln in auth.lines if int(ln["seq"]) == seq)


def _src(ctx: GenContext, stage_id: str) -> str:
    """Source key of the real file that belongs to a stage."""
    return ctx.inventory.keys_for(stage_id).source_key


def timestomp(ctx: GenContext, fs: FsResult, host: str) -> GroundTruthContradiction:
    """P1: stomp the two S4 binaries in place and describe it."""
    rng = ctx.rng("p1")
    sk, files = f"fs_{slug(host)}", []
    for tag in STOMPED_TAGS:
        row = fs.rows[fs.artifacts[tag] - 1]
        hms = (rng.randint(8, 17), rng.randint(0, 59), rng.randint(0, 59))
        old = f"{ATTACKER_DATE}T{hms[0]:02d}:{hms[1]:02d}:{hms[2]:02d}Z"
        delta = int((parse_ts(row["fn_created"]) - parse_ts(old)).total_seconds())
        row["si_created"] = row["si_modified"] = old
        pr = fs.pairings[tag]
        files.append(
            {
                "source_key": sk,
                "record_id": int(row["record_id"]),
                "path": row["path"],
                "si_created": old,
                "fn_created": row["fn_created"],
                "delta_seconds": delta,
                "pairing_field": pr.field,
                "pairing_value": pr.value,
            }
        )
    return GroundTruthContradiction(
        id="GT-CON-001",
        kind=ContradictionKind.timestomp,
        sources_involved=[sk, _src(ctx, "S4")],
        description=(
            f"Two attacker-dropped binaries on {host} (the renamed service binary and the PsExec "
            f"client) have $STANDARD_INFORMATION created/modified times set to {ATTACKER_DATE} "
            "while $FILE_NAME times keep the true drop time."
        ),
        magnitude=len(files),
        magnitude_unit="count",
        params={"host": host, "files": files},
        detectable_by=(
            "si_created differs from fn_created by more than a day within the SAME file-system "
            "record. This is the only check that works: no real event records the creation of "
            "these files, so there is no cross-source creation-time comparison."
        ),
        checks=[CHECK_SI_FN],
    )


def _cross_pair(src: AuthResult, dst: AuthResult, dst_shift: int) -> dict:
    """LINK-A: both ends of its connection and their time difference (destination minus source)."""
    s, d = line_at(src, "LINK_A:src"), line_at(dst, "LINK_A:dst")
    assert s["conn_id"] == d["conn_id"]
    delta = int((parse_ts(d["ts"]) - parse_ts(s["ts"])).total_seconds())
    return {
        "conn_id": s["conn_id"],
        "source_side": {"source_key": f"auth_{slug(s['host'])}", "seq": int(s["seq"])},
        "dest_side": {"source_key": f"auth_{slug(d['host'])}", "seq": int(d["seq"])},
        "clean_delta_seconds": delta,
        "perturbed_delta_seconds": delta + dst_shift,
    }


def clock_skew(
    ctx: GenContext, auth: AuthResult, host: str, all_auth: dict[str, AuthResult]
) -> GroundTruthContradiction:
    """P2: shift every line of the host (benign background included) and describe it."""
    sk, paired = f"auth_{slug(host)}", []
    cross = _cross_pair(all_auth["WS-FIN-07"], auth, SKEW_SECONDS)
    by_seq = {int(ln["seq"]): ln for ln in auth.lines}
    for tag, seq in sorted(auth.key_seq.items(), key=lambda kv: kv[1]):
        pr = auth.pairings[tag]
        real = ctx.key_time(pr.source_key or "", pr.record_ids[0])
        before = parse_ts(by_seq[seq]["ts"])
        paired.append(
            {
                "seq": seq,
                "pairing_field": pr.field,
                "pairing_value": pr.value,
                "real_source_key": pr.source_key,
                "real_record_ids": list(pr.record_ids),
                "aligned_real_time": fmt_ts(real),
                "clean_delta_seconds": int((before - real).total_seconds()),
                "perturbed_delta_seconds": int((before - real).total_seconds()) + SKEW_SECONDS,
            }
        )
    for ln in auth.lines:
        ln["ts"] = fmt_ts(parse_ts(ln["ts"]) + timedelta(seconds=SKEW_SECONDS))
    return GroundTruthContradiction(
        id="GT-CON-002",
        kind=ContradictionKind.clock_skew,
        sources_involved=[sk, _src(ctx, "S4")],
        description=(
            f"Every auth-log line of {host} ({len(auth.lines)} lines, benign background and the "
            f"synthetic cross-host link lines included) is {SKEW_SECONDS} s later than reality."
        ),
        magnitude=SKEW_SECONDS,
        magnitude_unit="seconds",
        params={
            "host": host,
            "source_key": sk,
            "shift_seconds": SKEW_SECONDS,
            "lines_shifted": len(auth.lines),
            "paired_lines": paired,
            "cross_host_pairs": [cross],
        },
        detectable_by=(
            "paired lines: each NAMED_PIPE_OPEN line carries pair=pipe_name:<name>, the pipe name "
            "of a real S4 Sysmon 18 event; after the alignment layer the line time minus the real "
            "event time (whole seconds) is 0 s in the clean variant and +420 s in the perturbed "
            "variant for every paired line. cross_host_pair_delta: the two ends of "
            f"{cross['conn_id']} (WS-FIN-07 CONN_OUT, SRV-FILE-02 LOGON_SUCCESS, same conn_id) "
            "differ by exactly 0 s in the clean variant and +420 s in the perturbed variant; "
            "every benign connection with one end on SRV-FILE-02 is shifted the same way "
            "(+420 s when SRV-FILE-02 holds the destination end, -420 s when it holds the source "
            "end); this compares SYNTHETIC with SYNTHETIC lines, no real event is involved"
        ),
        checks=[CHECK_PAIRED_DELTA, CHECK_CROSS_PAIR],
    )


def _unmatched(gone: list[dict[str, str]], srv: AuthResult) -> dict:
    """LINK-B: its DC-01 end was removed in the window; its SRV-FILE-02 end remains."""
    src = line_at(srv, "LINK_B:src")
    lost = [ln for ln in gone if ln.get("conn_id") == src["conn_id"]]
    assert len(lost) == 1  # the destination-side line must be inside the removed window
    return {
        "conn_id": src["conn_id"],
        "present_side": "source",
        "present": {"source_key": f"auth_{slug(src['host'])}", "seq": int(src["seq"])},
        "missing": {"source_key": f"auth_{slug(lost[0]['host'])}", "seq": int(lost[0]["seq"])},
    }


def _gap_start(ctx: GenContext, key_ts: datetime) -> datetime:
    """Window start: the DCSync time minus a seeded 200-520 s, never on a minute boundary."""
    rng = ctx.rng("p3")
    while True:
        lo = key_ts - timedelta(seconds=rng.randint(*GAP_BEFORE_RANGE))
        if lo.second != 0:
            return lo


def log_gap(
    ctx: GenContext, auth: AuthResult, host: str, all_auth: dict[str, AuthResult]
) -> GroundTruthContradiction:
    """P3: remove the window from the DC log (seq not renumbered) and describe it."""
    by_seq = {int(ln["seq"]): ln for ln in auth.lines}
    key_ts = parse_ts(by_seq[auth.key_seq["S5"]]["ts"])  # the DCSync line (not a benign replica)
    lo = _gap_start(ctx, key_ts)
    hi = lo + GAP_LENGTH
    gone = [ln for ln in auth.lines if lo <= parse_ts(ln["ts"]) < hi]
    auth.lines[:] = [ln for ln in auth.lines if ln not in gone]
    seqs = [int(ln["seq"]) for ln in gone]
    sk, s5 = f"auth_{slug(host)}", ctx.inventory.keys_for("S5")
    inside = [
        e.record_id for e in s5.result.events if lo <= ctx.virt(s5.source_key, e.real_time) < hi
    ]
    link_b = line_at(all_auth["SRV-FILE-02"], "LINK_B:src")["conn_id"]
    collateral = sorted({ln["conn_id"] for ln in gone if "conn_id" in ln} - {link_b})
    return GroundTruthContradiction(
        id="GT-CON-003",
        kind=ContradictionKind.log_gap,
        sources_involved=[sk, s5.source_key],
        description=(
            f"All {len(gone)} {host} auth-log lines in a 12-minute window containing the DCSync "
            f"event are missing (seq {min(seqs)} to {max(seqs)}), among them the destination-side "
            f"line of the synthetic connection {link_b} and the {host} end of "
            f"{len(collateral)} benign connections; seq jumps over the window."
        ),
        magnitude=int(GAP_LENGTH.total_seconds()),
        magnitude_unit="seconds",
        params={
            "host": host,
            "source_key": sk,
            "window_start": fmt_ts(lo),
            "window_end": fmt_ts(hi),
            "removed_lines": len(gone),
            "first_removed_seq": min(seqs),
            "last_removed_seq": max(seqs),
            "real_source_key": s5.source_key,
            "real_record_ids_inside_window": inside,
            "unmatched_connections": [_unmatched(gone, all_auth["SRV-FILE-02"])],
        },
        detectable_by=(
            "seq discontinuity in the DC-01 auth log, plus real S5 4662 events (record ids in "
            "real_record_ids_inside_window) whose aligned time falls inside the missing window. "
            f"unmatched_connection: the SRV-FILE-02 source-side line of {link_b} has no "
            "destination-side counterpart on DC-01 (removed in the window); in the clean "
            "variant every conn_id has both ends. The removal also breaks benign connections: "
            "every conn_id in expected_collateral_conn_ids loses its DC-01 end and shows up as "
            "unmatched too (expected collateral of the gap, not a separate contradiction)"
        ),
        checks=[CHECK_SEQ_GAP, CHECK_REAL_IN_GAP, CHECK_UNMATCHED],
        expected_collateral_conn_ids=collateral,
    )
