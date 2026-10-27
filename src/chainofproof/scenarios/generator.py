"""Deterministic generator of the SYNTHETIC companion sources and their perturbations.

Inputs: scenario.yaml, inventory.json (key events) and the scenario seed. No wall clock, no uuid,
no system randomness: the same inputs give byte-identical files. The perturbed variant is the
clean data plus exactly three recorded perturbations:

* P1 timestomp: si_created/si_modified of the two S4 PsExec binaries on SRV-FILE-02 (the renamed
  svchost.exe and PsExec.exe) moved back to 2021-06-15 while fn_* keep the true drop time.
* P2 clock skew: every auth line of SRV-FILE-02 shifted +420 s.
* P3 log gap: all DC-01 auth lines in a 12-minute window around the DCSync event removed
  (seq is NOT renumbered, so the jump is visible).

Every synthetic attacker record is paired with real events or marked synthetic_only (rule R1).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

from chainofproof.custody.hashing import sha256_bytes
from chainofproof.scenarios.companions import Pairing, fmt_ts, parse_ts
from chainofproof.scenarios.gen_auth import AuthResult, generate_auth, render_auth
from chainofproof.scenarios.gen_context import GenContext
from chainofproof.scenarios.gen_fs import ATTACKER_DATE, FsResult, generate_fs, render_fs
from chainofproof.scenarios.inventory import Inventory
from chainofproof.schemas.scenario import (
    ContradictionKind,
    GroundTruthContradiction,
    Scenario,
    Variant,
)

HOSTS = ("WS-FIN-07", "SRV-FILE-02", "DC-01")
SKEW_SECONDS = 420
GAP_BEFORE, GAP_LENGTH = timedelta(minutes=4), timedelta(minutes=12)
STOMPED_TAGS = ("renamed_svchost", "psexec_client")
# check names that tests/oracles.py proves to work on the generated data
CHECK_SI_FN, CHECK_PAIRED_DELTA = "si_fn_mismatch", "paired_line_time_delta"
CHECK_SEQ_GAP, CHECK_REAL_IN_GAP = "seq_discontinuity", "real_events_inside_gap"


def slug(host: str) -> str:
    """Host name -> source_key suffix (WS-FIN-07 -> ws_fin_07)."""
    return host.lower().replace("-", "_")


@dataclass
class GenResult:
    """What was generated: file hashes, where attacker artifacts/lines are, contradictions."""

    hashes: dict[str, str]
    fs_ids: dict[str, tuple[str, int]] = field(default_factory=dict)  # tag -> (source_key, id)
    auth_seq: dict[str, tuple[str, int]] = field(default_factory=dict)  # present lines only
    pairings: dict[str, Pairing] = field(default_factory=dict)  # tag -> pairing (fs and auth)
    contradictions: list[GroundTruthContradiction] = field(default_factory=list)


def _src(ctx: GenContext, stage_id: str) -> str:
    """Source key of the real file that belongs to a stage."""
    return ctx.inventory.keys_for(stage_id).source_key


def _timestomp(ctx: GenContext, fs: FsResult, host: str) -> GroundTruthContradiction:
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


def _skew(ctx: GenContext, auth: AuthResult, host: str) -> GroundTruthContradiction:
    sk, paired = f"auth_{slug(host)}", []
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
        description=f"Every auth-log line of {host} is {SKEW_SECONDS} s later than reality.",
        magnitude=SKEW_SECONDS,
        magnitude_unit="seconds",
        params={
            "host": host,
            "source_key": sk,
            "shift_seconds": SKEW_SECONDS,
            "lines_shifted": len(auth.lines),
            "paired_lines": paired,
        },
        detectable_by=(
            "paired lines: each NAMED_PIPE_OPEN line carries pair=pipe_name:<name>, the pipe name "
            "of a real S4 Sysmon 18 event; after the alignment layer the line time minus the real "
            "event time (whole seconds) is 0 s in the clean variant and +420 s in the perturbed "
            "variant for every paired line"
        ),
        checks=[CHECK_PAIRED_DELTA],
    )


def _gap(ctx: GenContext, auth: AuthResult, host: str) -> GroundTruthContradiction:
    key_ts = parse_ts(next(ln["ts"] for ln in auth.lines if ln["event"].startswith("DIRECTORY")))
    lo = key_ts - GAP_BEFORE
    hi = lo + GAP_LENGTH
    gone = [ln for ln in auth.lines if lo <= parse_ts(ln["ts"]) < hi]
    auth.lines[:] = [ln for ln in auth.lines if ln not in gone]
    seqs = [int(ln["seq"]) for ln in gone]
    sk, s5 = f"auth_{slug(host)}", ctx.inventory.keys_for("S5")
    inside = [
        e.record_id for e in s5.result.events if lo <= ctx.virt(s5.source_key, e.real_time) < hi
    ]
    return GroundTruthContradiction(
        id="GT-CON-003",
        kind=ContradictionKind.log_gap,
        sources_involved=[sk, s5.source_key],
        description=(
            f"All {host} auth-log lines in a 12-minute window containing the DCSync event are "
            "missing; seq jumps over the window."
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
        },
        detectable_by=(
            "seq discontinuity in the DC-01 auth log, plus real S5 4662 events (record ids in "
            "real_record_ids_inside_window) whose aligned time falls inside the missing window"
        ),
        checks=[CHECK_SEQ_GAP, CHECK_REAL_IN_GAP],
    )


def generate_variant(
    scenario: Scenario, inventory: Inventory, variant: Variant, out_dir: Path
) -> GenResult:
    """Write the companion files of one variant into out_dir; returns hashes and bookkeeping."""
    ctx = GenContext(scenario, inventory)
    texts: dict[str, str] = {}
    res = GenResult(hashes={})
    for host in HOSTS:
        fs, auth = generate_fs(ctx, host), generate_auth(ctx, host)
        fsk, auk = f"fs_{slug(host)}", f"auth_{slug(host)}"
        if variant == Variant.perturbed:
            if host == "SRV-FILE-02":
                res.contradictions.append(_timestomp(ctx, fs, host))
                res.contradictions.append(_skew(ctx, auth, host))
            if host == "DC-01":
                res.contradictions.append(_gap(ctx, auth, host))
        texts[scenario.source(fsk).relative_path] = render_fs(ctx, fs.rows)
        texts[scenario.source(auk).relative_path] = render_auth(ctx, auth.lines)
        res.fs_ids.update({t: (fsk, i) for t, i in fs.artifacts.items()})
        res.auth_seq.update({t: (auk, s) for t, s in auth.key_seq.items() if _present(auth, s)})
        res.pairings.update(fs.pairings)
        res.pairings.update(auth.pairings)
    res.contradictions.sort(key=lambda c: c.id)
    out_dir.mkdir(parents=True, exist_ok=True)
    for rel in sorted(texts):
        data = texts[rel].encode("utf-8")
        (out_dir / rel).write_bytes(data)
        res.hashes[rel] = sha256_bytes(data)
    return res


def _present(auth: AuthResult, seq: int) -> bool:
    return any(int(ln["seq"]) == seq for ln in auth.lines)
