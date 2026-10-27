"""EVALUATION ONLY, REPORT ONLY: can key-referenced synthetic lines be told apart by style?

"Referenced" lines are the synthetic lines (auth logs, file-system timelines) named anywhere in
the answer key (GT-ACT, GT-LNK, GT-CON, adjudication); "benign" lines are all the others.

Verdict rule (fixed before the first run), applied identically to every feature after turning it
into a categorical bucket: ``coverage`` = share of referenced lines whose bucket value occurs in NO
benign line of the same source kind.  coverage >= 0.5 -> "separates cleanly"; 0 < coverage < 0.5
-> "weak"; coverage == 0 -> "none". Counts only, no statistical tests (about 20 referenced lines).
Nothing is changed in the generator by this module.
"""

from __future__ import annotations

import math
import ntpath
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from chainofproof.config import Paths
from chainofproof.eval.gt_link import (
    EvalIndex,
    build_index,
    contradiction_refs,
    key_action_refs,
)
from chainofproof.scenarios.dataset import scenario_dir
from chainofproof.scenarios.source_map import load_case_scenario
from chainofproof.schemas.scenario import load_key

Row = dict[str, Any]
CLEAN_AT, SOME_AT = 0.5, 0.0
RECOMMEND = {
    "event": "Draw benign event names from the same pool the key lines use (e.g. add benign "
    "CONN_OUT/CONN_ACCEPTED and NAMED_PIPE_OPEN lines).",
    "user": "Use the same account vocabulary for benign and key lines (the key lines use `user01`, "
    "`unknown` or machine names that no benign line uses).",
    "src_ip": "Draw benign source addresses from the virtual hosts' own addresses as well.",
    "dst_host": "Let benign connection lines target the same hosts as key lines.",
    "logon_type": "Make benign logon types overlap with the key lines'.",
    "service": "Give benign lines the same optional fields (service=smb/drsuapi) as key lines.",
    "key_presence": "Make the set of keys per line identical across benign and key lines.",
    "name_stem": "Generate benign file names from a vocabulary that includes tool-like names "
    "(and avoid names that appear only in key rows).",
    "extension": "Give benign files the same extensions as the key files (.exe, .pf, .txt).",
    "dir_prefix": "Place benign files in the same directories as the key files.",
    "depth": "Match path depth distributions.",
    "size_bucket": "Match file size distributions.",
}


def _ts(r: Row) -> str:
    return r["timestamp"]


AUTH_FEATURES: dict[str, Callable[[Row], Any]] = {
    "event": lambda r: r["fields"].get("auth_event"),
    "user": lambda r: r["user"],
    "logon_type": lambda r: r["logon_type"],
    "service": lambda r: r["fields"].get("service"),
    "dst_host": lambda r: r["dst_host"],
    "src_ip": lambda r: r["src_ip"],
    "key_presence": lambda r: ",".join(
        sorted(
            [k for k in r["fields"] if k != "auth_event"]
            + [
                c
                for c in (
                    "user",
                    "logon_type",
                    "logon_id",
                    "src_ip",
                    "dst_host",
                    "conn_id",
                    "pipe_name",
                )
                if r[c]
            ]
        )
    ),  # fmt: skip
    "second_of_minute": lambda r: _ts(r)[17:19],
    "minute_of_hour": lambda r: _ts(r)[14:16],
    "zero_microseconds": lambda r: _ts(r)[20:26] == "000000",
}
FS_FEATURES: dict[str, Callable[[Row], Any]] = {
    "extension": lambda r: ntpath.splitext(r["file_path"] or "")[1].lower(),
    "dir_prefix": lambda r: "\\".join((r["file_path"] or "").lower().split("\\")[:3]),
    "depth": lambda r: (r["file_path"] or "").count("\\"),
    "size_bucket": lambda r: int(math.log10(max(int(r["fields"].get("size", "1")), 1))),
    "name_stem": lambda r: re.sub(
        r"[\d_\-\.]+$|\d+", "", ntpath.splitext(ntpath.basename(r["file_path"] or ""))[0].lower()
    ),
    "second_of_minute": lambda r: _ts(r)[17:19],
    "minute_of_hour": lambda r: _ts(r)[14:16],
    "zero_microseconds": lambda r: _ts(r)[20:26] == "000000",
}


@dataclass
class Feature:
    """Result for one feature of one source kind."""

    kind: str
    name: str
    coverage: float
    verdict: str
    ref_only: list[tuple[str, int, int]]  # (value, referenced count, benign count)
    ref_values: int
    benign_only_values: int


@dataclass
class Audit:
    """Style audit of one case."""

    case_id: str
    counts: dict[str, tuple[int, int]] = field(default_factory=dict)  # kind -> (ref, benign)
    features: list[Feature] = field(default_factory=list)
    position: dict[str, tuple[list[int], list[int]]] = field(default_factory=dict)

    def clean(self) -> list[Feature]:
        """Features that separate cleanly."""
        return [f for f in self.features if f.verdict == "separates cleanly"]

    def summary_text(self) -> str:
        """Plain-text summary."""
        lines = [f"{self.case_id}: " + ", ".join(
            f"{k}: {r} referenced / {b} benign" for k, (r, b) in self.counts.items())]  # fmt: skip
        for f in self.features:
            lines.append(f"  {f.kind}.{f.name}: {f.verdict} (coverage {f.coverage:.2f}, "
                         f"{len(f.ref_only)} referenced-only values)")  # fmt: skip
        return "\n".join(lines)


def verdict(coverage: float) -> str:
    """Apply the fixed rule."""
    if coverage >= CLEAN_AT:
        return "separates cleanly"
    return "weak" if coverage > SOME_AT else "none"


def _referenced(idx: EvalIndex, key) -> set[str]:
    refs = {(r.source_key, r.event_record_id) for _, r in key_action_refs(key)}
    refs |= {(r.source_key, r.event_record_id) for ln in key.links for r in ln.evidence_refs}
    refs |= {(sk, rid) for _, sk, rid, present in contradiction_refs(key) if present}
    return {u for sk, rid in refs for u in idx.uids(sk, rid)}


def audit_features(
    kind: str, feats: dict[str, Callable[[Row], Any]], ref: list[Row], ben: list[Row]
) -> list[Feature]:
    """Evaluate every feature on referenced vs benign rows of one source kind."""
    out = []
    for name, fn in feats.items():
        rc, bc = Counter(str(fn(r)) for r in ref), Counter(str(fn(r)) for r in ben)
        only = sorted(
            ((v, n, 0) for v, n in rc.items() if v not in bc), key=lambda t: (-t[1], t[0])
        )
        cov = sum(n for _, n, _ in only) / len(ref) if ref else 0.0
        out.append(Feature(kind, name, cov, verdict(cov), only[:8], len(rc),
                           sum(1 for v in bc if v not in rc)))  # fmt: skip
    return out


def _position(rows: list[Row], uids: set[str]) -> tuple[list[int], list[int]]:
    """Decile (0-9) of record_id inside its source for referenced vs benign rows."""
    top: dict[str, int] = {}
    for r in rows:
        top[r["evidence_label"]] = max(top.get(r["evidence_label"], 1), r["record_id"] or 1)
    ref, ben = [0] * 10, [0] * 10
    for r in rows:
        d = min(int((r["record_id"] or 1) * 10 / (top[r["evidence_label"]] + 1)), 9)
        (ref if r["event_uid"] in uids else ben)[d] += 1
    return ref, ben


def audit_case(paths: Paths, case_id: str) -> Audit:
    """Audit the synthetic sources of one case."""
    scn, variant = load_case_scenario(case_id)
    key = load_key(scenario_dir(scn.scenario_id) / f"key_{variant.value}.yaml", scn)
    idx = build_index(paths, case_id)
    refs = _referenced(idx, key)
    a = Audit(case_id)
    for kind, feats in (("auth_log", AUTH_FEATURES), ("fs_timeline", FS_FEATURES)):
        rows = [idx.row(u) for u in idx.rows if idx.rows[u]["source_kind"] == kind]
        ref = [r for r in rows if r["event_uid"] in refs]
        ben = [r for r in rows if r["event_uid"] not in refs]
        a.counts[kind] = (len(ref), len(ben))
        a.position[kind] = _position(rows, refs)
        a.features += audit_features(kind, feats, ref, ben)
        pos_cov = sum(n for n, b in zip(*a.position[kind], strict=True) if b == 0) / max(
            len(ref), 1
        )
        a.features.append(Feature(kind, "position_decile", pos_cov, verdict(pos_cov), [],
                                  sum(1 for n in a.position[kind][0] if n), 0))  # fmt: skip
    return a


def render(audits: list[Audit]) -> str:
    """docs/style_audit.md text."""
    lines = ["# Style-tell audit (report only)", "", __doc__.split("\n\n", 1)[1].strip(), "",
             "`si_*` vs `fn_*` differences are not listed as a feature: they ARE the planted "
             "timestomp perturbation, not a style tell.", ""]  # fmt: skip
    for a in audits:
        lines += [f"## {a.case_id}", ""]
        lines += [
            f"* {k}: {r} referenced lines, {b} benign lines" for k, (r, b) in a.counts.items()
        ]
        lines += ["", "| source | feature | verdict | coverage | referenced-only (ref/ben) |"]
        lines.append("|---|---|---|---|---|")
        for f in a.features:
            vals = "; ".join(f"{v} ({n}/{b})" for v, n, b in f.ref_only) or "-"
            lines.append(f"| {f.kind} | {f.name} | {f.verdict} | {f.coverage:.2f} | {vals} |")
        for k, (r, b) in a.position.items():
            lines += ["", f"Position deciles ({k}), referenced: {r}; benign: {b}"]
        lines.append("")
    seen: dict[str, str] = {}
    for a in audits:
        for f in a.clean():
            seen.setdefault(f.name, RECOMMEND.get(f.name, "Review how this field is generated."))
    lines += ["## Features that separate cleanly (in at least one case)", ""]
    lines += [f"* {n}" for n in sorted(seen)] or ["* none"]
    lines += ["", "## Recommended generator changes (NOT applied; ordered by number of cases)", ""]
    order = sorted(seen, key=lambda n: -sum(any(f.name == n for f in a.clean()) for a in audits))
    lines += [f"{i}. `{n}`: {seen[n]}" for i, n in enumerate(order, 1)] or ["None needed."]
    return "\n".join(lines) + "\n"


def write_audit(path: Path, audits: list[Audit]) -> None:
    """Write docs/style_audit.md."""
    Path(path).write_text(render(audits), encoding="utf-8", newline="\n")
