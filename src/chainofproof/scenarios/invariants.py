"""Phase 4.1 generator invariants as library checks (used by ``scenario-verify --seed``).

They look at the GENERATED files of a seed (both variants) and report problems as plain strings:
vocabulary (G1: every value on a key line also appears on at least 5 benign lines of that host),
connections (G2: two ends, ids rise with time, key ids are not first or last), timing (G3: the
log-gap window is 720 s and does not start on a minute), filesystem (G4: no extension or depth
exclusive to referenced rows) and the exactness of the timestomp perturbation (G5).
"""

from __future__ import annotations

import ntpath
from collections import Counter, defaultdict
from pathlib import Path

from chainofproof.scenarios.companions import parse_auth_log, parse_fs_csv, parse_ts, row_marker
from chainofproof.scenarios.gen_vocab import HOSTS
from chainofproof.schemas.scenario import AnswerKey, Variant

FIELDS = ("event", "user", "service", "logon_type", "dst_host", "src_ip")
MIN_BENIGN, MIN_CONNECTIONS = 5, 60


def _slug(host: str) -> str:
    return host.lower().replace("-", "_")


def _auth(folder: Path) -> list[dict[str, str]]:
    return [ln for h in HOSTS for ln in parse_auth_log(folder / f"auth_{_slug(h)}.log")]


def _fs(folder: Path) -> list[dict[str, str]]:
    return [r for h in HOSTS for r in parse_fs_csv(folder / f"fs_{_slug(h)}.csv")]


def _vocabulary(lines: list[dict[str, str]], tag: str) -> list[str]:
    out = []
    for host in HOSTS:
        mine = [ln for ln in lines if ln["host"] == host]
        benign = [ln for ln in mine if row_marker(ln) is None]
        for field in FIELDS:
            counts = Counter(ln[field] for ln in benign if field in ln)
            for ln in (x for x in mine if row_marker(x) is not None and field in x):
                if counts[ln[field]] < MIN_BENIGN:
                    out.append(f"{tag} G1: {host}.{field} value on a key line has "
                               f"{counts[ln[field]]} benign lines")  # fmt: skip
        users = {ln["user"] for ln in benign if ln["user"] != "unknown"}
        if not 7 <= len(users) <= 10:
            out.append(f"{tag} G1: {host} has {len(users)} benign users")
    return out


def _connections(lines: list[dict[str, str]], key: AnswerKey, tag: str) -> list[str]:
    by = defaultdict(list)
    for ln in lines:
        if "conn_id" in ln:
            by[ln["conn_id"]].append(ln)
    out = []
    for cid, ends in by.items():
        src = [e for e in ends if e["event"] == "CONN_OUT"]
        if len(ends) != 2 or len(src) != 1:
            out.append(f"{tag} G2: {cid} does not have exactly two ends")
            continue
        dst = next(e for e in ends if e is not src[0])
        if not (src[0]["dst_host"] in HOSTS and dst["host"] == src[0]["dst_host"]):
            out.append(f"{tag} G2: {cid} ends do not match")
        if src[0]["ts"] != dst["ts"]:
            out.append(f"{tag} G2: {cid} ends have different times")
    ids = sorted(by)
    if [by[c][0]["ts"] for c in ids] != sorted(by[c][0]["ts"] for c in ids):
        out.append(f"{tag} G2: connection ids do not rise with time")
    link_ids = {r.conn_id for k in key.links for r in k.evidence_refs if r.conn_id}
    if ids and link_ids & {ids[0], ids[-1]}:
        out.append(f"{tag} G2: a key connection id is the first or last id")
    if len(ids) < MIN_CONNECTIONS:
        out.append(f"{tag} G2: only {len(ids)} connections")
    return out


def _filesystem(rows: list[dict[str, str]], tag: str) -> list[str]:
    benign, ref = [r for r in rows if not r["note"]], [r for r in rows if r["note"]]
    ext = lambda p: ntpath.splitext(p)[1].lower()  # noqa: E731
    out = []
    if len(ref) != 5:
        out.append(f"{tag} G4: {len(ref)} referenced file rows (expected 5)")
    exts = {ext(r["path"]) for r in benign}
    depths = {r["path"].count("\\") for r in benign}
    for r in ref:
        if ext(r["path"]) not in exts or r["path"].count("\\") not in depths:
            out.append(f"{tag} G4: a referenced row has an extension or depth no benign row has")
    return out


def _timing(key: AnswerKey) -> list[str]:
    gap = next((c for c in key.contradictions if c.kind == "log_gap"), None)
    if gap is None:
        return []
    lo, hi = parse_ts(gap.params["window_start"]), parse_ts(gap.params["window_end"])
    out = []
    if (hi - lo).total_seconds() != 720:
        out.append("perturbed G3: the log-gap window is not 720 s")
    if lo.second == 0:
        out.append("perturbed G3: the log-gap window starts on a minute")
    return out


def _timestomp(rows: list[dict[str, str]], key: AnswerKey) -> list[str]:
    p1 = next((c for c in key.contradictions if c.kind == "timestomp"), None)
    if p1 is None:
        return []
    want = {(f["record_id"], f["delta_seconds"]) for f in p1.params["files"]}
    got = set()
    for r in rows:
        d = (parse_ts(r["fn_created"]) - parse_ts(r["si_created"])).total_seconds()
        if abs(d) > 3600:
            got.add((int(r["record_id"]), int(d)))
        elif abs(d) > 3:
            return ["perturbed G5: benign si/fn jitter above 3 s"]
    return [] if got == want else ["perturbed G5: the stomped files differ from the key"]


def check_generated(dirs: dict[Variant, Path], keys: dict[Variant, AnswerKey]) -> list[str]:
    """All invariant problems of a seed's generated data (empty list = all hold)."""
    out: list[str] = []
    for v, folder in dirs.items():
        lines = _auth(folder)
        out += _vocabulary(lines, v.value)
        if v == Variant.clean:  # the perturbed log gap leaves one-ended collateral by design
            out += _connections(lines, keys[v], v.value)
        out += _filesystem(_fs(folder), v.value)
    if Variant.perturbed in keys:
        out += _timing(keys[Variant.perturbed])
        out += _timestomp(_fs(dirs[Variant.perturbed]), keys[Variant.perturbed])
    return out
