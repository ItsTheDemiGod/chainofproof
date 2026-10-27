"""clock_skew: two sources disagree about when the SAME thing happened.

Pairs are discovered from SHARED FIELDS only: the same ``conn_id`` (two ends of a connection) or
the same pipe name (leading backslashes ignored) in events of different evidence sources, on
timestamps truncated to whole seconds (the coarsest source has 1 s resolution). For a conn_id the
closest pair of events is used. A pipe name repeats all day, so pipe pairs must be on the same
virtual host, at most ``pair_window_seconds`` apart, and matched one-to-one by nearest time (an
event is in at most one pair). Per source, pairs that agree within
``agreement_seconds`` form a consistent offset; it is reported when at least
``min_independent_pairs`` agree and they involve 2+ partner sources or 2+ shared keys.

Disambiguation (general rule, not data specific): a clock that is wrong is wrong against EVERY
partner, while the partner merely mirrors it. Candidates are ranked by number of partner sources,
then pairs; a candidate whose pairs are already explained by a better one is dropped (and noted
as ``ambiguous_with`` when it ranked equally). Single pairs that no source offset explains are
reported as low-severity ``pair_time_offset`` hits.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from chainofproof.config import ClockSkewParams
from chainofproof.schemas.events import NormalizedEvent
from chainofproof.tools.detectors.base import Hit, make_hit, ordered, parse_ts

NAME = "clock_skew"
LIMITATIONS = [
    "Cannot tell which of the two clocks is wrong.",
    "Consistent only with the pairing keys listed; pairs rely on shared identifiers present in "
    "both sources.",
]


@dataclass(frozen=True)
class Pair:
    """Two events of different sources that share a key; ``delta`` = b minus a, whole seconds."""

    key_kind: str
    key: str
    label_a: str
    label_b: str
    uid_a: str
    uid_b: str
    host_a: str
    host_b: str
    delta: int


def _sec(ts: str) -> datetime | None:
    dt = parse_ts(ts)
    return dt.replace(microsecond=0) if dt else None


def _keys(ev: NormalizedEvent) -> list[tuple[str, str]]:
    out = []
    if ev.conn_id:
        out.append(("conn_id", ev.conn_id))
    if ev.pipe_name:
        out.append(("pipe_name", ev.pipe_name.lstrip("\\").lower()))
    return out


def discover_pairs(events: Iterable[NormalizedEvent], params: ClockSkewParams) -> list[Pair]:
    """Pairs of events sharing a key across different sources, with |delta| >= the minimum."""
    groups: dict[tuple[str, str], dict[str, list[NormalizedEvent]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for ev in ordered(events):
        for k in _keys(ev):
            groups[k][ev.evidence_label].append(ev)
    pairs = []
    for (kind, key), by_label in sorted(groups.items()):
        labels = sorted(by_label)
        for i, la in enumerate(labels):
            for lb in labels[i + 1 :]:
                cands = _candidates(kind, by_label[la], by_label[lb], params)
                for _, _, _, d, ea, eb in _chosen(kind, cands):
                    if abs(d) >= params.min_abs_delta_seconds:
                        pairs.append(Pair(kind, key, la, lb, ea.event_uid, eb.event_uid,
                                          ea.host, eb.host, d))  # fmt: skip
    return pairs


def _candidates(kind: str, evs_a: list, evs_b: list, params: ClockSkewParams) -> list[tuple]:
    """(|d|, uid_a, uid_b, d, a, b) for every event pair that may be the same thing.

    conn_id is unique per connection, so every combination counts. A pipe name is NOT unique
    (ordinary names repeat all day on every host), so a pipe pair must be on the same virtual host
    and within ``pair_window_seconds``.
    """
    out = []
    for ea in evs_a:
        for eb in evs_b:
            ta, tb = _sec(ea.timestamp), _sec(eb.timestamp)
            if ta is None or tb is None:
                continue
            d = int((tb - ta).total_seconds())
            if kind == "pipe_name" and (ea.host != eb.host or abs(d) > params.pair_window_seconds):
                continue
            out.append((abs(d), ea.event_uid, eb.event_uid, d, ea, eb))
    return sorted(out, key=lambda c: c[:3])


def _chosen(kind: str, cands: list[tuple]) -> list[tuple]:
    """conn_id: the single closest pair. Pipe name: one-to-one nearest-time matching."""
    if kind != "pipe_name":
        return cands[:1]
    used: set[str] = set()
    out = []
    for c in cands:
        if c[1] not in used and c[2] not in used:
            used.update((c[1], c[2]))
            out.append(c)
    return out


def _clusters(obs: list[tuple[int, int]], agreement: float) -> list[list[tuple[int, int]]]:
    """Group (offset, pair index) observations whose offsets stay within ``agreement`` seconds."""
    out: list[list[tuple[int, int]]] = []
    for o in sorted(obs):
        if out and o[0] - out[-1][0][0] <= agreement:
            out[-1].append(o)
        else:
            out.append([o])
    return out


def detect_clock_skew(events: Iterable[NormalizedEvent], params: ClockSkewParams) -> list[Hit]:
    """``source_offset`` hits (one source consistently off) and leftover ``pair_time_offset``."""
    evs = ordered(events)
    pairs = discover_pairs(evs, params)
    hosts: dict[str, set[str]] = defaultdict(set)
    for e in evs:
        hosts[e.evidence_label].add(e.host)
    obs: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for i, p in enumerate(pairs):
        obs[p.label_b].append((p.delta, i))
        obs[p.label_a].append((-p.delta, i))
    cands = []
    for label, o in sorted(obs.items()):
        for cl in _clusters(o, params.agreement_seconds):
            idx = [i for _, i in cl]
            partners = {
                pairs[i].label_a if pairs[i].label_b == label else pairs[i].label_b for i in idx
            }
            keys = {(pairs[i].key_kind, pairs[i].key) for i in idx}
            if len(idx) >= params.min_independent_pairs and (len(partners) >= 2 or len(keys) >= 2):
                cands.append((label, cl, idx, partners, keys))
    cands.sort(key=lambda c: (-len(c[3]), -len(c[2]), c[0]))
    explained: set[int] = set()
    hits, kept = [], []
    for label, cl, idx, partners, keys in cands:
        fresh = [i for i in idx if i not in explained]
        if len(fresh) < params.min_independent_pairs:
            for k in kept:  # equal rank mirror: say so on the kept hit
                if set(idx) <= k["idx"] and (len(partners), len(idx)) == k["rank"]:
                    k["ambiguous"].append(label)
            continue
        explained.update(idx)
        kept.append({"label": label, "cl": cl, "idx": set(idx), "partners": partners, "keys": keys,
                     "rank": (len(partners), len(idx)), "ambiguous": []})  # fmt: skip
    for k in kept:
        hits.append(_source_hit(k, pairs, hosts))
    for i, p in enumerate(pairs):
        if i not in explained:
            hits.append(_pair_hit(p))
    return hits


def _source_hit(k: dict, pairs: list[Pair], hosts: dict[str, set[str]]) -> Hit:
    label, offs = k["label"], [o for o, _ in k["cl"]]
    off = sum(offs) / len(offs)
    uids = [u for i in k["idx"] for u in (pairs[i].uid_a, pairs[i].uid_b)]
    direction = "late" if off > 0 else "early"
    shared = sorted(f"{kind}:{key}" for kind, key in k["keys"])
    measures = {
        "label": label, "hosts": sorted(hosts[label]), "offset_seconds": off,
        "direction": direction, "pair_count": len(k["idx"]),
        "partner_labels": sorted(k["partners"]), "shared_keys": shared,
        "ambiguous_with": sorted(k["ambiguous"]),
    }  # fmt: skip
    sev = "high" if abs(off) >= 60 and len(k["idx"]) >= 3 else "medium"
    text = (
        f"Source {label} (host {', '.join(sorted(hosts[label]))}) is consistently {direction} by "
        f"{abs(off):.1f} s against {len(k['partners'])} partner source(s), from {len(k['idx'])} "
        f"pair(s) sharing {len(k['keys'])} key(s)."
    )
    return make_hit(NAME, "source_offset", sev, hosts[label], [label, *k["partners"]], uids,
                    measures, text, LIMITATIONS)  # fmt: skip


def _pair_hit(p: Pair) -> Hit:
    later = p.label_b if p.delta > 0 else p.label_a
    measures = {
        "key_kind": p.key_kind, "key": p.key, "labels": sorted([p.label_a, p.label_b]),
        "later_label": later, "delta_seconds": abs(p.delta),
    }  # fmt: skip
    text = (
        f"Sources {p.label_a} and {p.label_b} record the same {p.key_kind} {p.key} "
        f"{abs(p.delta)} s apart ({later} later); a single pair."
    )
    return make_hit(NAME, "pair_time_offset", "low", [p.host_a, p.host_b], [p.label_a, p.label_b],
                    [p.uid_a, p.uid_b], measures, text, LIMITATIONS)  # fmt: skip
