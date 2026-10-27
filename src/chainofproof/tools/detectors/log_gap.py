"""log_gap: discontinuities in the sequence numbers of a sequence-numbered log (auth logs).

Every interior jump ``seq -> seq + n`` (n > 1) is reported with the interval between the last line
before and the first line after the jump, and the events from OTHER sources on the same virtual
host that fall inside that interval (they prove the host was active while the log is silent).
A gap at the very start or end of a log cannot be seen. File-system timeline record ids are NOT
checked: they may legitimately skip.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from chainofproof.config import LogGapParams
from chainofproof.schemas.events import NormalizedEvent
from chainofproof.tools.detectors.base import Hit, make_hit, ordered, parse_ts

NAME = "log_gap"
LIMITATIONS = [
    "Shows that lines are missing from this log; does not show who removed them or why.",
    "Checks sequence-numbered logs only; file-system timeline record ids may legitimately skip.",
    "A gap at the very start or end of a log cannot be seen.",
]


def detect_log_gap(events: Iterable[NormalizedEvent], params: LogGapParams) -> list[Hit]:
    """One ``sequence_gap`` hit per interior discontinuity of every auth-log source."""
    evs = ordered(events)
    logs: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for e in evs:
        if e.source_kind.value == "auth_log" and e.record_id is not None:
            logs[e.evidence_label].append(e)
    hits = []
    for label, lines in sorted(logs.items()):
        lines = sorted(lines, key=lambda e: (e.record_id, e.event_uid))
        for before, after in zip(lines, lines[1:], strict=False):
            missing = after.record_id - before.record_id - 1
            if missing > 0:
                hits.append(_hit(label, before, after, missing, evs, params))
    return hits


def _hit(label: str, before: NormalizedEvent, after: NormalizedEvent, missing: int,
         evs: list[NormalizedEvent], params: LogGapParams) -> Hit:  # fmt: skip
    t1, t2 = parse_ts(before.timestamp), parse_ts(after.timestamp)
    hosts = {before.host, after.host}
    lo, hi = before.timestamp, after.timestamp
    inside = [
        e for e in evs if e.evidence_label != label and e.host in hosts and lo <= e.timestamp <= hi
    ]
    counts: dict[str, int] = defaultdict(int)
    for e in inside:
        counts[f"{e.evidence_label}/{e.event_type.value}"] += 1
    first, last = before.record_id + 1, after.record_id - 1
    secs = (t2 - t1).total_seconds() if t1 and t2 else 0.0
    measures = {
        "label": label, "host": before.host, "first_missing_seq": first, "last_missing_seq": last,
        "missing_count": missing, "last_ts_before": before.timestamp,
        "first_ts_after": after.timestamp, "interval_seconds": secs,
        "other_source_event_total": len(inside), "other_source_events_inside": dict(counts),
    }  # fmt: skip
    text = (
        f"Log {label} on {before.host} jumps from seq {before.record_id} to {after.record_id}: "
        f"{missing} line(s) missing (seq {first}-{last}) in the {secs:.0f} s between "
        f"{before.timestamp} and {after.timestamp}; {len(inside)} event(s) from other sources "
        f"on this host fall inside that interval."
    )
    listed = [e.event_uid for e in inside[: params.max_other_events_listed]]
    return make_hit(NAME, "sequence_gap", "high" if inside else "medium", hosts, [label],
                    [before.event_uid, after.event_uid, *listed], measures, text,
                    LIMITATIONS)  # fmt: skip
