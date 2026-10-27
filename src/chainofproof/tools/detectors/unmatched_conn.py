"""unmatched_connection: a connection id seen at only one end.

A connection has a source end (``CONN_OUT``) and a destination end (``CONN_ACCEPTED`` or
``LOGON_SUCCESS``) that share one ``conn_id``. When only one end exists the hit says which; if the
host that should hold the missing end has a ``sequence_gap`` hit whose interval contains the
present end's time, the gap hit is named as a possible explanation (generic rule).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from chainofproof.config import LogGapParams, UnmatchedConnectionParams
from chainofproof.schemas.events import EventType, NormalizedEvent
from chainofproof.tools.detectors.base import Hit, make_hit, ordered
from chainofproof.tools.detectors.log_gap import detect_log_gap

NAME = "unmatched_connection"
SOURCE_EVENTS = {"CONN_OUT"}
DEST_EVENTS = {"CONN_ACCEPTED", "LOGON_SUCCESS"}
LIMITATIONS = ["Absence of a line does not prove the connection did not happen."]


def detect_unmatched_connection(
    events: Iterable[NormalizedEvent], params: UnmatchedConnectionParams
) -> list[Hit]:
    """One ``missing_counterpart`` hit per conn_id that has exactly one of its two ends."""
    evs = ordered(events)
    groups: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for e in evs:
        if e.conn_id and e.event_type in (EventType.auth_conn, EventType.auth_logon):
            groups[e.conn_id].append(e)
    gaps = detect_log_gap(evs, LogGapParams())
    hits = []
    for cid, group in sorted(groups.items()):
        src = [e for e in group if e.fields.get("auth_event") in SOURCE_EVENTS]
        dst = [e for e in group if e.fields.get("auth_event") in DEST_EVENTS]
        if bool(src) == bool(dst):
            continue
        present, side = (src, "source") if src else (dst, "destination")
        first = present[0]
        expected = first.dst_host if side == "source" else None
        why = _explanation(gaps, expected, first.timestamp)
        measures = {
            "conn_id": cid, "present_end": side, "present_host": first.host,
            "present_event": first.fields.get("auth_event"), "present_time": first.timestamp,
            "expected_missing_host": expected, "possible_explanation_hit_key": why,
        }  # fmt: skip
        text = (
            f"Connection {cid}: only the {side} end is present (host {first.host}, "
            f"{first.timestamp}); the other end is expected on "
            f"{expected or 'an unknown host'}."
            + (" A sequence gap on that host covers the present end's time." if why else "")
        )
        hits.append(make_hit(NAME, "missing_counterpart", "low" if why else "medium", [first.host],
                             [e.evidence_label for e in present], [e.event_uid for e in present],
                             measures, text, LIMITATIONS))  # fmt: skip
    return hits


def _explanation(gaps: list[Hit], host: str | None, ts: str) -> str | None:
    for g in gaps:
        m = g.measures
        if host and m["host"] == host and m["last_ts_before"] <= ts <= m["first_ts_after"]:
            return g.hit_key
    return None
