"""log_clear: an audit log was cleared (Security 1102 / System 104), with follow-on context."""

from __future__ import annotations

from collections.abc import Iterable

from chainofproof.config import LogClearParams
from chainofproof.schemas.events import EventType, NormalizedEvent
from chainofproof.tools.detectors.base import Hit, make_hit, ordered, parse_ts

NAME = "log_clear"
CONTEXT_TYPES = {
    EventType.logon, EventType.auth_logon, EventType.process_create,
    EventType.process_create_security,
}  # fmt: skip
LIMITATIONS = ["A cleared log can also be routine administration or lab preparation."]


def detect_log_clear(events: Iterable[NormalizedEvent], params: LogClearParams) -> list[Hit]:
    """One ``audit_log_cleared`` hit per clearing event, with logon/process events that follow."""
    evs = ordered(events)
    hits = []
    for ev in evs:
        if ev.event_type != EventType.audit_log_cleared:
            continue
        t0 = parse_ts(ev.timestamp)
        follow = []
        for o in evs:
            t = parse_ts(o.timestamp)
            same = o.host == ev.host and o.event_type in CONTEXT_TYPES
            if same and o.event_uid != ev.event_uid and t0 and t:
                if 0 <= (t - t0).total_seconds() <= params.window_seconds:
                    follow.append(o)
        measures = {
            "event_id": ev.event_id, "channel": ev.channel, "host": ev.host,
            "timestamp": ev.timestamp, "context_event_count": len(follow),
            "window_seconds": params.window_seconds,
        }  # fmt: skip
        text = (
            f"Audit log cleared on {ev.host} at {ev.timestamp} (event id {ev.event_id}, channel "
            f"{ev.channel}); {len(follow)} logon/process event(s) on this host within "
            f"{params.window_seconds:.0f} s after it."
        )
        hits.append(make_hit(NAME, "audit_log_cleared", "medium", [ev.host], [ev.evidence_label],
                             [ev.event_uid, *[f.event_uid for f in follow[:10]]], measures, text,
                             LIMITATIONS))  # fmt: skip
    return hits
