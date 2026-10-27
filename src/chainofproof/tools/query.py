"""Agent-facing query API over the AGENT VIEW tables. Nothing else is reachable from here.

Every function returns agent-view objects only (opaque labels and event ids, virtual time and
hosts) and is bounded: default limit 25, hard maximum 50, always with ``total_matches`` and a
``truncated`` flag. This module must never import the evaluation package or the scenario key
modules, nor read the eval-layer table (a test scans this file's source for exactly that).
"""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from datetime import UTC, datetime

from pydantic import BaseModel

from chainofproof.config import Paths
from chainofproof.custody.db import connect
from chainofproof.errors import UserError
from chainofproof.schemas.events import AgentDetection, EventType, NormalizedEvent
from chainofproof.tools.norm_store import LATEST_RUNS

DEFAULT_LIMIT = 25
MAX_LIMIT = 50
MAX_TEXT = 100
EVENT_TYPES = frozenset(t.value for t in EventType)
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")
_JSON_COLUMNS = {"fields_json": "fields", "injection_flags_json": "injection_flags"}
_HIDDEN = {"norm_run_id", "ord"}


class QueryError(UserError):
    """A bad query argument (unknown label, malformed time)."""


class EventPage(BaseModel):
    """A bounded page of events."""

    total_matches: int
    returned: int
    truncated: bool
    events: list[NormalizedEvent]


class LabelInfo(BaseModel):
    """One evidence source as an agent may know it."""

    label: str
    source_kind: str
    hosts: list[str]
    event_count: int
    first_timestamp: str | None
    last_timestamp: str | None


class DetectionPage(BaseModel):
    """A bounded page of Hayabusa detections."""

    total_matches: int
    returned: int
    truncated: bool
    detections: list[AgentDetection]


class SourceSummary(BaseModel):
    """Small overview of one source."""

    label: str
    event_count: int
    by_event_type: dict[str, int]
    top_users: list[tuple[str, int]]
    top_processes: list[tuple[str, int]]


def _limit(limit: int | None) -> int:
    return max(1, min(limit if limit is not None else DEFAULT_LIMIT, MAX_LIMIT))


def _iso(value: str | datetime | None, name: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if not _ISO.match(value):
        raise QueryError(f"{name} must be an ISO-8601 UTC string like 2000-01-01T00:00:00Z")
    base, _, frac = value.rstrip("Z").partition(".")
    return f"{base}.{(frac or '0').ljust(6, '0')}Z"


def _like(text: str) -> str:
    if len(text) > MAX_TEXT:
        raise QueryError(f"text filter is limited to {MAX_TEXT} characters")
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _event(row: sqlite3.Row) -> NormalizedEvent:
    d = {k: row[k] for k in row.keys() if k not in _HIDDEN}  # noqa: SIM118 - sqlite3.Row
    for col, name in _JSON_COLUMNS.items():
        d[name] = json.loads(d.pop(col))
    d["truncated"] = bool(d["truncated"])
    return NormalizedEvent(**d)


event_from_row = _event  # public alias for the loader


def _page(conn: sqlite3.Connection, where: str, args: list, limit: int, offset: int = 0):
    base = f"FROM events e WHERE e.norm_run_id IN ({LATEST_RUNS}) AND {where}"
    total = conn.execute(f"SELECT COUNT(*) {base}", args).fetchone()[0]  # noqa: S608 - fixed text
    rows = conn.execute(
        f"SELECT e.* {base} ORDER BY e.timestamp, e.evidence_label, e.ord LIMIT ? OFFSET ?",  # noqa: S608
        [*args, limit, max(offset, 0)],
    ).fetchall()
    return EventPage(
        total_matches=total,
        returned=len(rows),
        truncated=total > max(offset, 0) + len(rows),
        events=[_event(r) for r in rows],
    )


def _case_args(case_id: str) -> list:
    return [case_id]


def list_evidence_labels(paths: Paths, case_id: str) -> list[LabelInfo]:
    """Sources of a case: label, kind, virtual hosts, event count, virtual time span."""
    sql = (
        "SELECT evidence_label, source_kind, COUNT(*) n, MIN(timestamp) lo, MAX(timestamp) hi "
        f"FROM events WHERE norm_run_id IN ({LATEST_RUNS}) GROUP BY evidence_label ORDER BY 1"
    )
    with closing(connect(paths.db_path)) as conn:
        rows = conn.execute(sql, _case_args(case_id)).fetchall()
        out = []
        for r in rows:
            hosts = conn.execute(
                f"SELECT DISTINCT host FROM events WHERE evidence_label = ? AND norm_run_id IN "  # noqa: S608
                f"({LATEST_RUNS}) ORDER BY host",
                [r["evidence_label"], case_id],
            ).fetchall()
            out.append(
                LabelInfo(label=r["evidence_label"], source_kind=r["source_kind"],
                          hosts=[h[0] for h in hosts], event_count=r["n"],
                          first_timestamp=r["lo"], last_timestamp=r["hi"])
            )  # fmt: skip
    return out


MAX_VALUES = 10


def _values(val, name: str) -> list | None:
    """One value or a list of up to 10 values; None or an empty list means no filter."""
    if val is None:
        return None
    vals = list(val) if isinstance(val, list | tuple) else [val]
    if len(vals) > MAX_VALUES:
        raise QueryError(f"{name} accepts at most {MAX_VALUES} values")
    return [getattr(v, "value", v) for v in vals] or None


def _in_clauses(filters: dict[str, object], prefix: str = "e") -> tuple[list[str], list]:
    """Parameterized ``col IN (?,..)`` clauses (placeholders only are string-built)."""
    clauses, args = [], []
    for col, val in filters.items():
        vals = _values(val, col)
        if vals is None:
            continue
        if col == "event_type" and any(v not in EVENT_TYPES for v in vals):
            raise QueryError("event_type must be one of the normalized event types")
        clauses.append(f"{prefix}.{col} IN ({','.join('?' * len(vals))})")
        args += vals
    return clauses, args


def search_events(
    paths: Paths, case_id: str, *, host=None, event_type=None, user=None, process_image=None,
    text: str | None = None, time_from: str | datetime | None = None,
    time_to: str | datetime | None = None, evidence_label=None, conn_id=None, event_id=None,
    limit: int | None = None, offset: int = 0,
) -> EventPage:  # fmt: skip
    """Filtered, bounded, time-ordered event search (all filters ANDed).

    host, event_type, user, process_image, evidence_label, conn_id and event_id take one value or
    a list of up to 10 values (an empty list is no filter).
    """
    clauses, args = ["1=1"], _case_args(case_id)
    exact = {
        "host": host,
        "event_type": event_type,
        "user": user,
        "process_image": process_image,
        "evidence_label": evidence_label,
        "conn_id": conn_id,
        "event_id": event_id,
    }
    more, vals = _in_clauses(exact)
    clauses += more
    args += vals
    lo, hi = _iso(time_from, "time_from"), _iso(time_to, "time_to")
    if lo:
        clauses.append("e.timestamp >= ?")
        args.append(lo)
    if hi:
        clauses.append("e.timestamp <= ?")
        args.append(hi)
    if text:
        pat = _like(text)
        clauses.append(
            "(e.summary LIKE ? ESCAPE '\\' OR e.fields_json LIKE ? ESCAPE '\\' "
            "OR e.command_line LIKE ? ESCAPE '\\')"
        )
        args += [pat, pat, pat]
    with closing(connect(paths.db_path)) as conn:
        return _page(conn, " AND ".join(clauses), args, _limit(limit), offset)


def get_event(paths: Paths, case_id: str, event_uid: str) -> NormalizedEvent | None:
    """One event by its opaque id, or None."""
    with closing(connect(paths.db_path)) as conn:
        page = _page(conn, "e.event_uid = ?", [case_id, event_uid], 1)
    return page.events[0] if page.events else None


def timeline_window(
    paths: Paths, case_id: str, host: str, start: str | datetime, end: str | datetime,
    limit: int | None = None,
) -> EventPage:  # fmt: skip
    """Events of one virtual host between two virtual times, oldest first."""
    return search_events(paths, case_id, host=host, time_from=start, time_to=end, limit=limit)


def get_detections(
    paths: Paths, case_id: str, evidence_label: str | None = None, event_uid: str | None = None,
    limit: int | None = None,
) -> DetectionPage:  # fmt: skip
    """Hayabusa detections of the latest run, by source label and/or linked event."""
    clauses, args = ["1=1"], _case_args(case_id)
    more, vals = _in_clauses({"evidence_label": evidence_label, "event_uid": event_uid}, "d")
    clauses += more
    args += vals
    base = f"FROM detections d WHERE d.norm_run_id IN ({LATEST_RUNS}) AND {' AND '.join(clauses)}"
    n = _limit(limit)
    with closing(connect(paths.db_path)) as conn:
        total = conn.execute(f"SELECT COUNT(*) {base}", args).fetchone()[0]  # noqa: S608
        rows = conn.execute(
            f"SELECT d.* {base} ORDER BY d.detection_id LIMIT ?",
            [*args, n],  # noqa: S608
        ).fetchall()
    dets = [
        AgentDetection(
            detection_id=r["detection_id"], event_uid=r["event_uid"],
            evidence_label=r["evidence_label"], rule_title=r["rule_title"], rule_id=r["rule_id"],
            level=r["level"], mitre_tags=json.loads(r["mitre_tags"]), record_id=r["record_id"],
        )
        for r in rows
    ]  # fmt: skip
    return DetectionPage(total_matches=total, returned=len(dets), truncated=total > len(dets),
                         detections=dets)  # fmt: skip


def source_summary(paths: Paths, case_id: str, evidence_label: str) -> SourceSummary:
    """Counts by event type plus the top users and processes of one source."""
    where = f"FROM events WHERE evidence_label = ? AND norm_run_id IN ({LATEST_RUNS})"
    args = [evidence_label, case_id]
    with closing(connect(paths.db_path)) as conn:
        types = conn.execute(
            f"SELECT event_type, COUNT(*) FROM events WHERE evidence_label = ? "  # noqa: S608
            f"AND norm_run_id IN ({LATEST_RUNS}) GROUP BY event_type ORDER BY 2 DESC, 1",
            args,
        ).fetchall()
        if not types:
            raise QueryError("unknown evidence label for this case")

        def top(col: str) -> list[tuple[str, int]]:
            q = (f"SELECT {col}, COUNT(*) {where} AND {col} IS NOT NULL "  # noqa: S608
                 f"GROUP BY {col} ORDER BY 2 DESC, 1 LIMIT 5")  # fmt: skip
            return [(r[0], r[1]) for r in conn.execute(q, args)]

        return SourceSummary(
            label=evidence_label, event_count=sum(t[1] for t in types),
            by_event_type={t[0]: t[1] for t in types},
            top_users=top("user"), top_processes=top("process_image"),
        )  # fmt: skip
