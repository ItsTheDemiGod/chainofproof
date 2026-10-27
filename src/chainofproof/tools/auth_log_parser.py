"""Auth / network log (SYNTHETIC companion, ``key=value`` lines) -> normalized events.

Same ``#`` handling as the file-system parser; malformed lines are rejected with the line number
only. ``LOGON_*`` lines become ``auth_logon``, ``CONN_*`` lines ``auth_conn``, everything else
``other``. The ``seq`` field stays as ``record_id``. ``synth_only`` and ``pair`` markers are
moved to the eval layer and never reach the agent view.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from chainofproof.ingest.sanitize import DEFAULT_MAX, FIELD_MAX, clean, sanitize
from chainofproof.schemas.common import CONN_ID_PATTERN
from chainofproof.schemas.events import EventEvalMeta, EventType, NormalizedEvent
from chainofproof.tools.fs_timeline_parser import content_lines, split_note
from chainofproof.tools.parse_common import (
    ParseContext,
    ParseError,
    build_summary,
    clean_ip,
    fmt_virtual,
    make_event_uid,
)

REQUIRED = ("seq", "ts", "host", "event")
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_CONN = re.compile(CONN_ID_PATTERN)
MAPPED = {"seq", "ts", "host", "event", "user", "src_ip", "dst_host", "logon_type", "logon_id",
          "conn_id", "pipe", "synth_only", "pair"}  # fmt: skip


def parse_line(no: int, line: str) -> dict[str, str]:
    """Split one line into a key -> value dict; raises ParseError naming the line number."""
    row: dict[str, str] = {}
    for tok in line.split():
        k, sep, v = tok.partition("=")
        if not sep or not k or not v or k in row:
            raise ParseError(f"line {no}: malformed key=value token")
        row[k] = v
    missing = [k for k in REQUIRED if k not in row]
    if missing or not row["seq"].isdigit():
        raise ParseError(f"line {no}: missing or invalid required field")
    if not _TS.match(row["ts"]):
        raise ParseError(f"line {no}: invalid timestamp")
    if "conn_id" in row and not _CONN.match(row["conn_id"]):
        raise ParseError(f"line {no}: invalid conn_id")
    return row


def _event_type(name: str) -> EventType:
    if name.startswith("LOGON_"):
        return EventType.auth_logon
    return EventType.auth_conn if name.startswith("CONN_") else EventType.other


def _marker(row: dict[str, str]) -> tuple[bool, str | None, str | None]:
    if row.get("synth_only") == "1":
        return True, None, None
    return split_note(f"pair={row['pair']}") if "pair" in row else (False, None, None)


def iter_auth_log(path: Path, ctx: ParseContext) -> Iterator[tuple[NormalizedEvent, EventEvalMeta]]:
    """Yield (event, meta) per line in file order."""
    for no, line in content_lines(path):
        row = parse_line(no, line)
        if row["host"] not in ctx.virtual_hosts:
            raise ParseError(f"line {no}: unknown virtual host")
        ts = datetime.strptime(row["ts"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        user = clean(row.get("user", ""), 128)
        fields = {"auth_event": clean(row["event"], 64)}
        trunc = False
        for k, v in row.items():
            if k not in MAPPED:
                fields[clean(k, 64)], t, _ = sanitize(v, FIELD_MAX)
                trunc = trunc or t
        pipe, t, _ = sanitize(row.get("pipe", ""), DEFAULT_MAX)
        uid = make_event_uid(ctx.evidence_sha256, f"auth:{row['seq']}")
        ev = NormalizedEvent(
            event_uid=uid,
            evidence_label=ctx.label,
            source_kind=ctx.source_kind,
            host=row["host"],
            timestamp=fmt_virtual(ts + ctx.offset),
            event_type=_event_type(row["event"]),
            record_id=int(row["seq"]),
            user=None if user in ("", "unknown") else user,
            logon_type=clean(row.get("logon_type", ""), 16) or None,
            logon_id=clean(row.get("logon_id", ""), 64).lower() or None,
            src_ip=clean_ip(row.get("src_ip")),
            dst_host=clean(row.get("dst_host", ""), 128) or None,
            conn_id=row.get("conn_id"),
            pipe_name=pipe or None,
            fields=fields,
            truncated=trunc or t,
        )
        ev.summary = build_summary(ev)
        synth, pf, pv = _marker(row)
        meta = EventEvalMeta(
            event_uid=uid,
            source_key=ctx.source_key,
            evidence_id=ctx.evidence_id,
            locator=f"auth:{row['seq']}",
            synth_only=synth,
            pair_field=pf,
            pair_value=pv,
            is_synthetic=ctx.is_synthetic,
            raw_note=" ".join(f"{k}={row[k]}" for k in ("pair", "synth_only") if k in row) or None,
        )
        ctx.stats.records += 1
        yield ev, meta
