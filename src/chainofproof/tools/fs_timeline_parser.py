"""File-system timeline CSV (SYNTHETIC companion) -> normalized events.

``#`` comment lines and blank lines are skipped; malformed rows are rejected with an error that
names the line number only (never the content). One ``file_timeline`` event per row; ALL eight
$STANDARD_INFORMATION / $FILE_NAME timestamps stay in ``fields`` because the Phase 4 timestomp
detector needs them. The ``note`` column (a pairing marker) is moved to the eval layer.
"""

from __future__ import annotations

import csv
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from chainofproof.ingest.sanitize import DEFAULT_MAX, FIELD_MAX, sanitize
from chainofproof.schemas.events import EventEvalMeta, EventType, NormalizedEvent
from chainofproof.tools.parse_common import (
    ParseContext,
    ParseError,
    build_summary,
    fmt_virtual,
    make_event_uid,
)

COLUMNS = [
    "record_id", "host", "path", "size",
    "si_created", "si_modified", "si_accessed", "si_changed",
    "fn_created", "fn_modified", "fn_accessed", "fn_changed", "note",
]  # fmt: skip
TIME_COLUMNS = COLUMNS[4:12]
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_MARK_PAIR = re.compile(r"^pair=([^:\s]+):(.+)$")


def content_lines(path: Path) -> list[tuple[int, str]]:
    """(line number, line) for non-blank, non-``#`` lines."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise ParseError(f"cannot read text file ({type(e).__name__})") from None
    return [(i, ln) for i, ln in enumerate(text.splitlines(), 1) if ln.strip() and ln[0] != "#"]


def split_note(note: str) -> tuple[bool, str | None, str | None]:
    """(synth_only, pair_field, pair_value) from a marker; plain text yields all-empty."""
    if note == "synth_only=1":
        return True, None, None
    m = _MARK_PAIR.match(note)
    return (False, m.group(1), m.group(2)) if m else (False, None, None)


def _ts(value: str, line_no: int) -> datetime:
    if not _TS.match(value):
        raise ParseError(f"line {line_no}: invalid timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _row(line_no: int, line: str) -> dict[str, str]:
    try:
        rec = next(csv.reader([line]))
    except (csv.Error, StopIteration):
        raise ParseError(f"line {line_no}: malformed CSV row") from None
    if len(rec) != len(COLUMNS) or not rec[0].isdigit() or not rec[3].isdigit():
        raise ParseError(f"line {line_no}: malformed row")
    return dict(zip(COLUMNS, rec, strict=True))


def iter_fs_timeline(
    path: Path, ctx: ParseContext
) -> Iterator[tuple[NormalizedEvent, EventEvalMeta]]:
    """Yield (event, meta) per row in file order; raises ParseError naming the line number."""
    lines = content_lines(path)
    if not lines:
        return
    if next(csv.reader([lines[0][1]]), []) != COLUMNS:
        raise ParseError(f"line {lines[0][0]}: unexpected CSV header")
    for no, line in lines[1:]:
        row = _row(no, line)
        times = {c: _ts(row[c], no) for c in TIME_COLUMNS}
        if row["host"] not in ctx.virtual_hosts:
            raise ParseError(f"line {no}: unknown virtual host")
        fpath, trunc, _ = sanitize(row["path"], DEFAULT_MAX)
        fields = {c: row[c] for c in TIME_COLUMNS + ["size", "record_id"]}
        fields["path"], t2, _ = sanitize(row["path"], FIELD_MAX)
        uid = make_event_uid(ctx.evidence_sha256, f"fs:{row['record_id']}")
        ev = NormalizedEvent(
            event_uid=uid,
            evidence_label=ctx.label,
            source_kind=ctx.source_kind,
            host=row["host"],
            timestamp=fmt_virtual(times["fn_created"] + ctx.offset),
            event_type=EventType.file_timeline,
            record_id=int(row["record_id"]),
            file_path=fpath,
            fields=fields,
            truncated=trunc or t2,
        )
        ev.summary = build_summary(ev)
        synth, pf, pv = split_note(row["note"])
        meta = EventEvalMeta(
            event_uid=uid,
            source_key=ctx.source_key,
            evidence_id=ctx.evidence_id,
            locator=f"fs:{row['record_id']}",
            real_timestamp=None,
            synth_only=synth,
            pair_field=pf,
            pair_value=pv,
            is_synthetic=ctx.is_synthetic,
            raw_note=row["note"] or None,
        )
        ctx.stats.records += 1
        yield ev, meta
