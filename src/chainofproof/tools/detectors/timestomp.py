"""timestomp: $STANDARD_INFORMATION vs $FILE_NAME times inside ONE file-system timeline record.

Window: ordinary jitter between the two sets is seconds; ``min_delta_seconds`` (default 3600) is
far beyond it. This check compares the two timestamp sets of the same record only; it makes no
cross-source claim.
"""

from __future__ import annotations

import ntpath
from collections.abc import Iterable

from chainofproof.config import TimestompParams
from chainofproof.schemas.events import EventType, NormalizedEvent
from chainofproof.tools.detectors.base import Hit, make_hit, ordered, parse_ts

NAME = "timestomp"
PAIRS = ("created", "modified", "accessed", "changed")
LIMITATIONS = [
    "A mismatch can occur through legitimate file moves or restores; this check alone does not "
    "show intent.",
    "Compares the two timestamp sets inside one file-system record only.",
]


def _deltas(ev: NormalizedEvent) -> dict[str, float] | None:
    out = {}
    for p in PAIRS:
        si, fn = parse_ts(ev.fields.get(f"si_{p}", "")), parse_ts(ev.fields.get(f"fn_{p}", ""))
        if si is None or fn is None:
            return None
        out[p] = (fn - si).total_seconds()
    return out


def detect_timestomp(events: Iterable[NormalizedEvent], params: TimestompParams) -> list[Hit]:
    """One ``si_fn_mismatch`` hit per file record whose si_*/fn_* times differ enough."""
    hits = []
    for ev in ordered(events):
        if ev.event_type != EventType.file_timeline:
            continue
        deltas = _deltas(ev)
        if deltas is None:
            continue
        diff = {p: d for p, d in deltas.items() if abs(d) >= params.min_delta_seconds}
        if not diff:
            continue
        mx = max(abs(d) for d in diff.values())
        if all(d > 0 for d in diff.values()):
            direction = "si_earlier_than_fn"
        elif all(d < 0 for d in diff.values()):
            direction = "si_later_than_fn"
        else:
            direction = "mixed"
        sev = "high" if direction == "si_earlier_than_fn" and mx >= 86400 else "medium"
        name = ntpath.basename(ev.file_path or "") or "?"
        measures = {
            "file": name, "host": ev.host, "record_id": ev.record_id, "max_delta_seconds": mx,
            "pairs_differing": sorted(diff), "direction": direction,
            "deltas_by_pair": {p: deltas[p] for p in sorted(diff)},
        }  # fmt: skip
        text = (
            f"File {name} on {ev.host} (record {ev.record_id}): {len(diff)} of 4 "
            f"$STANDARD_INFORMATION/$FILE_NAME time pairs differ, by up to {mx:.0f} s "
            f"({mx / 86400:.1f} days); direction {direction}."
        )
        hits.append(make_hit(NAME, "si_fn_mismatch", sev, [ev.host], [ev.evidence_label],
                             [ev.event_uid], measures, text, LIMITATIONS))  # fmt: skip
    return hits
