"""Streaming, metadata-oriented EVTX reader (python-evtx + defusedxml).

Used in Phase 2 ONLY for inventory and key-event discovery; production parsing is Hayabusa
(Phase 3). Everything read from evidence is DATA: callers get small typed fields, never raw XML.
All XML is parsed with defusedxml (entity expansion / external entities are rejected).
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from defusedxml import ElementTree as DefusedET
from defusedxml.common import DefusedXmlException
from Evtx.Evtx import Evtx

log = logging.getLogger(__name__)

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


@dataclass
class EvtxEvent:
    """The few System fields we need plus the EventData name->value mapping."""

    record_id: int
    event_id: int
    channel: str
    computer: str
    time: str  # SystemTime normalized to UTC, e.g. 2019-03-20T15:14:20.123456Z
    data: dict[str, str] = field(default_factory=dict)


@dataclass
class ReadStats:
    """Filled while iterating: how many records were skipped because they were unreadable."""

    records: int = 0
    corrupt: int = 0


def normalize_time(value: str) -> str:
    """Any ISO-8601 timestamp (python-evtx emits ``+00:00``) -> UTC ``...Z`` with microseconds."""
    dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_event_xml(xml: str) -> EvtxEvent:
    """Parse one event's XML (defusedxml). Raises ValueError/DefusedXmlException if unusable."""
    root = DefusedET.fromstring(xml)
    sysn = root.find(f"{NS}System")
    if sysn is None:
        raise ValueError("no System element")

    def txt(tag: str) -> str:
        el = sysn.find(f"{NS}{tag}")
        return (el.text or "") if el is not None else ""

    tc = sysn.find(f"{NS}TimeCreated")
    time = normalize_time(tc.get("SystemTime", "")) if tc is not None else ""
    data: dict[str, str] = {}
    ed = root.find(f"{NS}EventData")
    if ed is not None:
        for i, d in enumerate(ed):
            data[d.get("Name") or f"_{i}"] = d.text or ""
    return EvtxEvent(
        record_id=int(txt("EventRecordID")),
        event_id=int(txt("EventID")),
        channel=txt("Channel"),
        computer=txt("Computer"),
        time=time,
        data=data,
    )


def iter_events(path: Path, stats: ReadStats | None = None) -> Iterator[EvtxEvent]:
    """Yield events chunk by chunk; unreadable records are counted in ``stats.corrupt``.

    A record that cannot be decoded is skipped; if the record iterator itself breaks, the rest of
    that chunk is abandoned (counted as one corrupt record) and reading continues with the next.
    """
    stats = stats if stats is not None else ReadStats()
    name = Path(path).name
    with Evtx(str(path)) as evtx:
        for chunk in evtx.chunks():
            it = iter(chunk.records())
            while True:
                try:
                    rec = next(it)
                except StopIteration:
                    break
                except Exception:  # noqa: BLE001 - python-evtx raises many types on bad data
                    stats.corrupt += 1
                    log.warning("%s: record iterator broke; rest of chunk skipped", name)
                    break
                try:
                    ev = parse_event_xml(rec.xml())
                except Exception as e:  # noqa: BLE001 - any parse failure = corrupt record
                    stats.corrupt += 1
                    if isinstance(e, DefusedXmlException):
                        log.warning("%s: record rejected by defusedxml", name)
                    continue
                stats.records += 1
                yield ev
