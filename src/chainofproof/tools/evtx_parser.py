"""EVTX -> normalized events (python-evtx + defusedxml ONLY; never plain xml.etree).

A pure function of (path, context): it streams records, tolerates corrupt ones (counted in
``ctx.stats.corrupt``) and never touches the database. Both XML layouts are handled: ``EventData``
(named ``Data`` elements) and ``UserData`` (child elements of its single child, e.g. Security 1102).
The raw XML is never stored or logged; only sanitized, size-capped structured fields leave here.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from defusedxml import ElementTree as DefusedET
from Evtx.Evtx import Evtx

from chainofproof.ingest.sanitize import COMMAND_MAX, clean, sanitize
from chainofproof.schemas.events import EventEvalMeta, EventType, NormalizedEvent
from chainofproof.tools.parse_common import (
    ParseContext,
    ParseError,
    add_fields,
    basename,
    build_summary,
    clean_ip,
    fmt_virtual,
    make_event_uid,
    to_int,
)

log = logging.getLogger(__name__)
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
SYSMON = "microsoft-windows-sysmon/operational"
_SVC = re.compile(r"\\services\\([^\\]+)\\", re.IGNORECASE)

ET = EventType
EVENT_TYPES: dict[tuple[str, int], EventType] = {
    (SYSMON, 1): ET.process_create,
    (SYSMON, 3): ET.network_connect,
    (SYSMON, 7): ET.image_load,
    (SYSMON, 10): ET.process_access,
    (SYSMON, 11): ET.file_create,
    (SYSMON, 12): ET.registry_set,
    (SYSMON, 13): ET.registry_set,
    (SYSMON, 14): ET.registry_set,
    (SYSMON, 17): ET.pipe_created,
    (SYSMON, 18): ET.pipe_connected,
    ("security", 4624): ET.logon,
    ("security", 4672): ET.special_privileges,
    ("security", 1102): ET.audit_log_cleared,
    ("security", 4662): ET.directory_service_access,
    ("security", 4688): ET.process_create_security,
    ("security", 4697): ET.service_install,
    ("system", 7045): ET.service_install,
    ("system", 104): ET.audit_log_cleared,
}
# attribute -> raw field name, per event type. Attributes in PATH_ATTRS keep the full path in
# ``fields`` (only the basename goes into the attribute), so masquerading stays visible.
# fmt: off
SIMPLE_MAP: dict[EventType, dict[str, str]] = {
    ET.process_create: {"process_image": "Image", "parent_image": "ParentImage",
                        "command_line": "CommandLine", "user": "User", "logon_id": "LogonId"},
    ET.network_connect: {"process_image": "Image", "user": "User", "src_ip": "SourceIp",
                         "dst_ip": "DestinationIp", "src_port": "SourcePort",
                         "dst_port": "DestinationPort", "dst_host": "DestinationHostname"},
    ET.image_load: {"process_image": "Image", "target_image": "ImageLoaded", "user": "User"},
    ET.process_access: {"process_image": "SourceImage", "target_image": "TargetImage",
                        "user": "SourceUser"},
    ET.file_create: {"process_image": "Image", "file_path": "TargetFilename", "user": "User"},
    ET.registry_set: {"process_image": "Image", "registry_target": "TargetObject", "user": "User"},
    ET.pipe_created: {"process_image": "Image", "pipe_name": "PipeName", "user": "User"},
    ET.pipe_connected: {"process_image": "Image", "pipe_name": "PipeName", "user": "User"},
    ET.logon: {"user": "TargetUserName", "logon_type": "LogonType", "logon_id": "TargetLogonId",
               "src_ip": "IpAddress", "src_port": "IpPort", "process_image": "ProcessName"},
    ET.special_privileges: {"user": "SubjectUserName", "logon_id": "SubjectLogonId"},
    ET.audit_log_cleared: {"user": "SubjectUserName", "logon_id": "SubjectLogonId"},
    ET.directory_service_access: {"user": "SubjectUserName", "logon_id": "SubjectLogonId"},
    ET.process_create_security: {"process_image": "NewProcessName",
                                 "parent_image": "ParentProcessName", "command_line": "CommandLine",
                                 "user": "SubjectUserName", "logon_id": "SubjectLogonId"},
    ET.service_install: {"service_name": "ServiceName", "command_line": "ImagePath"},
}
# fmt: on
PATH_ATTRS = {"process_image", "parent_image", "target_image"}
INT_ATTRS = {"src_port", "dst_port"}
IP_ATTRS = {"src_ip", "dst_ip"}


@dataclass
class RawEvent:
    """System fields plus the name -> value data of one record (internal to this module)."""

    record_id: int
    event_id: int
    channel: str
    provider: str
    computer: str
    time: datetime
    data: dict[str, str] = field(default_factory=dict)


def _parse_time(value: str) -> datetime:
    dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).astimezone(UTC)


def parse_event_xml(xml: str) -> RawEvent:
    """Parse one event's XML with defusedxml. Raises on anything unusable (caller counts it)."""
    root = DefusedET.fromstring(xml)
    sysn = root.find(f"{NS}System")
    if sysn is None:
        raise ValueError("no System element")

    def txt(tag: str) -> str:
        el = sysn.find(f"{NS}{tag}")
        return (el.text or "") if el is not None else ""

    tc = sysn.find(f"{NS}TimeCreated")
    prov = sysn.find(f"{NS}Provider")
    data: dict[str, str] = {}
    ed = root.find(f"{NS}EventData")
    if ed is not None:
        for i, d in enumerate(ed):
            data[d.get("Name") or f"_{i}"] = d.text or ""
    ud = root.find(f"{NS}UserData")
    if ud is not None and len(ud):
        for el in list(ud[0]):
            data[el.tag.rsplit("}", 1)[-1]] = el.text or ""
    return RawEvent(
        record_id=int(txt("EventRecordID")),
        event_id=int(txt("EventID")),
        channel=txt("Channel"),
        provider=prov.get("Name", "") if prov is not None else "",
        computer=txt("Computer"),
        time=_parse_time(tc.get("SystemTime", "")) if tc is not None else _parse_time(""),
        data=data,
    )


def event_type_of(raw: RawEvent) -> EventType:
    """Small table lookup on (channel, EventID); unknown combinations become ``other``."""
    return EVENT_TYPES.get((raw.channel.lower(), raw.event_id), EventType.other)


def _scrub_user(user: str, ctx: ParseContext) -> str:
    """``PC04\\IEUser`` -> ``WS-FIN-07\\IEUser`` when the domain part is a real computer name."""
    dom, sep, name = user.partition("\\")
    return f"{ctx.scrub(dom)}{sep}{ctx.scrub(name)}" if sep else ctx.scrub(user)


def _extract(etype: EventType, raw: RawEvent, ctx: ParseContext) -> tuple[dict, set[str], bool]:
    """(attributes, consumed field names, truncated) for the structured entities."""
    attrs: dict = {}
    consumed: set[str] = set()
    trunc = False
    for attr, name in SIMPLE_MAP.get(etype, {}).items():
        val = raw.data.get(name)
        if val is None or val == "":
            continue
        if attr in PATH_ATTRS:
            attrs[attr] = basename(val)
            continue  # full path stays in ``fields``
        consumed.add(name)
        if attr == "command_line":
            text, t, n = sanitize(val, COMMAND_MAX)
            attrs[attr], attrs["command_line_length"], trunc = text, n, trunc or t
        elif attr in INT_ATTRS:
            attrs[attr] = to_int(val)
        elif attr in IP_ATTRS:
            attrs[attr] = clean_ip(val)
        elif attr == "logon_id":
            attrs[attr] = clean(val, 64).lower()
        else:
            attrs[attr], t, _ = sanitize(_scrub_user(val, ctx) if attr == "user" else val)
            trunc = trunc or t
    m = _SVC.search(attrs.get("registry_target") or "")
    if m and "service_name" not in attrs:
        attrs["service_name"] = clean(m.group(1), 256)
    return attrs, consumed, trunc


def build_event(raw: RawEvent, ctx: ParseContext) -> tuple[NormalizedEvent, EventEvalMeta]:
    """Raw record -> (agent view, eval meta). Raises ParseError when the computer has no alias."""
    etype = event_type_of(raw)
    attrs, consumed, trunc = _extract(etype, raw, ctx)
    fields, ftrunc = add_fields(ctx, raw.data, consumed)
    uid = make_event_uid(ctx.evidence_sha256, str(raw.record_id))
    ev = NormalizedEvent(
        event_uid=uid,
        evidence_label=ctx.label,
        source_kind=ctx.source_kind,
        host=ctx.virtual_host(raw.computer),
        timestamp=fmt_virtual(raw.time + ctx.offset),
        event_type=etype,
        channel=clean(raw.channel, 128) or None,
        provider=clean(raw.provider, 128) or None,
        event_id=raw.event_id,
        record_id=raw.record_id,
        fields=fields,
        truncated=trunc or ftrunc,
        **attrs,
    )
    ev.summary = build_summary(ev)
    meta = EventEvalMeta(
        event_uid=uid,
        source_key=ctx.source_key,
        evidence_id=ctx.evidence_id,
        locator=str(raw.record_id),
        real_computer=clean(raw.computer, 256),
        real_timestamp=fmt_virtual(raw.time),
        is_synthetic=ctx.is_synthetic,
    )
    return ev, meta


def iter_evtx(path: Path, ctx: ParseContext) -> Iterator[tuple[NormalizedEvent, EventEvalMeta]]:
    """Yield (event, meta) in file order. Unreadable records are counted, never fatal."""
    try:
        evtx = Evtx(str(path))
        evtx.__enter__()
    except Exception as e:  # noqa: BLE001 - python-evtx raises many types on a bad header
        raise ParseError(f"not a readable EVTX file ({type(e).__name__})") from None
    try:
        for chunk in evtx.chunks():
            it = iter(chunk.records())
            while True:
                try:
                    rec = next(it)
                except StopIteration:
                    break
                except Exception:  # noqa: BLE001 - rest of the chunk is unreadable
                    ctx.stats.corrupt += 1
                    log.warning("record iterator broke; rest of chunk skipped")
                    break
                try:
                    raw = parse_event_xml(rec.xml())
                except Exception:  # noqa: BLE001 - corrupt XML, defusedxml rejection, bad fields
                    ctx.stats.corrupt += 1
                    continue
                try:
                    pair = build_event(raw, ctx)
                except ParseError:
                    raise
                except Exception:  # noqa: BLE001 - one odd record must not fail the file
                    ctx.stats.corrupt += 1
                    continue
                ctx.stats.records += 1
                yield pair
    finally:
        evtx.__exit__(None, None, None)
