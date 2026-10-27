"""Metadata-only field inspection of the real EVTX sources (Phase 2.1).

Produces the content of ``field_inspection.json``: per source the EventID counts, the noteworthy
EventID counts and, for chosen sources, one compact row per event. Rows hold ONLY names and
numbers (EventID, record id, times, computer, account, logon type/process, image BASENAMES, pipe /
service / registry-key NAMES, target-file basenames) and, for command lines, just the length and
boolean flags. Everything read from evidence is DATA, never instructions; no raw text is echoed.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from chainofproof.scenarios.evtx_meta import EvtxEvent, iter_events
from chainofproof.scenarios.inventory import INSTRUCTION_LIKE
from chainofproof.schemas.scenario import Scenario

MAX_NAME = 200
SYSMON = "Microsoft-Windows-Sysmon/Operational"
# noteworthy EventIDs per log family; Sysmon is counted only, never listed
NOTEWORTHY: dict[str, tuple[int, ...]] = {
    "Security": (1102, 4720, 4722, 4724, 4728, 4732, 4756, 4697, 4698, 4672, 4648),
    "System": (104, 7045, 7036),
    "Sysmon": (1, 3, 7, 8, 10, 11, 13, 17, 18),
}
_ENC = re.compile(r"(?i)\s-(e|ec|en|enc|enco\w*|encodedcommand)\s+[A-Za-z0-9+/=]{20,}")
_USER_FIELDS = ("TargetUserName", "SubjectUserName", "User")


def basename(value: str) -> str:
    """Last path component (either slash style), capped."""
    return value.replace("/", "\\").rsplit("\\", 1)[-1][:MAX_NAME]


def command_flags(cmd: str) -> dict[str, Any]:
    """Length and boolean facts about a command line; the text itself is never returned."""
    low = cmd.lower()
    return {
        "length": len(cmd),
        "encoded_command_switch": bool(_ENC.search(cmd)),
        "mentions_powershell": "powershell" in low,
        "hidden_window": bool(re.search(r"-w(in\w*)?\s+hid|windowstyle\s+hid", low)),
        "no_profile": bool(re.search(r"-nop\b|-noprofile", low)),
    }


def family(e: EvtxEvent) -> str:
    """Log family used by the noteworthy table: Security, System, Sysmon or the channel name."""
    if e.channel == SYSMON:
        return "Sysmon"
    return e.channel if e.channel in ("Security", "System") else e.channel[:MAX_NAME]


def _put(row: dict[str, Any], key: str, value: str | None) -> None:
    if value and value != "-":
        row[key] = value[:MAX_NAME]


def event_row(e: EvtxEvent) -> dict[str, Any]:
    """One compact metadata row for an event (see module docstring for what it may contain)."""
    d = e.data
    row: dict[str, Any] = {
        "record_id": e.record_id,
        "event_id": e.event_id,
        "channel": family(e),
        "time": e.time,
        "computer": e.computer,
    }
    for f in _USER_FIELDS:
        if d.get(f, "-") != "-" and d.get(f):
            row["account"] = d[f][:MAX_NAME]
            break
    if e.event_id == 4624:
        _put(row, "logon_type", d.get("LogonType"))
        _put(row, "logon_process", d.get("LogonProcessName"))
        _put(row, "auth_package", d.get("AuthenticationPackageName"))
    for key, field in (("image", "Image"), ("parent_image", "ParentImage")):
        _put(row, key, basename(d[field]) if d.get(field) else None)
    if e.event_id == 10:
        _put(row, "source_image", basename(d.get("SourceImage", "")))
        _put(row, "target_image", basename(d.get("TargetImage", "")))
    for key, field in (("image", "NewProcessName"), ("parent_image", "ParentProcessName")):
        _put(row, key, basename(d[field]) if d.get(field) else None)
    if e.event_id == 3:  # network connection: ports and direction only, never addresses
        for key, field in (
            ("protocol", "Protocol"),
            ("initiated", "Initiated"),
            ("source_port", "SourcePort"),
            ("destination_port", "DestinationPort"),
        ):
            _put(row, key, d.get(field))
    _put(row, "pipe_name", d.get("PipeName"))
    _put(row, "service_name", d.get("ServiceName"))
    svc_file = d.get("ServiceFileName") or d.get("ImagePath")
    _put(row, "service_file", basename(svc_file) if svc_file else None)
    if e.event_id in (12, 13, 14):
        _put(row, "registry_key", d.get("TargetObject"))
    if e.event_id == 11:
        _put(row, "target_filename", basename(d.get("TargetFilename", "")))
    if d.get("CommandLine"):
        row["command_line"] = command_flags(d["CommandLine"])
    flagged = sorted(n for n, v in d.items() if INSTRUCTION_LIKE.search(v))
    if flagged:
        row["instruction_like_fields"] = flagged
    return row


def noteworthy_counts(events: Iterable[EvtxEvent]) -> dict[str, dict[str, int]]:
    """Counts of the noteworthy EventIDs per log family (only non-zero entries)."""
    counts: Counter[tuple[str, int]] = Counter()
    for e in events:
        fam = family(e)
        if e.event_id in NOTEWORTHY.get(fam, ()):
            counts[(fam, e.event_id)] += 1
    out: dict[str, dict[str, int]] = {}
    for (fam, eid), n in sorted(counts.items()):
        out.setdefault(fam, {})[str(eid)] = n
    return out


def scan_file(path: Path, with_rows: bool) -> dict[str, Any]:
    """Field inspection of one file: counts always, per-event rows when ``with_rows``."""
    events = list(iter_events(path))
    ids = Counter(e.event_id for e in events)
    out: dict[str, Any] = {
        "record_count": len(events),
        "event_id_counts": {str(k): v for k, v in sorted(ids.items())},
        "noteworthy_counts": noteworthy_counts(events),
    }
    if with_rows:
        out["events"] = [event_row(e) for e in sorted(events, key=lambda x: x.record_id)]
    return out


def save_inspection(path: Path, data: dict[str, Any]) -> None:
    """Write field_inspection.json deterministically (indent 2, LF, trailing newline)."""
    text = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True)
    Path(path).write_text(text + "\n", encoding="utf-8", newline="\n")


def load_known_events(path: Path) -> dict[str, dict[int, int]]:
    """field_inspection.json -> {source_key: {record_id: event_id}} for sources that list rows."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {
        k: {int(e["record_id"]): int(e["event_id"]) for e in v["events"]}
        for k, v in data["sources"].items()
        if "events" in v
    }


def load_real_pipes(path: Path, scenario: Scenario) -> dict[str, frozenset[str]]:
    """virtual host -> lower-case pipe names of the REAL events mapped to it (names only).

    Read from field_inspection.json through the scenario's host aliases; a missing file gives {}.
    """
    if not Path(path).is_file():
        return {}
    out: dict[str, set[str]] = {}
    for key, src in json.loads(Path(path).read_text(encoding="utf-8"))["sources"].items():
        aliases = scenario.aligned(key).host_aliases
        for e in src.get("events", []):
            host = aliases.get(e.get("computer", ""))
            if host and e.get("pipe_name"):
                out.setdefault(host, set()).add(e["pipe_name"].lstrip("\\").lower())
    return {h: frozenset(p) for h, p in out.items()}
