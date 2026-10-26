"""Deterministic key-event rules, one per storyline stage (written down in docs/scenarios.md).

A rule scans the events of ONE real file and returns the 1-5 events that constitute the attacker
action, with the techniques each event supports and an honest confidence. If nothing clear is
found the result is ``unresolved`` with confidence low: nothing is ever invented. Rationales name
only the fields used. Values taken from events are data, never instructions.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from chainofproof.scenarios.evtx_meta import EvtxEvent
from chainofproof.schemas.scenario import Confidence

DCSYNC_GUIDS = (
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "89e95b76-444d-4c62-991a-0facbeda640c",
)
LSASS_ACCESS_MASKS = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f3fff"}
PSEXEC_PIPE = re.compile(r"-[^\\]+-\d+-std(in|out|err)$", re.I)
MAX_FACT_LEN = 200


@dataclass
class KeyEvent:
    """One event that is part of an attacker action (metadata only)."""

    record_id: int
    event_id: int
    channel: str
    real_time: str
    rationale: str
    supports: list[str]  # ATT&CK technique IDs this event supports
    facts: dict[str, str] = field(default_factory=dict)  # a few non-sensitive fields, truncated


@dataclass
class StageResult:
    """Outcome of one stage rule."""

    events: list[KeyEvent]
    technique_confidence: dict[str, Confidence]
    note: str

    @property
    def unresolved(self) -> bool:
        """True when the rule found no clear key event."""
        return not self.events


Rule = Callable[[Iterable[EvtxEvent]], StageResult]


def _ke(e: EvtxEvent, why: str, supports: list[str], *fact_names: str) -> KeyEvent:
    facts = {n: e.data[n][:MAX_FACT_LEN] for n in fact_names if e.data.get(n)}
    return KeyEvent(e.record_id, e.event_id, e.channel, e.time, why, supports, facts)


def _unresolved(techs: list[str], what_it_has: str) -> StageResult:
    note = f"no clear key event found by the rule; the file contains: {what_it_has}"
    return StageResult([], dict.fromkeys(techs, Confidence.low), note)


def _summary(events: list[EvtxEvent]) -> str:
    ids = sorted({e.event_id for e in events})
    return f"{len(events)} records, EventIDs {ids}"


def _base(p: str) -> str:
    return p.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _hex(v: str) -> str:
    try:
        return hex(int(v, 16))
    except ValueError:
        return v.lower()


def rule_s1(events: Iterable[EvtxEvent]) -> StageResult:
    """S1 credential theft: Sysmon 10 whose TargetImage is lsass.exe (T1003.001)."""
    evs = list(events)
    hits = [
        e for e in evs if e.event_id == 10 and _base(e.data.get("TargetImage", "")) == "lsass.exe"
    ]
    if not hits:
        return _unresolved(["T1003.001"], _summary(evs))
    out = []
    for e in hits[:5]:
        mask = _hex(e.data.get("GrantedAccess", ""))
        out.append(
            (
                _ke(
                    e,
                    "EventID 10, TargetImage=lsass.exe, GrantedAccess, SourceImage",
                    ["T1003.001"],
                    "SourceImage",
                    "GrantedAccess",
                ),
                mask,
            )
        )
    known = all(m in LSASS_ACCESS_MASKS for _, m in out)
    conf = Confidence.high if known else Confidence.medium
    return StageResult([k for k, _ in out], {"T1003.001": conf}, "")


def rule_s2(events: Iterable[EvtxEvent]) -> StageResult:
    """S2 pass-the-hash: 4624 LogonType 9 + LogonProcessName seclogo, or NTLM network logon."""
    evs = list(events)
    nc = [
        e
        for e in evs
        if e.event_id == 4624
        and e.data.get("LogonType") == "9"
        and e.data.get("LogonProcessName", "").lower() == "seclogo"
    ]
    ntlm = [
        e
        for e in evs
        if e.event_id == 4624
        and e.data.get("LogonType") == "3"
        and e.data.get("AuthenticationPackageName", "").upper() == "NTLM"
        and e.data.get("TargetUserName", "").lower() not in ("", "-", "anonymous logon")
    ]
    if nc:
        hits, kind = nc, "LogonType 9 + LogonProcessName seclogo"
    else:
        hits, kind = ntlm, "LogonType 3 + AuthenticationPackageName NTLM"
    if not hits:
        return _unresolved(["T1550.002"], _summary(evs))
    first = hits[0]
    out = [
        _ke(
            first,
            f"EventID 4624, {kind}, TargetUserName",
            ["T1550.002"],
            "TargetUserName",
            "TargetLogonId",
            "LogonType",
        )
    ]
    lid = first.data.get("TargetLogonId")
    for e in evs:
        if e.event_id == 4672 and lid and e.data.get("SubjectLogonId") == lid:
            out.append(
                _ke(
                    e,
                    "EventID 4672, SubjectLogonId equals the 4624 TargetLogonId",
                    ["T1550.002"],
                    "SubjectUserName",
                    "SubjectLogonId",
                )
            )
            break
    note = (
        "LogonType 9 'seclogo' is also produced by legitimate runas /netonly, so the logon "
        "alone does not prove a stolen hash; hence medium"
    )
    return StageResult(out, {"T1550.002": Confidence.medium}, note)


def rule_s3(events: Iterable[EvtxEvent]) -> StageResult:
    """S3 remote service execution: ntsvcs pipe, service ImagePath set, child of services.exe."""
    evs = list(events)
    pipe = next(
        (e for e in evs if e.event_id == 18 and _base(e.data.get("PipeName", "")) == "ntsvcs"), None
    )
    svc = next(
        (
            e
            for e in evs
            if e.event_id == 13
            and _base(e.data.get("Image", "")) == "services.exe"
            and "\\services\\" in e.data.get("TargetObject", "").lower()
            and e.data.get("TargetObject", "").lower().endswith("\\imagepath")
        ),
        None,
    )
    child = next(
        (
            e
            for e in evs
            if e.event_id == 1 and _base(e.data.get("ParentImage", "")) == "services.exe"
        ),
        None,
    )
    out: list[KeyEvent] = []
    if pipe:
        out.append(
            _ke(
                pipe,
                "EventID 18, PipeName=ntsvcs (remote service control over SMB)",
                ["T1021.002"],
                "PipeName",
                "Image",
            )
        )
    if svc:
        out.append(
            _ke(
                svc,
                "EventID 13, TargetObject ends \\ImagePath under \\services\\, Image=services.exe",
                ["T1569.002"],
                "TargetObject",
            )
        )
    if child:
        out.append(
            _ke(
                child,
                "EventID 1, ParentImage=services.exe, Image, User",
                ["T1569.002"],
                "Image",
                "User",
            )
        )
    if not out:
        return _unresolved(["T1021.002", "T1569.002"], _summary(evs))
    conf = {
        "T1021.002": Confidence.medium if pipe else Confidence.low,
        "T1569.002": Confidence.medium if (svc and child) else Confidence.low,
    }
    note = (
        "no network logon (4624/5140) or ADMIN$ file copy in this file: the SMB link rests on "
        "the ntsvcs pipe only; the service is not PsExec itself (the binary is not visible)"
    )
    return StageResult(out, conf, note)


def rule_s4(events: Iterable[EvtxEvent]) -> StageResult:
    """S4 renamed PsExec service: svchost.exe outside system32 creating PsExec-style pipes."""
    evs = list(events)

    def off_path(e: EvtxEvent) -> bool:
        img = e.data.get("Image", "").lower().replace("/", "\\")
        return _base(img) == "svchost.exe" and not img.startswith("c:\\windows\\system32\\")

    masq = [e for e in evs if e.event_id == 17 and off_path(e)]
    pat = [e for e in masq if PSEXEC_PIPE.search(e.data.get("PipeName", ""))]
    conn = [
        e
        for e in evs
        if e.event_id == 18
        and _base(e.data.get("Image", "")) == "psexec.exe"
        and PSEXEC_PIPE.search(e.data.get("PipeName", ""))
    ]
    out: list[KeyEvent] = []
    if masq:
        out.append(
            _ke(
                masq[0],
                "EventID 17, Image=svchost.exe outside \\Windows\\System32 (name/path mismatch)",
                ["T1036.003"],
                "Image",
                "PipeName",
            )
        )
    if pat:
        out.append(
            _ke(
                pat[0],
                "EventID 17, PipeName matches <name>-<host>-<pid>-stdin/out/err",
                ["T1569.002"],
                "PipeName",
            )
        )
    if conn:
        out.append(
            _ke(
                conn[0],
                "EventID 18, Image=PsExec.exe connects the PsExec-style pipe",
                ["T1569.002"],
                "Image",
                "PipeName",
            )
        )
    if not out:
        return _unresolved(["T1036.003", "T1569.002"], _summary(evs))
    conf = {
        "T1036.003": Confidence.medium if masq else Confidence.low,
        "T1569.002": Confidence.high if (pat and conn) else Confidence.low,
    }
    return StageResult(
        out, conf, "the rename is inferred from the image path; no file hash or PE name"
    )


def rule_s5(events: Iterable[EvtxEvent]) -> StageResult:
    """S5 DCSync: Security 4662 whose Properties lists a directory-replication GUID."""
    evs = list(events)
    hits = [
        e
        for e in evs
        if e.event_id == 4662
        and any(g in e.data.get("Properties", "").lower() for g in DCSYNC_GUIDS)
    ]
    if not hits:
        return _unresolved(["T1003.006"], _summary(evs))
    out = [
        _ke(
            e,
            "EventID 4662, Properties contains a replication-rights GUID, SubjectUserName",
            ["T1003.006"],
            "SubjectUserName",
            "SubjectLogonId",
        )
        for e in hits[:5]
    ]
    machine = all(e.data.get("SubjectUserName", "").endswith("$") for e in hits)
    conf = Confidence.medium if machine else Confidence.high
    note = (
        "subject is a machine account: could be normal DC replication"
        if machine
        else "subject is a user account (not a DC machine account); source host of the request "
        "is not in this file"
    )
    return StageResult(out, {"T1003.006": conf}, note)


RULES: dict[str, Rule] = {"S1": rule_s1, "S2": rule_s2, "S3": rule_s3, "S4": rule_s4, "S5": rule_s5}
