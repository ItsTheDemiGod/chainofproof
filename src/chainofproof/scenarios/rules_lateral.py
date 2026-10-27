"""Key-event rules for lateral movement and later stages: S3, S4 (PsExec-style) and S5 (DCSync)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from chainofproof.scenarios.evtx_meta import EvtxEvent
from chainofproof.scenarios.keyevents_base import (
    KeyEvent,
    StageResult,
    base,
    make_key_event,
    summary,
    unresolved,
)
from chainofproof.schemas.scenario import Confidence

DCSYNC_GUIDS = (
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "89e95b76-444d-4c62-991a-0facbeda640c",
)
PSEXEC_PIPE = re.compile(r"-[^\\]+-\d+-std(in|out|err)$", re.I)
SHELLS = ("cmd.exe", "powershell.exe")
MAX_CHAIN = 5


def _s3_service_events(evs: list[EvtxEvent]) -> list[EvtxEvent]:
    """Sysmon 13 writes by services.exe to the service key whose ImagePath is set (up to it)."""

    def key_of(e: EvtxEvent) -> str:
        return e.data.get("TargetObject", "").lower().rsplit("\\", 1)[0]

    regs = [
        e
        for e in evs
        if e.event_id == 13
        and base(e.data.get("Image", "")) == "services.exe"
        and "\\services\\" in e.data.get("TargetObject", "").lower()
    ]
    anchor = next((e for e in regs if e.data["TargetObject"].lower().endswith("\\imagepath")), None)
    if anchor is None:
        return []
    return [e for e in regs if key_of(e) == key_of(anchor) and e.record_id <= anchor.record_id]


def _s3_chain(evs: list[EvtxEvent]) -> list[EvtxEvent]:
    """Sysmon 1: first child of services.exe, then shells started by cmd.exe/powershell.exe."""
    procs = sorted((e for e in evs if e.event_id == 1), key=lambda e: e.record_id)
    head = next((e for e in procs if base(e.data.get("ParentImage", "")) == "services.exe"), None)
    if head is None:
        return []
    rest = [
        e
        for e in procs
        if e.record_id > head.record_id
        and base(e.data.get("ParentImage", "")) in SHELLS
        and base(e.data.get("Image", "")) in SHELLS
    ]
    return [head, *rest][:MAX_CHAIN]


def rule_s3(events: Iterable[EvtxEvent]) -> StageResult:
    """S3 remote service execution: ntsvcs pipe + inbound SMB, service ImagePath, shell chain."""
    evs = list(events)
    pipe = next(
        (e for e in evs if e.event_id == 18 and base(e.data.get("PipeName", "")) == "ntsvcs"), None
    )
    smb = next(
        (
            e
            for e in evs
            if e.event_id == 3
            and base(e.data.get("Image", "")) == "system"
            and e.data.get("Initiated", "").lower() == "false"
            and e.data.get("SourcePort") == "445"
        ),
        None,
    )
    svc, chain = _s3_service_events(evs), _s3_chain(evs)
    out: list[KeyEvent] = []
    if pipe:
        why = "EventID 18, PipeName=ntsvcs opened by the System process (SMB server side)"
        out.append(make_key_event(pipe, why, ["T1021.002"], "PipeName", "Image"))
    if smb:
        why = "EventID 3, Image=System, Initiated=False, SourcePort=445 (inbound SMB)"
        out.append(
            make_key_event(smb, why, ["T1021.002"], "Image", "Initiated", "SourcePort", "Protocol")
        )
    for e in svc:
        why = "EventID 13, TargetObject under \\services\\ written by services.exe"
        out.append(make_key_event(e, why, ["T1569.002"], "TargetObject"))
    for e in chain:
        why = "EventID 1, shell/PowerShell process chain started by the new service"
        out.append(make_key_event(e, why, ["T1569.002"], "Image", "ParentImage", "User"))
    if not out:
        return unresolved(["T1021.002", "T1569.002"], summary(evs))
    conf = {
        "T1021.002": Confidence.medium if (pipe and smb) else Confidence.low,
        "T1569.002": Confidence.medium if (svc and chain) else Confidence.low,
    }
    notes = {
        "T1021.002": (
            "no network logon (4624/5140) and no ADMIN$ file copy in this file: the SMB link rests "
            "on the System-process ntsvcs pipe open and the inbound TCP 445 connection; who "
            "connected and with which credential is not shown"
        ),
        "T1569.002": (
            "the service runs a command line (cmd.exe -> powershell.exe), not PsExec itself; no "
            "PsExec artifact is visible in this file"
        ),
    }
    return StageResult(out, conf, "", notes)


def rule_s4(events: Iterable[EvtxEvent]) -> StageResult:
    """S4 renamed PsExec service: svchost.exe outside system32 creating PsExec-style pipes."""
    evs = list(events)

    def off_path(e: EvtxEvent) -> bool:
        img = e.data.get("Image", "").lower().replace("/", "\\")
        return base(img) == "svchost.exe" and not img.startswith("c:\\windows\\system32\\")

    masq = [e for e in evs if e.event_id == 17 and off_path(e)]
    pat = [e for e in masq if PSEXEC_PIPE.search(e.data.get("PipeName", ""))]
    conn = [
        e
        for e in evs
        if e.event_id == 18
        and base(e.data.get("Image", "")) == "psexec.exe"
        and PSEXEC_PIPE.search(e.data.get("PipeName", ""))
    ]
    out: list[KeyEvent] = []
    if masq:
        why = "EventID 17, Image=svchost.exe outside \\Windows\\System32 (name/path mismatch)"
        out.append(make_key_event(masq[0], why, ["T1036.003"], "Image", "PipeName"))
    for e in pat[:3]:
        why = "EventID 17, PipeName matches <name>-<host>-<pid>-stdin/out/err"
        out.append(make_key_event(e, why, ["T1569.002"], "PipeName"))
    for e in conn[:3]:
        why = "EventID 18, Image=PsExec.exe connects the PsExec-style pipe"
        out.append(make_key_event(e, why, ["T1569.002"], "Image", "PipeName"))
    if not out:
        return unresolved(["T1036.003", "T1569.002"], summary(evs))
    conf = {
        "T1036.003": Confidence.medium if masq else Confidence.low,
        "T1569.002": Confidence.high if (pat and conn) else Confidence.low,
    }
    note = "the rename is inferred from the image path; no file hash or PE name"
    return StageResult(out, conf, note)


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
        return unresolved(["T1003.006"], summary(evs))
    why = "EventID 4662, Properties contains a replication-rights GUID, SubjectUserName"
    out = [
        make_key_event(e, why, ["T1003.006"], "SubjectUserName", "SubjectLogonId") for e in hits[:5]
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
