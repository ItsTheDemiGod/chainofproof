"""Key-event rules for the first stages: S1 credential theft and S2 use of the stolen credential."""

from __future__ import annotations

from collections.abc import Iterable

from chainofproof.scenarios.evtx_meta import EvtxEvent
from chainofproof.scenarios.keyevents_base import (
    StageResult,
    base,
    hex_norm,
    make_key_event,
    summary,
    unresolved,
)
from chainofproof.schemas.scenario import Confidence

LSASS_ACCESS_MASKS = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f3fff"}
LOG_CLEARED_TECHNIQUE = "T1070.001"


def rule_s1(events: Iterable[EvtxEvent]) -> StageResult:
    """S1 credential theft: Sysmon 10 whose TargetImage is lsass.exe (T1003.001)."""
    evs = list(events)
    hits = [
        e for e in evs if e.event_id == 10 and base(e.data.get("TargetImage", "")) == "lsass.exe"
    ]
    if not hits:
        return unresolved(["T1003.001"], summary(evs))
    out = [
        make_key_event(
            e,
            "EventID 10, TargetImage=lsass.exe, GrantedAccess, SourceImage",
            ["T1003.001"],
            "SourceImage",
            "GrantedAccess",
        )
        for e in hits[:5]
    ]
    known = all(hex_norm(e.data.get("GrantedAccess", "")) in LSASS_ACCESS_MASKS for e in hits[:5])
    conf = Confidence.high if known else Confidence.medium
    return StageResult(out, {"T1003.001": conf}, "")


def _s2_logons(evs: list[EvtxEvent]) -> tuple[list[EvtxEvent], str]:
    nc = [
        e
        for e in evs
        if e.event_id == 4624
        and e.data.get("LogonType") == "9"
        and e.data.get("LogonProcessName", "").lower() == "seclogo"
    ]
    if nc:
        return nc, "LogonType 9 + LogonProcessName seclogo"
    ntlm = [
        e
        for e in evs
        if e.event_id == 4624
        and e.data.get("LogonType") == "3"
        and e.data.get("AuthenticationPackageName", "").upper() == "NTLM"
        and e.data.get("TargetUserName", "").lower() not in ("", "-", "anonymous logon")
    ]
    return ntlm, "LogonType 3 + AuthenticationPackageName NTLM"


def rule_s2(events: Iterable[EvtxEvent]) -> StageResult:
    """S2 pass-the-hash (4624 [+4672]) and, if present just before it, a Security 1102 log clear."""
    evs = list(events)
    hits, kind = _s2_logons(evs)
    if not hits:
        return unresolved(["T1550.002"], summary(evs))
    first = hits[0]
    out = [
        make_key_event(
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
                make_key_event(
                    e,
                    "EventID 4672, SubjectLogonId equals the 4624 TargetLogonId",
                    ["T1550.002"],
                    "SubjectUserName",
                    "SubjectLogonId",
                )
            )
            break
    conf = {"T1550.002": Confidence.medium}
    note = (
        "LogonType 9 'seclogo' is also produced by legitimate runas /netonly, so the logon "
        "alone does not prove a stolen hash; hence medium"
    )
    notes: dict[str, str] = {}
    clears = [e for e in evs if e.event_id == 1102 and e.time <= first.time]
    if clears:
        c = max(clears, key=lambda e: e.time)
        out.append(
            make_key_event(
                c,
                "EventID 1102 (Security audit log cleared) shortly before the 4624",
                [LOG_CLEARED_TECHNIQUE],
                "SubjectUserName",
            )
        )
        conf[LOG_CLEARED_TECHNIQUE] = Confidence.medium
        notes[LOG_CLEARED_TECHNIQUE] = (
            "the clear may instead be lab preparation by the dataset author before recording; "
            "it is treated as a defense-evasion indicator inside this constructed storyline"
        )
    return StageResult(out, conf, note, notes)
