"""Tiny factory for in-memory NormalizedEvent objects (detector and graph tests)."""

import hashlib
from itertools import count

from chainofproof.schemas.events import EventType, NormalizedEvent

_n = count(1)
KIND = {"EVTX": "evtx", "FSTL": "fs_timeline", "AUTH": "auth_log"}


def ev(label="AUTH-aaaaaa", ts="2024-03-12T09:00:00.000000Z", host="H1", etype="other", **kw):
    """One event; the source kind follows the label prefix, the uid is unique per call."""
    uid = "EVT-" + hashlib.sha256(str(next(_n)).encode()).hexdigest()[:12]
    base = {
        "event_uid": uid,
        "evidence_label": label,
        "source_kind": KIND[label.split("-")[0]],
        "host": host,
        "timestamp": ts,
        "event_type": EventType(etype),
        "summary": "x",
    }
    return NormalizedEvent(**{**base, **kw})


def auth(seq, ts, host="H1", name="LOGON_SUCCESS", label="AUTH-aaaaaa", **kw):
    """An auth-log line (seq = record_id, name = auth_event)."""
    etype = (
        "auth_conn"
        if name.startswith("CONN_")
        else "auth_logon"
        if name.startswith("LOGON")
        else "other"
    )
    fields = {"auth_event": name, **kw.pop("fields", {})}
    return ev(label, ts, host, etype, record_id=seq, fields=fields, **kw)


def fs(rid, si, fn, path="C:\\a\\b.exe", host="H1", label="FSTL-bbbbbb"):
    """A file-timeline row: si/fn are dicts of the four pairs or one value for all four."""
    fields = {}
    for p in ("created", "modified", "accessed", "changed"):
        fields[f"si_{p}"] = si if isinstance(si, str) else si[p]
        fields[f"fn_{p}"] = fn if isinstance(fn, str) else fn[p]
    created = (fn if isinstance(fn, str) else fn["created"]).replace("Z", ".000000Z")
    return ev(label, created, host, "file_timeline", record_id=rid, file_path=path, fields=fields)
