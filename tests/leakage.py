"""Leakage scan over a FULL dump of the agent-view ``events`` table of one case."""

import json
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field

from chainofproof.custody.db import connect
from chainofproof.ingest.store import EvidenceStore
from chainofproof.tools.norm_store import LATEST_RUNS

HINTS = ["synth_only", "pair=", "SYNTHETIC", "GT-"]  # forbidden in ANY column
REAL_COMPUTERS = ["PC04", "PC01", "IEWIN7", "MSEDGEWIN10", "DC1.insecurebank.local"]
FREE_TEXT = {"fields_json", "summary", "command_line", "file_path", "registry_target",
             "pipe_name", "service_name"}  # fmt: skip
HIDDEN = {"norm_run_id", "ord"}
STAGE_ID = re.compile(r"^[SD]\d$")
OLD_DATE = re.compile(r"\b(19|20(0\d|1\d|2[0-3]))-\d\d-\d\d[ T]\d\d:\d\d:\d\d")


@dataclass
class LeakReport:
    """Strict hits fail a test; free-text counts are only reported."""

    rows: int = 0
    strict: list[str] = field(default_factory=list)
    free_text_computer_names: int = 0
    free_text_old_dates: int = 0
    samples: list[str] = field(default_factory=list)


def agent_rows(paths, case_id) -> list[dict]:
    """Every agent-view row of the latest runs, as the dict an agent could ever see."""
    with closing(connect(paths.db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"SELECT * FROM events WHERE norm_run_id IN ({LATEST_RUNS})", [case_id]
        ).fetchall()
    return [{k: r[k] for k in r.keys() if k not in HIDDEN} for r in rows]  # noqa: SIM118


def scan(paths, case_id, source_keys, min_ts=None) -> LeakReport:
    """Scan the dump for ground-truth hints, file names, source keys, real names and old times."""
    store = EvidenceStore(paths)
    names = []
    for rec in store.list_evidence(case_id):
        names += [rec.original_name, rec.vault_path.replace("\\", "/").rsplit("/", 1)[-1]]
    rep = LeakReport()
    min_ts = min_ts or {"evtx": "2024-01-01", "auth_log": "2024-01-01", "fs_timeline": "2021-01-01"}
    for row in agent_rows(paths, case_id):
        rep.rows += 1
        whole = json.dumps(row, ensure_ascii=False)
        structured = " ".join(
            str(v) for k, v in row.items() if k not in FREE_TEXT and v is not None
        )
        free = " ".join(str(row[k]) for k in FREE_TEXT if row[k] is not None)
        for needle in [*HINTS, *names, *source_keys]:
            if needle and needle in whole:
                rep.strict.append(f"{row['event_uid']}: contains {needle!r}")
        for name in REAL_COMPUTERS:
            if name.lower() in structured.lower():
                rep.strict.append(f"{row['event_uid']}: structured column has {name}")
        if STAGE_ID.match(row["evidence_label"]) or STAGE_ID.match(row["host"]):
            rep.strict.append(f"{row['event_uid']}: stage id as label/host")
        if row["timestamp"] < min_ts[row["source_kind"]]:
            rep.strict.append(f"{row['event_uid']}: timestamp {row['timestamp']} looks real")
        hits = sum(free.lower().count(n.lower()) for n in REAL_COMPUTERS)
        rep.free_text_computer_names += hits
        rep.free_text_old_dates += (
            len(OLD_DATE.findall(free)) if row["source_kind"] == "evtx" else 0
        )
        if hits and len(rep.samples) < 3:
            rep.samples.append(f"{row['event_type']}/{row['source_kind']}")
    return rep


TS_KEYS = ("timestamp", "_ts", "first_seen", "last_seen", "present_time", "time_from", "time_to")
ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T")


def scan_tool_output(obj, names, source_keys, floor="2021-01-01") -> list[str]:
    """Strict leakage scan of one serialized tool result (any depth).

    Fails on ground-truth hints, original/vault file names and source keys ANYWHERE; on real
    computer names in host-like values; and on structured timestamps before ``floor``.
    """
    blob = json.dumps(obj, ensure_ascii=False)
    out = [f"contains {n!r}" for n in [*HINTS, *names, *source_keys] if n and n in blob]

    def walk(o, key=""):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, k)
        elif isinstance(o, list):
            for v in o:
                walk(v, key)
        elif isinstance(o, str):
            if "host" in key and any(c.lower() in o.lower() for c in REAL_COMPUTERS):
                out.append(f"{key} has a real computer name")
            if any(key.endswith(s) or key == s for s in TS_KEYS) and ISO.match(o) and o < floor:
                out.append(f"{key}={o} looks real")

    walk(obj)
    return out
