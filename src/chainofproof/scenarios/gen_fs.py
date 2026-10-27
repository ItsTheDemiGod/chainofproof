"""Companion A (SYNTHETIC): per-host file-system timeline with attacker artifacts.

Benign entries are random but seeded; attacker artifacts are timed from the REAL key events of the
matching stage (virtual time). In the clean data si_* and fn_* agree (within a few seconds for
benign files, exactly for attacker files).
"""

from __future__ import annotations

import csv
import io
import random
from dataclasses import dataclass
from datetime import datetime, timedelta

from chainofproof.scenarios.companions import FS_COLUMNS, MARKER, Pairing, fmt_ts
from chainofproof.scenarios.gen_context import GenContext
from chainofproof.scenarios.keyevents_base import base

SYSTEM_NAMES = [
    "kernel32",
    "user32",
    "advapi32",
    "ntdll",
    "shell32",
    "ole32",
    "ws2_32",
    "crypt32",
    "wininet",
    "netapi32",
    "samlib",
    "secur32",
    "rpcrt4",
    "msvcrt",
    "gdi32",
    "comctl32",
    "version",
    "setupapi",
    "wldap32",
    "dnsapi",
    "iphlpapi",
    "mswsock",
    "bcrypt",
    "sspicli",
]
APP_DIRS = [
    r"C:\Program Files\Microsoft Office\root\Office16",
    r"C:\Program Files\Common Files\Microsoft Shared",
    r"C:\Program Files (x86)\Internet Explorer",
    r"C:\Program Files\Windows Defender",
    r"C:\ProgramData\Microsoft\Windows",
]
DOC_WORDS = [
    "report",
    "budget",
    "notes",
    "invoice",
    "plan",
    "draft",
    "summary",
    "agenda",
    "q1",
    "q2",
]
EXTS = ["docx", "xlsx", "pdf", "txt", "pptx", "csv"]
USERS = ["jsmith", "mlopez", "akhan", "rbrown"]
ATTACKER_DATE = "2021-06-15"  # decoy date used by the timestomp perturbation


@dataclass
class FsResult:
    """Rows of one host plus the record_id of every attacker artifact (tag -> record_id)."""

    rows: list[dict[str, str]]
    artifacts: dict[str, int]
    pairings: dict[str, Pairing]  # tag -> how the artifact relates to real evidence


def _row(path: str, size: int, c: datetime, m: datetime, a: datetime, ch: datetime) -> dict:
    ts = [fmt_ts(x) for x in (c, m, a, ch)]
    names = ("created", "modified", "accessed", "changed")
    si = {f"si_{n}": t for n, t in zip(names, ts, strict=True)}
    fn = {f"fn_{n}": t for n, t in zip(names, ts, strict=True)}
    return {"path": path, "size": str(size), **si, **fn, "note": ""}


def _benign(ctx: GenContext, host: str, rng: random.Random) -> list[dict[str, str]]:
    start = ctx.start
    rows, seen = [], set()
    n = ctx.scenario.noise.benign_fs_entries_per_host
    for i in range(n):
        kind = rng.choice(["sys", "app", "doc"])
        if kind == "sys":
            path = rf"C:\Windows\System32\{rng.choice(SYSTEM_NAMES)}{rng.randint(0, 99):02d}.dll"
        elif kind == "app":
            path = rf"{rng.choice(APP_DIRS)}\{rng.choice(SYSTEM_NAMES)}_{i}.dll"
        else:
            u = rng.choice(USERS)
            path = rf"C:\Users\{u}\Documents\{rng.choice(DOC_WORDS)}_{i}.{rng.choice(EXTS)}"
        if path in seen:
            continue
        seen.add(path)
        created = start - timedelta(days=rng.randint(40, 700), seconds=rng.randint(0, 86399))
        modified = created + timedelta(days=rng.randint(0, 30), seconds=rng.randint(0, 86399))
        if rng.random() < 0.15:  # touched during the virtual window
            modified = start + timedelta(minutes=rng.randint(-100, 230))
        accessed = modified + timedelta(seconds=rng.randint(0, 3600))
        r = _row(path, int(10 ** rng.uniform(3, 7.5)), created, modified, accessed, modified)
        if rng.random() < 0.2:  # tiny benign si/fn jitter (a few seconds)
            j = timedelta(seconds=rng.randint(1, 3))
            r["si_modified"] = fmt_ts(modified + j)
        rows.append(r)
    return rows


Attacker = dict[str, tuple[dict[str, str], Pairing]]


def _marked(row: dict[str, str], pairing: Pairing) -> tuple[dict[str, str], Pairing]:
    """Write the pairing marker (rule R1) into the row's ``note`` column."""
    row["note"] = pairing.marker()
    return row, pairing


def _attacker_ws(ctx: GenContext) -> Attacker:
    ev, t1 = ctx.first_key("S1")
    exe = ev.facts.get("SourceImage", r"C:\Users\Public\mimikatz.exe")
    folder = exe.rsplit("\\", 1)[0]
    pr, _, _ = ctx.pairing("S1", "image_basename", base(exe), ("SourceImage",), by_basename=True)
    c = t1 - timedelta(seconds=180)
    d = t1 + timedelta(seconds=4)
    return {
        "mimikatz": _marked(_row(exe, 1_355_680, c, c, t1 - timedelta(seconds=60), c), pr),
        # the real S1 file shows no file write: a labelled supplement, not evidence
        "creds_dump": _marked(
            _row(rf"{folder}\sekurlsa_out.txt", 18_342, d, d, d, d), Pairing(synthetic_only=True)
        ),
    }


def _attacker_srv(ctx: GenContext, rng: random.Random) -> Attacker:
    """SRV-FILE-02: S3 shows only a PowerShell stager; PsExec artifacts belong to S4 (R2/R3)."""
    pr, _, t3 = ctx.pairing(
        "S3", "image_basename", "powershell.exe", ("Image",), event_id=1, by_basename=True
    )
    pf = f"C:\\Windows\\Prefetch\\POWERSHELL.EXE-{rng.getrandbits(32):08X}.pf"
    out = {"ps_prefetch": _marked(_row(pf, 63_244, t3, t3, t3, t3), pr)}
    pr, masq, t4 = ctx.pairing(
        "S4", "image_basename", "svchost.exe", ("Image",), event_id=17, by_basename=True
    )
    c = t4 - timedelta(seconds=3)
    out["renamed_svchost"] = _marked(_row(masq.facts["Image"], 381_328, c, c, t4, c), pr)
    pr, client, _ = ctx.pairing(
        "S4", "image_basename", "psexec.exe", ("Image",), event_id=18, by_basename=True
    )
    c = t4 - timedelta(seconds=12)  # the client must exist before its first use
    out["psexec_client"] = _marked(_row(client.facts["Image"], 833_024, c, c, t4, c), pr)
    return out


def _attacker(ctx: GenContext, host: str, rng: random.Random) -> Attacker:
    """Attacker artifacts for this host, keyed by tag; times come from real key events."""
    if host == "WS-FIN-07":
        return _attacker_ws(ctx)
    if host == "SRV-FILE-02":
        return _attacker_srv(ctx, rng)
    return {}


def generate_fs(ctx: GenContext, host: str) -> FsResult:
    """Rows for one host (record_id assigned after a seeded shuffle) and artifact record IDs."""
    rng = ctx.rng(f"fs:{host}")
    atk = _attacker(ctx, host, rng)
    rows = _benign(ctx, host, rng)
    rows += [r for r, _ in atk.values()]
    rows.sort(key=lambda r: r["path"].lower())
    for i, r in enumerate(rows, 1):
        r["record_id"], r["host"] = str(i), host
    ids = {tag: int(r["record_id"]) for tag, (r, _) in atk.items()}
    return FsResult(rows, ids, {tag: p for tag, (_, p) in atk.items()})


def render_fs(ctx: GenContext, rows: list[dict[str, str]]) -> str:
    """CSV text with the SYNTHETIC marker and a scenario comment as first lines."""
    buf = io.StringIO()
    buf.write(MARKER + "\n")
    buf.write(f"# scenario={ctx.scenario.scenario_id} kind=file_system_timeline\n")
    w = csv.DictWriter(buf, fieldnames=FS_COLUMNS, lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()
