"""Companion B (SYNTHETIC): per-host authentication / network log, key=value lines.

Benign lines are random but seeded. A few lines describe the SAME actions as real key events and
carry ``pair=<field>:<value>`` naming the value they share with the real event(s) (rule R1).
``seq`` is assigned
after sorting and increases by exactly 1 per line within a host.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import timedelta

from chainofproof.scenarios.companions import MARKER, Pairing, fmt_ts
from chainofproof.scenarios.gen_context import GenContext

USERS = ["a.rivera", "j.chen", "m.okafor", "s.novak", "t.haddad", "l.silva", "d.kim", "r.patel"]
SHARES = ["Finance", "Public", "Home$", "Projects"]
HOST_EVENTS = {
    "WS-FIN-07": ["LOGON_SUCCESS", "LOGON_SUCCESS", "LOGOFF", "KERBEROS_TGS_REQUEST"],
    "SRV-FILE-02": ["LOGON_SUCCESS", "SMB_SESSION_SETUP", "SMB_TREE_CONNECT", "SMB_TREE_CONNECT"],
    "DC-01": [
        "KERBEROS_TGT_REQUEST",
        "KERBEROS_TGS_REQUEST",
        "KERBEROS_TGS_REQUEST",
        "LOGON_SUCCESS",
        "LOGON_FAILURE",
    ],
}


@dataclass
class AuthResult:
    """Lines of one host (dicts, seq already assigned) and the seq of each key line (tag -> seq)."""

    lines: list[dict[str, str]]
    key_seq: dict[str, int]
    pairings: dict[str, Pairing]  # tag -> pairing of each key line


def _logon_id(rng: random.Random) -> str:
    return f"0x{rng.randint(0x100000, 0xFFFFFF):016x}"


def _benign(ctx: GenContext, host: str, count: int, rng: random.Random) -> list[dict[str, str]]:
    lo = ctx.start - timedelta(hours=2)
    out = []
    for _ in range(count):
        ev = rng.choice(HOST_EVENTS[host])
        row = {
            "ts": fmt_ts(lo + timedelta(seconds=rng.randint(0, 6 * 3600))),
            "host": host,
            "event": ev,
            "user": rng.choice(USERS),
            "src_ip": f"10.20.1.{rng.randint(10, 60)}",
            "dst_host": host,
        }
        if ev.startswith("LOGON") and ev != "LOGOFF":
            row["logon_type"] = str(rng.choice([2, 3, 3, 7, 10] if host == "WS-FIN-07" else [3]))
        if ev in ("LOGON_SUCCESS", "LOGOFF", "SMB_SESSION_SETUP"):
            row["logon_id"] = _logon_id(rng)
        if ev == "SMB_TREE_CONNECT":
            row["share"] = rng.choice(SHARES)
        if ev == "KERBEROS_TGS_REQUEST":
            row["service"] = rng.choice(["cifs", "ldap", "host"]) + "/" + host
        out.append(row)
    return out


def _key_lines(ctx: GenContext, host: str) -> list[tuple[str, dict[str, str], Pairing]]:
    """(tag, line, pairing) for lines that correspond to real key events (rule R1).

    S3 contributes no line: the real S3 file shows no network logon, so nothing is invented.
    """
    ips = {h.hostname: h.ip for h in ctx.scenario.virtual_hosts}
    if host == "WS-FIN-07":
        ev, t = ctx.first_key("S2", event_id=4624)
        lid = ev.facts["TargetLogonId"].lower()
        pr, _, _ = ctx.pairing("S2", "logon_id", lid, ("TargetLogonId", "SubjectLogonId"))
        line = {
            "ts": fmt_ts(t),
            "host": host,
            "event": "LOGON_SUCCESS",
            "user": ev.facts["TargetUserName"],
            "src_ip": ips[host],
            "dst_host": host,
            "logon_type": ev.facts["LogonType"],
            "logon_id": lid,
        }
        return [("S2", line, pr)]
    if host == "SRV-FILE-02":
        return _pipe_lines(ctx, host, ips[host])
    ev, _ = ctx.first_key("S5")
    lid = ev.facts["SubjectLogonId"].lower()
    pr, _, t = ctx.pairing("S5", "logon_id", lid, ("SubjectLogonId",))
    line = {
        "ts": fmt_ts(t),
        "host": host,
        "event": "DIRECTORY_REPLICATION_REQUEST",
        "user": ev.facts["SubjectUserName"],
        "src_ip": "unknown",  # the real 4662 events do not show where the request came from
        "dst_host": host,
        "logon_id": lid,
    }
    return [("S5", line, pr)]


def _pipe_lines(ctx: GenContext, host: str, ip: str) -> list[tuple[str, dict[str, str], Pairing]]:
    """One NAMED_PIPE_OPEN line per PsExec-style pipe the real S4 file shows being connected."""
    sk = ctx.inventory.keys_for("S4")
    pipes = sorted(
        {
            e.facts["PipeName"].lstrip("\\")
            for e in sk.result.events
            if e.event_id == 18 and e.facts.get("PipeName")
        }
    )
    out = []
    for pipe in pipes:
        pr, _, t = ctx.pairing("S4", "pipe_name", pipe, ("PipeName",), event_id=18)
        line = {
            "ts": fmt_ts(t),
            "host": host,
            "event": "NAMED_PIPE_OPEN",
            "user": "unknown",  # Sysmon 17/18 carry no account
            "src_ip": ip,  # local: the real PsExec.exe process runs on this host
            "dst_host": host,
            "pipe": pipe,
        }
        out.append((f"S4_pipe:{pipe.rsplit('-', 1)[-1]}", line, pr))
    return out


def generate_auth(ctx: GenContext, host: str) -> AuthResult:
    """Lines for one host, sorted by time, with contiguous per-host ``seq``."""
    rng = ctx.rng(f"auth:{host}")
    hosts = list(HOST_EVENTS)
    total = ctx.scenario.noise.benign_auth_lines_total
    count = total // len(hosts) + (1 if hosts.index(host) < total % len(hosts) else 0)
    keyed = _key_lines(ctx, host)
    pairings = {tag: pr for tag, _, pr in keyed}
    items = [("", r) for r in _benign(ctx, host, count, rng)] + [(t, r) for t, r, _ in keyed]
    items.sort(key=lambda it: it[1]["ts"])  # stable: key lines keep insertion order on ties
    lines, key_seq = [], {}
    for i, (tag, r) in enumerate(items, 1):
        if tag:
            r = {**r, "pair": f"{pairings[tag].field}:{pairings[tag].value}"}
            key_seq[tag] = i
        lines.append({"seq": f"{i:06d}", **r})
    return AuthResult(lines, key_seq, pairings)


def render_auth(ctx: GenContext, lines: list[dict[str, str]]) -> str:
    """Log text with the SYNTHETIC marker; one ``k=v`` line per event."""
    head = [MARKER, f"# scenario={ctx.scenario.scenario_id} kind=auth_network_log"]
    body = [" ".join(f"{k}={v}" for k, v in ln.items()) for ln in lines]
    return "\n".join(head + body) + "\n"
