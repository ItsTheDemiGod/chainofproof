"""Companion B (SYNTHETIC): per-host authentication / network log, key=value lines.

Benign lines are random but seeded. A few lines describe the SAME actions as real key events
(same user, same logon id where the real event has one, same virtual time). ``seq`` is assigned
after sorting and increases by exactly 1 per line within a host.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import timedelta

from chainofproof.scenarios.companions import MARKER, fmt_ts
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


def _key_lines(ctx: GenContext, host: str, rng: random.Random) -> list[tuple[str, dict[str, str]]]:
    """(tag, line) for lines that correspond to real key events."""
    ips = {h.hostname: h.ip for h in ctx.scenario.virtual_hosts}
    if host == "WS-FIN-07":
        ev, t = ctx.first_key("S2", event_id=4624)
        return [
            (
                "S2",
                {
                    "ts": fmt_ts(t),
                    "host": host,
                    "event": "LOGON_SUCCESS",
                    "user": ev.facts["TargetUserName"],
                    "src_ip": ips[host],
                    "dst_host": host,
                    "logon_type": ev.facts["LogonType"],
                    "logon_id": ev.facts["TargetLogonId"].lower(),
                },
            )
        ]
    if host == "SRV-FILE-02":
        user = ctx.first_key("S2", event_id=4624)[0].facts["TargetUserName"]
        _, t = ctx.first_key("S3", event_id=18)
        lid = _logon_id(rng)
        base = {
            "ts": fmt_ts(t),
            "host": host,
            "user": user,
            "src_ip": ips["WS-FIN-07"],
            "dst_host": host,
        }
        return [
            ("S3_logon", {**base, "event": "LOGON_SUCCESS", "logon_type": "3", "logon_id": lid}),
            (
                "S3_smb",
                {**base, "event": "SMB_ADMIN_SHARE_CONNECT", "share": "ADMIN$", "logon_id": lid},
            ),
        ]
    ev, t = ctx.first_key("S5")
    return [
        (
            "S5",
            {
                "ts": fmt_ts(t),
                "host": host,
                "event": "DIRECTORY_REPLICATION_REQUEST",
                "user": ev.facts["SubjectUserName"],
                "src_ip": ips["WS-FIN-07"],
                "dst_host": host,
                "logon_id": ev.facts["SubjectLogonId"].lower(),
            },
        )
    ]


def generate_auth(ctx: GenContext, host: str) -> AuthResult:
    """Lines for one host, sorted by time, with contiguous per-host ``seq``."""
    rng = ctx.rng(f"auth:{host}")
    hosts = list(HOST_EVENTS)
    total = ctx.scenario.noise.benign_auth_lines_total
    count = total // len(hosts) + (1 if hosts.index(host) < total % len(hosts) else 0)
    keyed = _key_lines(ctx, host, rng)
    items = [("", r) for r in _benign(ctx, host, count, rng)] + keyed
    items.sort(key=lambda it: it[1]["ts"])  # stable: key lines keep insertion order on ties
    lines, key_seq = [], {}
    for i, (tag, r) in enumerate(items, 1):
        lines.append({"seq": f"{i:06d}", **r})
        if tag:
            key_seq[tag] = i
    return AuthResult(lines, key_seq)


def render_auth(ctx: GenContext, lines: list[dict[str, str]]) -> str:
    """Log text with the SYNTHETIC marker; one ``k=v`` line per event."""
    head = [MARKER, f"# scenario={ctx.scenario.scenario_id} kind=auth_network_log"]
    body = [" ".join(f"{k}={v}" for k, v in ln.items()) for ln in lines]
    return "\n".join(head + body) + "\n"
