"""Benign standalone auth lines (v4): same event types, users, services and IP ranges as key lines.

Required vocabulary is placed with fixed minimum counts (forced lines), the rest is drawn by weight:
type 9 logons of user01 on the workstation, directory-replication requests of a sync service
account on the DC, named-pipe lines with ordinary names, a few failed logons.
"""

from __future__ import annotations

import random

from chainofproof.scenarios.companions import fmt_ts
from chainofproof.scenarios.gen_context import GenContext
from chainofproof.scenarios.gen_time import host_span, sample_time
from chainofproof.scenarios.gen_vocab import (
    CLIENT_IPS,
    HOSTS,
    LOGON_TYPES,
    OTHER_IPS,
    SHARES,
    USERS,
    host_ips,
    humans,
    logon_id,
    pipe_name,
    weighted,
)

EVENTS: dict[str, list[tuple[str, int]]] = {
    "WS-FIN-07": [
        ("LOGON_SUCCESS", 34),
        ("LOGOFF", 22),
        ("KERBEROS_TGS_REQUEST", 16),
        ("NAMED_PIPE_OPEN", 14),
        ("LOGON_FAILURE", 4),
    ],  # fmt: skip
    "SRV-FILE-02": [
        ("LOGON_SUCCESS", 24),
        ("LOGOFF", 16),
        ("SMB_SESSION_SETUP", 16),
        ("SMB_TREE_CONNECT", 24),
        ("NAMED_PIPE_OPEN", 12),
        ("LOGON_FAILURE", 4),
    ],  # fmt: skip
    "DC-01": [
        ("KERBEROS_TGT_REQUEST", 22),
        ("KERBEROS_TGS_REQUEST", 30),
        ("LOGON_SUCCESS", 18),
        ("LOGON_FAILURE", 6),
        ("NAMED_PIPE_OPEN", 8),
    ],  # fmt: skip
}
FORCED = {  # (event, count): vocabulary that key lines use and benign lines must also show
    "WS-FIN-07": [("LOGON_SUCCESS:9", 7)],
    "DC-01": [("DIRECTORY_REPLICATION_REQUEST", 8)],
    "SRV-FILE-02": [],
}


def _client_ip(rng: random.Random, host: str, ips: dict[str, str]) -> str:
    """Where a non-local logon comes from: other workstations, the logged hosts, odd addresses."""
    pick = rng.random()
    if pick < 0.7:
        return rng.choice(CLIENT_IPS)
    if pick < 0.8:
        return rng.choice(OTHER_IPS)
    return rng.choice([ips[h] for h in HOSTS if h != host])


def _row(
    ctx: GenContext, rng: random.Random, host: str, spec: str, exclude: frozenset[str]
) -> dict:
    ips = host_ips(ctx)
    own = ips[host]
    event, _, forced_type = spec.partition(":")
    lo, hi = host_span(ctx, host)
    row = {"ts": fmt_ts(sample_time(rng, lo, hi)), "host": host, "event": event}
    if event == "NAMED_PIPE_OPEN":
        row |= {"user": "unknown", "src_ip": own, "dst_host": host}
        return row | {"pipe": pipe_name(rng, host, exclude)}
    if event == "DIRECTORY_REPLICATION_REQUEST":
        user = rng.choice(["svc_adsync", "svc_adsync", "Administrator"])
        return row | {
            "user": user,
            "src_ip": "unknown",
            "dst_host": host,
            "logon_id": logon_id(rng),
        }
    user = weighted(rng, humans(host) if event.startswith("LOGON") else USERS[host])
    ltype = forced_type or weighted(rng, LOGON_TYPES[host])
    local = event == "LOGOFF" or ltype in ("2", "5", "9")
    src = own if local and rng.random() < 0.9 else _client_ip(rng, host, ips)
    row |= {"user": user, "src_ip": src, "dst_host": host}
    if forced_type:
        row["user"] = "user01"
    if event.startswith("LOGON"):
        row["logon_type"] = ltype
    if event in ("LOGON_SUCCESS", "LOGOFF", "SMB_SESSION_SETUP"):
        row["logon_id"] = logon_id(rng)
    if event == "SMB_TREE_CONNECT":
        row["share"] = rng.choice(SHARES)
    if event == "KERBEROS_TGS_REQUEST":
        row["service"] = rng.choice(["cifs", "ldap", "host"]) + "/" + host
    return row


def benign_lines(
    ctx: GenContext, host: str, count: int, exclude: frozenset[str]
) -> list[dict[str, str]]:
    """``count`` standalone lines of one host (forced vocabulary first, then weighted draws)."""
    rng = ctx.rng(f"auth:{host}")
    specs = [s for s, n in FORCED[host] for _ in range(n)]
    specs += [weighted(rng, EVENTS[host]) for _ in range(max(count - len(specs), 0))]
    return [_row(ctx, rng, host, s, exclude) for s in specs]
