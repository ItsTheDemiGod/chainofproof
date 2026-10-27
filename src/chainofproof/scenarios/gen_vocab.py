"""Shared vocabulary of the benign auth background (v4): the SAME users, events, services and IP
ranges the key lines use, so key-referenced lines are not separable by superficial features."""

from __future__ import annotations

import random

from chainofproof.scenarios.gen_context import GenContext

HOSTS = ("WS-FIN-07", "SRV-FILE-02", "DC-01")
# (account, weight): about 8 per host; user01 is the legitimate user of WS-FIN-07 and uses shares
USERS: dict[str, list[tuple[str, int]]] = {
    "WS-FIN-07": [
        ("user01", 10),
        ("a.rivera", 3),
        ("j.chen", 3),
        ("m.okafor", 2),
        ("s.novak", 2),
        ("WS-FIN-07$", 4),
        ("svc_backup", 2),
        ("Administrator", 1),
    ],  # fmt: skip
    "SRV-FILE-02": [
        ("user01", 4),
        ("a.rivera", 4),
        ("j.chen", 4),
        ("t.haddad", 3),
        ("l.silva", 3),
        ("SRV-FILE-02$", 4),
        ("svc_backup", 3),
        ("Administrator", 2),
    ],  # fmt: skip
    "DC-01": [
        ("Administrator", 3),
        ("a.rivera", 3),
        ("j.chen", 3),
        ("d.kim", 2),
        ("r.patel", 2),
        ("DC-01$", 6),
        ("svc_adsync", 2),
        ("user01", 3),
    ],  # fmt: skip
}
# logon types per host role; type 9 (new credentials) is added separately on the workstation
LOGON_TYPES: dict[str, list[tuple[str, int]]] = {
    "WS-FIN-07": [("2", 55), ("3", 10), ("5", 8), ("10", 5)],
    "SRV-FILE-02": [("3", 70), ("5", 10), ("10", 4), ("2", 1)],
    "DC-01": [("3", 60), ("2", 8), ("10", 5)],
}
CLIENT_IPS = [f"10.20.1.{n}" for n in range(10, 61)]  # other workstations (no log here)
OTHER_IPS = [
    "10.20.4.11",
    "10.20.4.12",
    "10.20.5.20",
    "10.20.5.21",
    "10.20.3.20",
]  # printer, servers
SHARES = ["Finance", "Public", "Home$", "Projects"]
PIPES = {  # ordinary names; templates add embedded hexadecimal / process ids
    "WS-FIN-07": ["spoolss", "srvsvc", "lsarpc"],
    "SRV-FILE-02": ["srvsvc", "spoolss", "atsvc", "lsarpc"],
    "DC-01": ["netlogon", "samr", "lsarpc", "srvsvc"],
}


def host_ips(ctx: GenContext) -> dict[str, str]:
    """Virtual hostname -> synthetic address."""
    return {h.hostname: h.ip for h in ctx.scenario.virtual_hosts}


def weighted(rng: random.Random, pairs: list[tuple[str, int]]) -> str:
    """One value from (value, weight) pairs."""
    return rng.choices([v for v, _ in pairs], [w for _, w in pairs])[0]


def humans(host: str) -> list[tuple[str, int]]:
    """The host's accounts without machine accounts (those cannot log on as a person)."""
    return [(u, w) for u, w in USERS[host] if not u.endswith("$")]


def logon_id(rng: random.Random) -> str:
    """A random logon id in the format the key lines use."""
    return f"0x{rng.randint(0x100000, 0xFFFFFF):016x}"


def pipe_name(rng: random.Random, host: str, exclude: frozenset[str]) -> str:
    """A benign pipe name that no real pipe event of this host carries (rule G1)."""
    while True:
        pick = rng.random()
        if pick < 0.55:
            name = rng.choice(PIPES[host])
        elif pick < 0.8:
            name = f"mojo.{rng.randint(300, 9000)}.{rng.randint(300, 9000)}.{rng.getrandbits(60)}"
        elif pick < 0.92:
            name = f"CatalogChangeListener-{rng.getrandbits(24):x}-0"
        else:
            name = f"crashpad_{rng.randint(300, 9000)}_{rng.getrandbits(40):010X}"
        if name.lower() not in exclude:
            return name
