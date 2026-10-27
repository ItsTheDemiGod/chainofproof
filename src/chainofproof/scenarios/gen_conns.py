"""Connections of the auth logs (v4): benign complete pairs and the two key links share ONE builder.

A connection has a source-side line on the initiating host (``CONN_OUT``) and a destination-side
line on the target host (``CONN_ACCEPTED``, or a type 3 ``LOGON_SUCCESS`` for smb) with the same
time and ``conn_id``. Benign connections exist only between the three logged hosts (both ends
present). Ids are assigned after every connection is placed in time order, so ids increase with
time and key connections get ordinary ids in the middle of the sequence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from chainofproof.scenarios.companions import fmt_ts, parse_ts
from chainofproof.scenarios.gen_context import GenContext
from chainofproof.scenarios.gen_time import host_span, sample_time
from chainofproof.scenarios.gen_vocab import humans, weighted
from chainofproof.schemas.scenario import ScenarioError

WS, SRV, DC = "WS-FIN-07", "SRV-FILE-02", "DC-01"
# (source host, destination host, service, weight): benign traffic routes
ROUTES = [
    (WS, SRV, "smb", 40),
    (WS, SRV, "rpc", 5),
    (WS, DC, "kerberos", 10),
    (WS, DC, "ldap", 10),
    (WS, DC, "rpc", 4),
    (SRV, DC, "kerberos", 9),
    (SRV, DC, "ldap", 9),
    (SRV, DC, "rpc", 3),
    (SRV, DC, "drsuapi", 9),  # DsCrackNames-style name resolution, not replication
]
GUARD = timedelta(seconds=300)  # no same-triple benign connection this close to a key link
SMB_LOGON_SHARE = 0.6  # share of benign smb connections whose destination end is a type 3 logon


@dataclass
class Conn:
    """One connection (benign, or a key link when ``tag`` is set)."""

    ts: str
    src: str
    dst: str
    service: str
    dest_event: str  # CONN_ACCEPTED or LOGON_SUCCESS
    user: str = "unknown"
    logon_type: str = ""
    tag: str = ""  # LINK_A / LINK_B for key links
    conn_id: str = ""


def _quotas(n: int) -> list[tuple[str, str, str]]:
    """Route list of length n by largest-remainder shares of the route weights (deterministic)."""
    total = sum(w for *_, w in ROUTES)
    exact = [n * w / total for *_, w in ROUTES]
    counts = [int(x) for x in exact]
    order = sorted(range(len(ROUTES)), key=lambda i: (counts[i] - exact[i], i))
    for i in order[: n - sum(counts)]:
        counts[i] += 1
    return [r[:3] for r, c in zip(ROUTES, counts, strict=True) for _ in range(c)]


def _near_key(c_ts: str, route: tuple[str, str, str], keys: list[Conn]) -> bool:
    t = parse_ts(c_ts)
    return any(
        (k.src, k.dst, k.service) == route and abs(t - parse_ts(k.ts)) <= GUARD for k in keys
    )


def benign_conns(ctx: GenContext, keys: list[Conn]) -> list[Conn]:
    """The benign connection pairs (count from the scenario's noise knob), guarded against keys."""
    rng = ctx.rng("conns")
    routes = _quotas(ctx.scenario.noise.benign_connection_pairs)
    rng.shuffle(routes)
    out = []
    for route in routes:
        src, dst, svc = route
        lo = max(host_span(ctx, src)[0], host_span(ctx, dst)[0])
        hi = min(host_span(ctx, src)[1], host_span(ctx, dst)[1])
        for _ in range(500):
            ts = fmt_ts(sample_time(rng, lo, hi))
            if not _near_key(ts, route, keys):
                break
        else:
            raise ScenarioError(f"no free time for a benign {src}->{dst} {svc} connection")
        if svc == "smb" and rng.random() < SMB_LOGON_SHARE:
            out.append(Conn(ts, src, dst, svc, "LOGON_SUCCESS", weighted(rng, humans(dst)), "3"))
        else:
            out.append(Conn(ts, src, dst, svc, "CONN_ACCEPTED"))
    return out


def assign_ids(conns: list[Conn]) -> None:
    """``CONN-0001``... in time order over ALL connections; key links must not be first or last."""
    conns.sort(key=lambda c: (c.ts, c.src, c.dst, c.service, c.tag))
    for i, c in enumerate(conns, 1):
        c.conn_id = f"CONN-{i:04d}"
    if any(c.tag and c in (conns[0], conns[-1]) for c in conns):
        raise ScenarioError("a key connection got the first or last conn_id")


def conn_lines(c: Conn, ips: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    """(source-side line, destination-side line) of a connection; same shape for benign and key."""
    src = {
        "ts": c.ts,
        "host": c.src,
        "event": "CONN_OUT",
        "user": "unknown",
        "src_ip": ips[c.src],
        "dst_host": c.dst,
        "service": c.service,
        "conn_id": c.conn_id,
    }
    dst = {
        "ts": c.ts,
        "host": c.dst,
        "event": c.dest_event,
        "user": c.user,
        "src_ip": ips[c.src],
        "dst_host": c.dst,
    }
    if c.dest_event == "LOGON_SUCCESS":
        dst["logon_type"] = c.logon_type
    else:
        dst["service"] = c.service
    dst["conn_id"] = c.conn_id
    return src, dst
