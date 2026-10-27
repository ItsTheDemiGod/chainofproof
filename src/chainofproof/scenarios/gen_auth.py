"""Companion B (SYNTHETIC): per-host authentication / network log, key=value lines.

Benign lines are seeded and share the vocabulary of the key lines (``gen_benign``, ``gen_conns``).
A few lines describe the SAME actions as real key events and carry ``pair=<field>:<value>`` naming
the value they share with the real event(s) (rule R1); the cross-host link lines are
``synth_only=1``. ``seq`` is assigned after sorting and increases by exactly 1 per line within a
host. All hosts are generated together because connection ids are global (time-ordered).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from chainofproof.scenarios.companions import MARKER, Pairing, fmt_ts
from chainofproof.scenarios.gen_benign import benign_lines
from chainofproof.scenarios.gen_conns import assign_ids, benign_conns, conn_lines
from chainofproof.scenarios.gen_context import GenContext
from chainofproof.scenarios.gen_links import SYNTH, link_conns
from chainofproof.scenarios.gen_vocab import HOSTS, host_ips

Keyed = list[tuple[str, dict[str, str], Pairing]]  # (tag, line, pairing)


@dataclass
class AuthResult:
    """Lines of one host (dicts, seq already assigned) and the seq of each key line (tag -> seq)."""

    lines: list[dict[str, str]]
    key_seq: dict[str, int]
    pairings: dict[str, Pairing]  # tag -> pairing of each key line (and link line)
    link_seq: dict[str, int] = field(default_factory=dict)  # tag -> seq of each link line


def _key_lines(ctx: GenContext, host: str) -> Keyed:
    """(tag, line, pairing) for lines that correspond to real key events (rule R1).

    S3 contributes no line: the real S3 file shows no network logon, so nothing is invented.
    """
    ips = host_ips(ctx)
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


def _pipe_lines(ctx: GenContext, host: str, ip: str) -> Keyed:
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


def _assemble(host: str, plain: list[dict[str, str]], keyed: Keyed) -> AuthResult:
    """Sort benign + key lines by time (ties by content, not by origin) and number them."""
    items = [("", r, None) for r in plain] + [(t, r, p) for t, r, p in keyed]
    items.sort(key=lambda it: (it[1]["ts"], sorted(it[1].items())))
    lines, key_seq, link_seq = [], {}, {}
    for i, (tag, r, pr) in enumerate(items, 1):  # seq is assigned after insertion: contiguous
        if tag and pr is not None:
            k, _, v = pr.marker().partition("=")  # pair=<f>:<v> or synth_only=1
            r = {**r, k: v}
            (link_seq if tag.startswith("LINK_") else key_seq)[tag] = i
        lines.append({"seq": f"{i:06d}", **r})
    return AuthResult(lines, key_seq, {t: p for t, _, p in keyed}, link_seq)


def generate_all_auth(ctx: GenContext) -> dict[str, AuthResult]:
    """Auth logs of all three hosts; connections (benign and key) are placed and numbered first."""
    ips = host_ips(ctx)
    keys = link_conns(ctx)
    conns = keys + benign_conns(ctx, keys)
    assign_ids(conns)
    keyed = {h: _key_lines(ctx, h) for h in HOSTS}
    plain: dict[str, list[dict[str, str]]] = {h: [] for h in HOSTS}
    for c in conns:
        src, dst = conn_lines(c, ips)
        if c.tag:
            keyed[c.src].append((f"{c.tag}:src", src, SYNTH))
            keyed[c.dst].append((f"{c.tag}:dst", dst, SYNTH))
        else:
            plain[c.src].append(src)
            plain[c.dst].append(dst)
    total = ctx.scenario.noise.benign_auth_lines_total
    for i, h in enumerate(HOSTS):
        count = total // len(HOSTS) + (1 if i < total % len(HOSTS) else 0)
        exclude = ctx.real_pipes.get(h, frozenset())
        plain[h] += benign_lines(ctx, h, count, exclude)
    return {h: _assemble(h, plain[h], keyed[h]) for h in HOSTS}


def render_auth(ctx: GenContext, lines: list[dict[str, str]]) -> str:
    """Log text with the SYNTHETIC marker; one ``k=v`` line per event."""
    head = [MARKER, f"# scenario={ctx.scenario.scenario_id} kind=auth_network_log"]
    body = [" ".join(f"{k}={v}" for k, v in ln.items()) for ln in lines]
    return "\n".join(head + body) + "\n"
