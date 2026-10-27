"""Cross-host connection lines (SYNTHETIC, Phase 2.2).

The real captures tie no host to another (S2 is a local logon, S3 has an inbound TCP 445 record with
no account, S4 is local PsExec, the real 4662 events show no source address). To give the
correlation task something to find, two connections are added to the synthetic auth logs. Every
line is ``synth_only=1`` (rule R1: nothing real shows it) and carries a ``conn_id`` shared by the
source-side and destination-side line of one connection:

* CONN-001 (LINK-A): WS-FIN-07 -> SRV-FILE-02, SMB, a type-3 logon of user01, at the S3 start.
* CONN-002 (LINK-B): SRV-FILE-02 -> DC-01, drsuapi, at the time of the real S5 DCSync events.
"""

from __future__ import annotations

from datetime import timedelta

from chainofproof.scenarios.companions import Pairing, fmt_ts
from chainofproof.scenarios.gen_context import GenContext, parse_real

CONN_A, CONN_B = "CONN-001", "CONN-002"
LINK_USER = "user01"  # the real account of the S2 file; the real S3 file shows no account
SYNTH = Pairing(synthetic_only=True)
Line = tuple[str, dict[str, str], Pairing]  # (tag, line, pairing)


def _time_a(ctx: GenContext) -> str:
    """S3 virtual start (whole seconds) plus a small deterministic offset."""
    s3 = ctx.scenario.aligned(ctx.inventory.keys_for("S3").source_key)
    start = parse_real(s3.virtual_first_key_event_time).replace(microsecond=0)
    return fmt_ts(start + timedelta(seconds=ctx.rng(f"link:{CONN_A}").randint(1, 5)))


def _time_b(ctx: GenContext) -> str:
    """Virtual time of the real S5 key event that the DC-01 DCSync line is paired with."""
    ev, _ = ctx.first_key("S5")
    _, _, t = ctx.pairing("S5", "logon_id", ev.facts["SubjectLogonId"].lower(), ("SubjectLogonId",))
    return fmt_ts(t)


def _line(ts: str, host: str, event: str, dst: str, src_ip: str, conn: str, **extra: str) -> dict:
    user = extra.pop("user", "unknown")  # connection records carry no account
    return {
        "ts": ts,
        "host": host,
        "event": event,
        "user": user,
        "src_ip": src_ip,
        "dst_host": dst,
        **extra,
        "conn_id": conn,
    }


def link_lines(ctx: GenContext, host: str) -> list[Line]:
    """The synthetic link lines that belong in ``host``'s auth log (tags ``LINK_A:src`` etc.)."""
    ip = {h.hostname: h.ip for h in ctx.scenario.virtual_hosts}
    ta, tb = _time_a(ctx), _time_b(ctx)
    ws, srv, dc = "WS-FIN-07", "SRV-FILE-02", "DC-01"
    if host == ws:
        row = _line(ta, ws, "CONN_OUT", srv, ip[ws], CONN_A, service="smb")
        return [("LINK_A:src", row, SYNTH)]
    if host == srv:
        a = _line(ta, srv, "LOGON_SUCCESS", srv, ip[ws], CONN_A, user=LINK_USER, logon_type="3")
        b = _line(tb, srv, "CONN_OUT", dc, ip[srv], CONN_B, service="drsuapi")
        return [("LINK_A:dst", a, SYNTH), ("LINK_B:src", b, SYNTH)]
    row = _line(tb, dc, "CONN_ACCEPTED", dc, ip[srv], CONN_B, service="drsuapi")
    return [("LINK_B:dst", row, SYNTH)]
