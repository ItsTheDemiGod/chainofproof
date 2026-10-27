"""Cross-host key connections (SYNTHETIC, Phase 2.2, rebuilt in v4).

The real captures tie no host to another (S2 is a local logon, S3 has an inbound TCP 445 record with
no account, S4 is local PsExec, the real 4662 events show no source address). To give the
correlation task something to find, two connections are added to the synthetic auth logs. Every
line is ``synth_only=1`` (rule R1: nothing real shows it) and the two ends share a ``conn_id``.
They are built by the same code as the benign connections (``gen_conns``); only the time, the
account and the marker differ:

* LINK_A: WS-FIN-07 -> SRV-FILE-02, SMB, a type-3 logon of user01, at the S3 start.
* LINK_B: SRV-FILE-02 -> DC-01, drsuapi, at the time of the real S5 DCSync events.

The ``conn_id`` values are assigned in ``gen_auth`` together with all benign connections.
"""

from __future__ import annotations

from datetime import timedelta

from chainofproof.scenarios.companions import Pairing, fmt_ts
from chainofproof.scenarios.gen_conns import DC, SRV, WS, Conn
from chainofproof.scenarios.gen_context import GenContext, parse_real

LINK_USER = "user01"  # the real account of the S2 file; the real S3 file shows no account
SYNTH = Pairing(synthetic_only=True)


def _time_a(ctx: GenContext) -> str:
    """S3 virtual start (whole seconds) plus a small deterministic offset."""
    s3 = ctx.scenario.aligned(ctx.inventory.keys_for("S3").source_key)
    start = parse_real(s3.virtual_first_key_event_time).replace(microsecond=0)
    return fmt_ts(start + timedelta(seconds=ctx.rng("link:A").randint(1, 5)))


def _time_b(ctx: GenContext) -> str:
    """Virtual time of the real S5 key event that the DC-01 DCSync line is paired with."""
    ev, _ = ctx.first_key("S5")
    _, _, t = ctx.pairing("S5", "logon_id", ev.facts["SubjectLogonId"].lower(), ("SubjectLogonId",))
    return fmt_ts(t)


def link_conns(ctx: GenContext) -> list[Conn]:
    """The two key connections (conn_id not yet assigned)."""
    return [
        Conn(_time_a(ctx), WS, SRV, "smb", "LOGON_SUCCESS", LINK_USER, "3", tag="LINK_A"),
        Conn(_time_b(ctx), SRV, DC, "drsuapi", "CONN_ACCEPTED", tag="LINK_B"),
    ]
