"""Ground-truth links (GT-LNK) of an answer key, and the check that their refs really resolve.

Two kinds of link: ``alignment_constructed`` (both ends are REAL records that the alignment layer
puts on the same host, in order) and ``synthetic_only`` (the connection exists only as SYNTHETIC
``synth_only=1`` lines that share a ``conn_id``). The real files never tie one host to another.
"""

from __future__ import annotations

from pathlib import Path

from chainofproof.scenarios.companions import parse_auth_log, row_marker
from chainofproof.scenarios.gen_links import CONN_A, CONN_B
from chainofproof.scenarios.generator import GenResult
from chainofproof.scenarios.inventory import Inventory
from chainofproof.scenarios.keyevents import KeyEvent
from chainofproof.schemas.scenario import (
    AnswerKey,
    GroundTruthLink,
    LinkBasis,
    LinkKind,
    LinkRef,
    Scenario,
)

CONN_OF = {"LINK_A": CONN_A, "LINK_B": CONN_B}
WS, SRV, DC = "WS-FIN-07", "SRV-FILE-02", "DC-01"


def _real(inv: Inventory, stage: str, event_id: int | None = None) -> LinkRef:
    """Reference to the first real key event of a stage (optionally with a given EventID)."""
    sk = inv.keys_for(stage)
    e: KeyEvent = next(e for e in sk.result.events if event_id in (None, e.event_id))
    return LinkRef(source_key=sk.source_key, event_record_id=e.record_id, event_id=e.event_id)


def _synth(gen: GenResult, *tags: str) -> list[LinkRef]:
    """References to the synthetic link lines present in this variant (removed ones are absent)."""
    out = []
    for tag in tags:
        if tag in gen.link_seq:
            sk, seq = gen.link_seq[tag]
            out.append(
                LinkRef(
                    source_key=sk,
                    event_record_id=seq,
                    synthetic_only=True,
                    conn_id=CONN_OF[tag.split(":")[0]],
                )
            )
    return out


def build_links(scenario: Scenario, inv: Inventory, gen: GenResult) -> list[GroundTruthLink]:
    """The four ground-truth links of the scenario."""
    account = next(
        e.facts["TargetUserName"] for e in inv.keys_for("S2").result.events if e.event_id == 4624
    )
    lost = "LINK_B:dst" not in gen.link_seq
    removed = (
        " In this variant the destination-side line was removed by the DC-01 log gap (GT-CON-003)."
        if lost
        else ""
    )
    return [
        GroundTruthLink(
            id="GT-LNK-001",
            from_host=WS,
            to_host=WS,
            kind=LinkKind.stage_continuation,
            basis=LinkBasis.alignment_constructed,
            from_stage="S1",
            to_stage="S2",
            evidence_refs=[_real(inv, "S1"), _real(inv, "S2", 4624)],
            real_evidence_note=(
                "S1 shows a process reading lsass.exe memory (Sysmon 10) but no account. S2 shows "
                f"a type 9 (new credentials) logon of {account} (Security 4624). Neither file "
                "refers to the other; the connection between them is by time and host mapping "
                "only (the alignment layer maps both captures to WS-FIN-07, S2 after S1)."
            ),
            expected_agent_statement=(
                "The LSASS read and the later new-credentials logon of "
                f"{account} on WS-FIN-07 are plausibly one sequence, but only the host and time "
                "mapping links them; no record shows the logon used the stolen secret."
            ),
        ),
        GroundTruthLink(
            id="GT-LNK-002",
            from_host=WS,
            to_host=SRV,
            kind=LinkKind.lateral_movement,
            basis=LinkBasis.synthetic_only,
            from_stage="S2",
            to_stage="S3",
            evidence_refs=_synth(gen, "LINK_A:src", "LINK_A:dst"),
            real_evidence_note=(
                "The real S3 file shows only an inbound TCP 445 connection (Sysmon 3) and the "
                "ntsvcs pipe on SRV-FILE-02; it does not show which account connected or from "
                f"which host. The real S2 file shows the {account} logon on WS-FIN-07 only, a "
                "local logon. The only evidence of a connection from WS-FIN-07 to SRV-FILE-02 is "
                f"the pair of SYNTHETIC synth_only lines with conn_id {CONN_A}."
            ),
            expected_agent_statement=(
                f"A SYNTHETIC SMB connection ({CONN_A}) and type 3 logon of {account} from "
                "WS-FIN-07 to SRV-FILE-02 is the only evidence of the hop; the real S3 file does "
                "not show the account or the source host."
            ),
        ),
        GroundTruthLink(
            id="GT-LNK-003",
            from_host=SRV,
            to_host=SRV,
            kind=LinkKind.stage_continuation,
            basis=LinkBasis.alignment_constructed,
            from_stage="S3",
            to_stage="S4",
            evidence_refs=[_real(inv, "S3"), _real(inv, "S4")],
            real_evidence_note=(
                "S3 shows a new service launching a hidden PowerShell chain. S4 shows a "
                "svchost.exe outside System32 creating PsExec-style named pipes. The two "
                "captures share no process, logon, pipe or account; the alignment layer maps "
                "both to SRV-FILE-02 (S4 after S3), so continuity rests on host and time mapping."
            ),
            expected_agent_statement=(
                "The service-launched PowerShell (S3) and the renamed PsExec service pipes (S4) "
                "on SRV-FILE-02 may belong to one intrusion, but only the host and time mapping "
                "connects them."
            ),
        ),
        GroundTruthLink(
            id="GT-LNK-004",
            from_host=SRV,
            to_host=DC,
            kind=LinkKind.remote_replication,
            basis=LinkBasis.synthetic_only,
            from_stage="S4",
            to_stage="S5",
            evidence_refs=_synth(gen, "LINK_B:src", "LINK_B:dst"),
            real_evidence_note=(
                "The real S5 file shows Security 4662 directory-replication access on the domain "
                "controller with an account and logon id but no source address or connection "
                "record; the real S4 file is local to SRV-FILE-02. Nothing real shows that "
                "SRV-FILE-02 made the replication request. The connection is shown only by "
                f"SYNTHETIC synth_only lines with conn_id {CONN_B}." + removed
            ),
            expected_agent_statement=(
                f"Only SYNTHETIC lines ({CONN_B}) place the replication request on SRV-FILE-02; "
                "the real DCSync events do not show where the request came from."
            ),
        ),
    ]


def check_link_refs(key: AnswerKey, scenario: Scenario, inv: Inventory, gen_dir: Path) -> list[str]:
    """Problems if a link ref does not resolve to a real key event or an existing synthetic line."""
    real = {(sk.source_key, e.record_id) for sk in inv.key_events for e in sk.result.events}
    logs: dict[str, dict[int, dict[str, str]]] = {}
    problems = []
    for ln in key.links:
        for r in ln.evidence_refs:
            where = f"{ln.id}: {r.source_key}:{r.event_record_id}"
            spec = scenario.source(r.source_key)
            if not spec.is_synthetic:
                if (r.source_key, r.event_record_id) not in real:
                    problems.append(f"{where}: not a real key event")
                continue
            if r.source_key not in logs:
                rows = parse_auth_log(gen_dir / spec.relative_path)
                logs[r.source_key] = {int(x["seq"]): x for x in rows}
            row = logs[r.source_key].get(r.event_record_id)
            if row is None:
                problems.append(f"{where}: no such line")
            elif row.get("conn_id") != r.conn_id or row_marker(row) is not True:
                problems.append(f"{where}: conn_id or synth_only marker differs")
    return problems
