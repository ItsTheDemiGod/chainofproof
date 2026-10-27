"""Build the answer keys from the scenario, the inventory (real key events) and a generator run.

The key states WHAT was planted; tests re-measure the generated files independently and compare.
"""

from __future__ import annotations

from datetime import timedelta

from chainofproof.scenarios.gen_context import REAL_FMT, parse_real
from chainofproof.scenarios.generator import GenResult
from chainofproof.scenarios.inventory import Inventory, StageKeys
from chainofproof.scenarios.keyevents import APPENDED, LOG_CLEARED_TECHNIQUE, KeyEvent
from chainofproof.scenarios.keylinks import build_links
from chainofproof.schemas.scenario import (
    AnswerKey,
    Confidence,
    GroundTruthAction,
    GroundTruthDecoy,
    GroundTruthMissingEvidence,
    Role,
    Scenario,
    SupportingRef,
    Variant,
)

# (stage, technique) -> [(kind, tag)]: synthetic lines/files that carry the same action
SYNTH_REFS = {
    ("S1", "T1003.001"): [("fs", "mimikatz"), ("fs", "creds_dump")],
    ("S2", "T1550.002"): [("auth", "S2")],
    ("S3", "T1569.002"): [("fs", "ps_prefetch")],
    ("S4", "T1036.003"): [("fs", "renamed_svchost")],
    ("S4", "T1569.002"): [
        ("fs", "psexec_client"),
        ("auth", "S4_pipe:stdin"),
        ("auth", "S4_pipe:stdout"),
        ("auth", "S4_pipe:stderr"),
    ],
    ("S5", "T1003.006"): [("auth", "S5")],
}
# what the real events support, per (stage, technique); anything else is not asserted
DESCRIPTIONS = {
    ("S1", "T1003.001"): (
        "A Mimikatz binary reads LSASS memory (Sysmon 10). The SYNTHETIC credential-dump output "
        "file (synthetic_only) deliberately has an innocuous, document-like name and location."
    ),
    ("S2", LOG_CLEARED_TECHNIQUE): (
        "Security audit log cleared (EventID 1102) about 4.4 s before the new-credentials logon "
        "on the same host."
    ),
    ("S3", "T1021.002"): (
        "Remote service control reached the target over SMB: ntsvcs pipe opened by the System "
        "process and an inbound TCP 445 connection. No network logon and no ADMIN$ copy are "
        "present in the real file."
    ),
    ("S3", "T1569.002"): (
        "A new service key is written by services.exe and its command line runs a hidden "
        "PowerShell chain (cmd.exe then powershell.exe). PsExec itself is not visible."
    ),
    ("S4", "T1036.003"): (
        "A svchost.exe image outside System32 creates named pipes (renamed service binary)."
    ),
    ("S4", "T1569.002"): (
        "PsExec.exe connects the stdin/stdout/stderr pipes of the renamed service; the pipe "
        "naming scheme is PsExec's."
    ),
}
ACCOUNT_FACTS = ("TargetUserName", "SubjectUserName", "User")
DECOY_WHY = {
    "D1": "Winlogon Shell persistence on {host}: a separate incident with no shared account, "
    "host, tool or time window with the storyline. Linking it to the storyline is a false "
    "attribution.",
    "D2": "rundll32 advpack proxy execution on {host}: unrelated technique and host, no link "
    "to the credential-theft chain. Linking it to the storyline is a false attribution.",
}
MISSING = [
    (
        "No network packet capture is available, so the SMB data movement and the content of "
        "the PsExec/replication traffic cannot be inspected.",
        "S3/S5: that remote service creation and replication crossed the network from WS-FIN-07",
    ),
    (
        "No endpoint logs exist for the attacker's initial access (how the first foothold on "
        "WS-FIN-07 was obtained: phishing, exploit, valid account).",
        "The initial-access stage and the origin of the attack",
    ),
    (
        "No memory image of WS-FIN-07 or DC-01 is available.",
        "S1/S5: that credentials were actually extracted and which accounts were exposed",
    ),
    (
        "Real network-authentication evidence is still absent: no Security 4624 type 3 / 5140 / "
        "5145 and no ADMIN$ file copy exist for the remote service creation on SRV-FILE-02, and "
        "the real S5 4662 events show no source address. The real S3 file shows only the ntsvcs "
        "pipe, an inbound TCP 445 connection and the service/PowerShell activity. The SYNTHETIC "
        "synth_only cross-host lines ({conns}) stand in for this evidence; they are "
        "not proof that it exists in the real captures.",
        "S3/S5: which account authenticated, from which host, and that an admin share was used",
    ),
]


def _refs(events: list[KeyEvent], source_key: str) -> list[SupportingRef]:
    return [
        SupportingRef(source_key=source_key, event_record_id=e.record_id, event_id=e.event_id)
        for e in events
    ]


def _account(events: list[KeyEvent]) -> str | None:
    for e in events:
        for f in ACCOUNT_FACTS:
            if e.facts.get(f):
                return e.facts[f]
    return None


def _synth(gen: GenResult, stage: str, tech: str) -> list[SupportingRef]:
    """Refs to the synthetic records of an action, each with its pairing or synthetic_only."""
    out = []
    for kind, tag in SYNTH_REFS.get((stage, tech), []):
        found = (gen.fs_ids if kind == "fs" else gen.auth_seq).get(tag)
        if not found:  # a removed line (log gap) is simply absent
            continue
        pr = gen.pairings[tag]
        extra = (
            {"synthetic_only": True}
            if pr.synthetic_only
            else {
                "pairing_field": pr.field,
                "pairing_value": pr.value,
                "paired_source_key": pr.source_key,
                "paired_record_ids": list(pr.record_ids),
            }
        )
        out.append(SupportingRef(source_key=found[0], event_record_id=found[1], **extra))
    return out


def build_actions(scenario: Scenario, inv: Inventory, gen: GenResult) -> list[GroundTruthAction]:
    """One GT-ACT per (stage, technique) that has key events."""
    pending: list[tuple[str, str, StageKeys, list[KeyEvent]]] = []
    names = {s.stage_id: s.name for s in scenario.stages}
    for sk in inv.key_events:
        if sk.result.unresolved:
            continue  # nothing found: no action is invented (the inventory records why)
        for tech in sorted({t for e in sk.result.events for t in e.supports}):
            pending.append(
                (sk.stage_id, tech, sk, [e for e in sk.result.events if tech in e.supports])
            )
    pending.sort(key=lambda p: p[1] in APPENDED)  # stable: appended techniques come last
    actions: list[GroundTruthAction] = []
    for stage, tech, sk, evs in pending:
        al = scenario.aligned(sk.source_key)
        host = next(iter(al.host_aliases.values()))
        real = min(e.real_time for e in evs)
        virt = parse_real(real) + timedelta(seconds=al.time_offset_seconds)
        caveat = sk.result.technique_notes.get(tech, sk.result.note)
        note = f" Caveat: {caveat}." if caveat else ""
        actions.append(
            GroundTruthAction(
                id=f"GT-ACT-{len(actions) + 1:03d}",
                stage_id=stage,
                description=DESCRIPTIONS.get((stage, tech), f"{names[stage]} ({tech})."),
                attack_technique_id=tech,
                virtual_host=host,
                account=_account(evs),
                real_time=real,
                virtual_time=virt.strftime(REAL_FMT),
                supporting_refs=_refs(evs, sk.source_key) + _synth(gen, stage, tech),
                confidence=sk.result.technique_confidence.get(tech, Confidence.low),
                rationale="; ".join(dict.fromkeys(e.rationale for e in evs)) + "." + note,
            )
        )
    return actions


def build_key(scenario: Scenario, inv: Inventory, variant: Variant, gen: GenResult) -> AnswerKey:
    """The complete answer key of one variant."""
    decoys = []
    for s in scenario.sources:
        st = next((x for x in scenario.stages if x.stage_id == s.stage_id), None)
        if st is not None and st.role == Role.decoy:
            host = next(iter(scenario.aligned(s.source_key).host_aliases.values()))
            decoys.append(
                GroundTruthDecoy(
                    id=f"GT-DEC-{len(decoys) + 1:03d}",
                    source_key=s.source_key,
                    why_out_of_scope=DECOY_WHY[st.stage_id].format(host=host),
                )
            )
    return AnswerKey(
        scenario_id=scenario.scenario_id,
        variant=variant,
        seed=scenario.seed,
        actions=build_actions(scenario, inv, gen),
        contradictions=gen.contradictions if variant == Variant.perturbed else [],
        decoys=decoys,
        injections=[],
        links=build_links(scenario, inv, gen),
        missing_evidence=[
            GroundTruthMissingEvidence(
                id=f"GT-MIS-{i:03d}",
                description=d.replace("{conns}", ", ".join(gen.link_conn.values())),
                confirms_claim=c,
            )
            for i, (d, c) in enumerate(MISSING, 1)
        ],
        generated_file_hashes=dict(sorted(gen.hashes.items())),
    )
