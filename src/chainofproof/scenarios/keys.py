"""Build the answer keys from the scenario, the inventory (real key events) and a generator run.

The key states WHAT was planted; tests re-measure the generated files independently and compare.
"""

from __future__ import annotations

from datetime import timedelta

from chainofproof.scenarios.gen_context import REAL_FMT, parse_real
from chainofproof.scenarios.generator import GenResult
from chainofproof.scenarios.inventory import Inventory
from chainofproof.scenarios.keyevents import KeyEvent
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
    ("S3", "T1021.002"): [("auth", "S3_logon"), ("auth", "S3_smb")],
    ("S3", "T1569.002"): [("fs", "psexesvc")],
    ("S4", "T1036.003"): [("fs", "renamed_svchost")],
    ("S5", "T1003.006"): [("auth", "S5")],
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
    out = []
    for kind, tag in SYNTH_REFS.get((stage, tech), []):
        found = (gen.fs_ids if kind == "fs" else gen.auth_seq).get(tag)
        if found:  # a removed line (log gap) is simply absent
            out.append(SupportingRef(source_key=found[0], event_record_id=found[1]))
    return out


def build_actions(scenario: Scenario, inv: Inventory, gen: GenResult) -> list[GroundTruthAction]:
    """One GT-ACT per (stage, technique) that has key events."""
    actions: list[GroundTruthAction] = []
    names = {s.stage_id: s.name for s in scenario.stages}
    for sk in inv.key_events:
        if sk.result.unresolved:
            continue  # nothing found: no action is invented (the inventory records why)
        al = scenario.aligned(sk.source_key)
        host = next(iter(al.host_aliases.values()))
        for tech in sorted({t for e in sk.result.events for t in e.supports}):
            evs = [e for e in sk.result.events if tech in e.supports]
            real = min(e.real_time for e in evs)
            virt = parse_real(real) + timedelta(seconds=al.time_offset_seconds)
            note = f" Caveat: {sk.result.note}." if sk.result.note else ""
            actions.append(
                GroundTruthAction(
                    id=f"GT-ACT-{len(actions) + 1:03d}",
                    stage_id=sk.stage_id,
                    description=f"{names[sk.stage_id]} ({tech}).",
                    attack_technique_id=tech,
                    virtual_host=host,
                    account=_account(evs),
                    real_time=real,
                    virtual_time=virt.strftime(REAL_FMT),
                    supporting_refs=_refs(evs, sk.source_key) + _synth(gen, sk.stage_id, tech),
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
        missing_evidence=[
            GroundTruthMissingEvidence(id=f"GT-MIS-{i:03d}", description=d, confirms_claim=c)
            for i, (d, c) in enumerate(MISSING, 1)
        ],
        generated_file_hashes=dict(sorted(gen.hashes.items())),
    )
