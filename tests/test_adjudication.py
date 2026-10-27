"""Adjudication file: loader, validation and the scoring policy; plus the 1102 key entry."""

from pathlib import Path

import pytest

from chainofproof.scenarios.fieldscan import load_known_events
from chainofproof.schemas.adjudication import (
    POLICY,
    Adjudication,
    AdjudicationEntry,
    Verdict,
    load_adjudication,
    save_adjudication,
)
from chainofproof.schemas.scenario import ScenarioError, Variant

V4 = Path(__file__).resolve().parents[1] / "scenarios" / "credtheft_lateral_v4"


@pytest.fixture
def adj(v4):
    keys = list(v4.keys.values())
    return load_adjudication(
        V4 / "adjudication.yaml", v4.scn, keys, load_known_events(V4 / "field_inspection.json")
    )


def entry(**kw):
    base = dict(
        id="GT-ADJ-001",
        source_key="s3_psexec_smb",
        event_record_id=9810,
        event_id=10,
        verdict=Verdict.unclear,
        reason="r",
        decided_by="t",
    )
    return AdjudicationEntry(**{**base, **kw})


def test_committed_file_is_valid_and_drafts_are_flagged(adj):
    assert adj.policy == POLICY
    assert len(adj.entries) == 10
    assert {e.verdict for e in adj.entries} == {
        Verdict.true_finding,
        Verdict.unclear,
        Verdict.not_attack,
    }
    assert all(e.decided_by.startswith("reviewed and approved by Demian") for e in adj.entries)
    assert {e.id for e in adj.entries if e.verdict == Verdict.true_finding} == {
        "GT-ADJ-001",
        "GT-ADJ-006",
    }


def test_policy_scoring(adj, v4):
    keys = list(v4.keys.values())
    assert adj.score("s3_psexec_smb", 9806, keys) == "key"  # the service ImagePath write
    assert adj.score("s3_psexec_smb", 9813, keys) == "true_positive"  # listed true_finding
    assert adj.score("s3_psexec_smb", 9810, keys) == "unclear"  # listed unclear
    assert adj.score("s4_renamed_psexec", 409654, keys) == "false_positive"  # listed not_attack
    assert adj.score("s3_psexec_smb", 99999, keys) == "unlisted"  # not listed at all
    extra = Adjudication(
        scenario_id=adj.scenario_id,
        policy=POLICY,
        entries=[entry(verdict=Verdict.true_finding)],
    )
    assert extra.score("s3_psexec_smb", 9810, keys) == "true_positive"


def test_every_nonkey_event_of_inspected_sources_is_accounted_for(adj, v4):
    """Rows not in the key are either adjudicated or are the known benign 4688/other leftovers."""
    keys = list(v4.keys.values())
    for sk in ("s3_psexec_smb", "s4_renamed_psexec"):
        for r in v4.rows(sk):
            assert adj.score(sk, r["record_id"], keys) != "unlisted", (sk, r["record_id"])


def test_validation_errors(v4):
    keys = list(v4.keys.values())

    def build(entries):
        return Adjudication(scenario_id=v4.scn.scenario_id, policy=POLICY, entries=entries)

    with pytest.raises(ValueError, match="duplicate"):
        build([entry(), entry()])
    with pytest.raises(ValueError, match="not a real source"):
        build([entry(source_key="fs_ws_fin_07")]).check_against(v4.scn, keys)
    with pytest.raises(ValueError, match="already in the answer key"):
        build([entry(event_record_id=9806, event_id=13)]).check_against(v4.scn, keys)
    with pytest.raises(ValueError, match="not found"):
        build([entry(event_id=3)]).check_against(
            v4.scn, keys, load_known_events(V4 / "field_inspection.json")
        )
    with pytest.raises(ValueError, match="different scenario"):
        Adjudication(scenario_id="other", policy=POLICY, entries=[]).check_against(v4.scn, keys)
    with pytest.raises(ValueError, match="empty"):
        Adjudication(scenario_id="x", policy=" ", entries=[])


def test_loader_roundtrip_and_errors(tmp_path, v4):
    p = tmp_path / "a.yaml"
    save_adjudication(
        p, Adjudication(scenario_id=v4.scn.scenario_id, policy=POLICY, entries=[entry()])
    )
    assert load_adjudication(p, v4.scn, list(v4.keys.values())).entries[0].event_record_id == 9810
    p.write_text("scenario_id: x\npolicy: p\nentries:\n- id: bad\n", encoding="utf-8")
    with pytest.raises(ScenarioError, match="a.yaml"):
        load_adjudication(p)
    with pytest.raises(ScenarioError):
        load_adjudication(tmp_path / "missing.yaml")


# ---- the Security 1102 (audit log cleared) entry ------------------------------------------------
@pytest.mark.parametrize("variant", list(Variant))
def test_1102_action_in_both_keys(v4, variant):
    acts = [a for a in v4.keys[variant].actions if a.attack_technique_id == "T1070.001"]
    assert len(acts) == 1
    a = acts[0]
    assert (a.id, a.stage_id, a.virtual_host) == ("GT-ACT-008", "S2", "WS-FIN-07")
    assert a.confidence.value == "medium"
    assert [(r.source_key, r.event_record_id, r.event_id) for r in a.supporting_refs] == [
        ("s2_pth_logon", 432901, 1102)
    ]
    assert "lab preparation" in a.rationale
    rows = {r["record_id"]: r for r in v4.rows("s2_pth_logon")}
    assert rows[432901]["event_id"] == 1102


def test_existing_action_ids_did_not_move(v4):
    got = [(a.id, a.stage_id, a.attack_technique_id) for a in v4.keys[Variant.clean].actions]
    assert got == [
        ("GT-ACT-001", "S1", "T1003.001"),
        ("GT-ACT-002", "S2", "T1550.002"),
        ("GT-ACT-003", "S3", "T1021.002"),
        ("GT-ACT-004", "S3", "T1569.002"),
        ("GT-ACT-005", "S4", "T1036.003"),
        ("GT-ACT-006", "S4", "T1569.002"),
        ("GT-ACT-007", "S5", "T1003.006"),
        ("GT-ACT-008", "S2", "T1070.001"),
    ]


def test_1102_precedes_the_4624_by_about_four_seconds(v4):
    rows = {r["record_id"]: r for r in v4.rows("s2_pth_logon")}
    d = v4.aligned("s2_pth_logon", rows[432903]) - v4.aligned("s2_pth_logon", rows[432901])
    assert 4 <= d.total_seconds() <= 5


def test_s3_service_link_is_stated_with_its_gaps(v4):
    for variant in Variant:
        smb = next(a for a in v4.keys[variant].actions if a.attack_technique_id == "T1021.002")
        assert "no network logon" in (smb.description + smb.rationale).lower()
        assert smb.confidence.value == "medium"
