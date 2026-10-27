"""Notebook, action schemas and the trace writer."""

import json

import pytest
from pydantic import ValidationError

from chainofproof.agents.notebook import Notebook
from chainofproof.agents.trace import Trace, read_trace, tool_sequence
from chainofproof.llm.budget import estimate_tokens
from chainofproof.schemas.agent import (
    FindingDraft,
    HypothesisUpdate,
    NotebookUpdate,
    PlannerAction,
    WorkerAction,
)


def event(i, **kw):
    return {"event_uid": f"EVT-{i:012x}", "timestamp": "2024-03-12T09:00:00.000000Z",
            "host": "H1", "event_type": "logon", **kw}  # fmt: skip


def test_hypotheses_questions_findings_and_unknown_updates():
    nb = Notebook()
    nb.apply(NotebookUpdate(new_hypotheses=["a", "b"], new_questions=["q1"]))
    nb.apply(
        NotebookUpdate(
            hypothesis_updates=[
                HypothesisUpdate(id="H2", status="supported", note="n"),
                HypothesisUpdate(id="H9", status="refuted"),
            ]
        )
    )
    nb.add_finding("F1", "something verified")
    text = nb.render_text()
    assert "H1 [open] a" in text and "H2 [supported] b (n)" in text and "Q1 q1" in text
    assert "F1: something verified" in text and nb.dropped_updates == 1


def test_known_events_are_capped_oldest_first_and_fit_the_token_budget():
    nb = Notebook(known_events_cap=5)
    assert nb.add_events([event(i, user="u") for i in range(8)]) == 8
    assert list(nb.known)[0] == "EVT-000000000003" and len(nb.known) == 5
    assert nb.add_events([event(3)]) == 0 and list(nb.known)[-1] == "EVT-000000000003"
    big = Notebook(known_events_cap=500)
    big.set_survey(["S" * 700] * 6)
    big.add_events([event(i, user="u" * 100, process_image="p" * 100) for i in range(500)])
    assert estimate_tokens(big.render_text()) <= 1200
    assert "EVT-0000000001f3" in big.render_text()  # the newest events survive, oldest are dropped
    assert len(big.survey) <= 3


def test_notebook_is_saved_as_json(tmp_path):
    nb = Notebook()
    nb.add_events([event(1)])
    nb.save(tmp_path / "nb.json")
    assert json.loads((tmp_path / "nb.json").read_text())["known_events"]


def test_planner_action_schema_enforces_coherence_and_limits():
    ok = PlannerAction(rationale="r", action="delegate", worker_role="correlator", task="t")
    assert ok.notebook is None
    for bad in (
        {"action": "delegate", "task": "t"},
        {"action": "delegate", "worker_role": "extractor"},
        {"action": "delegate", "worker_role": "skeptic", "task": "t"},
        {"action": "run"},
    ):
        with pytest.raises(ValidationError):
            PlannerAction(rationale="r", **bad)
    with pytest.raises(ValidationError):
        PlannerAction(rationale="x" * 241, action="finish")
    with pytest.raises(ValidationError):
        PlannerAction(rationale="r", action="finish", surprise=1)
    PlannerAction(rationale="r", action="finish")


def test_worker_action_schema_enforces_coherence():
    WorkerAction(rationale="r", action="finish")
    WorkerAction(rationale="r", action="call_tool", tool="graph_stats")
    for bad in ({"action": "call_tool"}, {"action": "record_finding"}, {"action": "sleep"}):
        with pytest.raises(ValidationError):
            WorkerAction(rationale="r", **bad)
    with pytest.raises(ValidationError):
        WorkerAction(rationale="r", action="finish", handoff="x" * 301)
    d = FindingDraft(claim="c", claim_type="link", hosts=["A", "B"], users=["u"], revises="F2")
    fi = d.to_input()
    assert fi.entities.hosts == ["A", "B"] and fi.entities.users == ["u"] and fi.confidence == "low"
    with pytest.raises(ValidationError):
        FindingDraft(claim="c", claim_type="rumour")
    with pytest.raises(ValidationError):
        FindingDraft(claim="x" * 401, claim_type="anomaly")


def test_model_facing_schemas_stay_flat_and_small():
    s = json.dumps(WorkerAction.model_json_schema())
    assert "finding_id" not in s and "status" not in s  # the model never invents ids or statuses
    assert len(json.dumps(PlannerAction.model_json_schema())) < 2500 and len(s) < 4000


def test_trace_is_line_by_line_canonical_json_with_a_stable_hash(tmp_path):
    t = Trace(tmp_path / "t.jsonl")
    t.add("planner", "tool", tool="graph_stats", args_sha256="a" * 64, ok=True, extra=None)
    t.add("extractor", "worker_step", ok=False)
    h = t.close()
    lines = read_trace(tmp_path / "t.jsonl")
    assert [x["step"] for x in lines] == [1, 2] and "extra" not in lines[0]
    assert tool_sequence(lines) == [("planner", "graph_stats", "a" * 64, True)]
    raw = (tmp_path / "t.jsonl").read_text(encoding="utf-8").splitlines()
    assert raw[0] == json.dumps(json.loads(raw[0]), sort_keys=True, separators=(",", ":"))
    assert t.close() == h
