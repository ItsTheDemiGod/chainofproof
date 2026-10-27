"""Agent runtime with scripted fake LLMs (no Ollama): paths, stops, budgets, replay."""

import json

from agent_helpers import (
    PERT,
    PLANNER_FINISH,
    WORKER_FINISH,
    delegate,
    draft,
    events,
    finding,
    happy_script,
    settings,
    tool,
)
from chainofproof.agents import store
from chainofproof.agents.replay import replay_run
from chainofproof.agents.runner import run_agent
from chainofproof.agents.trace import read_trace, tool_sequence
from chainofproof.custody.ledger import Ledger
from chainofproof.llm.fake import FakeClock, FakeLLMClient, FakeReply


def run(paths, script, case=PERT, clock=None, **agent):
    client = FakeLLMClient(script, clock=clock)
    kw = {"clock": clock} if clock else {}
    return run_agent(paths, case, client, settings(**agent), **kw), client


def test_happy_path_records_a_verified_finding_and_everything_is_ledgered(synth_norm):
    paths, _ = synth_norm
    e = events(paths, PERT, 1)[0]
    res, client = run(paths, happy_script(e))
    assert res.status == "completed" and res.stop_reason == "planner_finish"
    assert [f.status for f in res.findings] == ["verified"] and res.findings[0].finding_id
    assert res.delegations == [("extractor", len("look at the first source"))]
    assert res.counts["llm_calls"] == 5 and res.tool_names["search_events"] == 1
    run_dir = paths.runs_dir / res.run_id
    assert (run_dir / "llm" / "call_00005.json").is_file() and (run_dir / "notebook.json").is_file()
    row = store.get_run(paths, res.run_id)
    assert row["status"] == "completed" and row["trace_sha256"] == res.trace_sha256
    assert row["prompt_version"] and row["num_ctx"] == 8192 and row["input_sha256"]
    led = [x for x in Ledger(paths).read_all() if x.details.get("run_id") == res.run_id]
    acts = [x.action for x in led]
    assert acts[0] == "run_start" and acts[-1] == "run_end" and acts.count("llm_call") == 5
    assert acts.count("tool_call") == 9  # 8 survey calls (labels, 6 summaries, graph) + 1 search
    assert Ledger(paths).verify().ok
    # the ledger never holds prompt or response text
    blob = json.dumps([x.model_dump(mode="json") for x in led])
    assert e["event_uid"] not in blob and "Reply now" not in blob


def test_survey_is_done_by_code_through_the_registry_as_the_planner(synth_norm):
    paths, _ = synth_norm
    res, _ = run(paths, [PLANNER_FINISH])
    tr = read_trace(paths.runs_dir / res.run_id / "trace.jsonl")
    seq = [(r, t) for r, t, _, _ in tool_sequence(tr)]
    assert seq[0] == ("planner", "list_evidence_labels") and seq[-1] == ("planner", "graph_stats")
    assert {t for _, t in seq} == {"list_evidence_labels", "source_summary", "graph_stats"}
    assert res.counts["tool_calls"] == len(seq) == 8  # 6 sources + labels + graph


def test_no_detector_runs_unless_the_script_chooses_it(synth_norm):
    paths, _ = synth_norm
    e = events(paths, PERT, 1)[0]
    res, _ = run(paths, happy_script(e))
    assert not any(k.startswith("detect_") for k in res.tool_names)
    script = [delegate("correlator", "check consistency"), tool("detect_log_gap"),
              tool("get_hits"), WORKER_FINISH, PLANNER_FINISH]  # fmt: skip
    res2, _ = run(paths, script)
    assert res2.tool_names["detect_log_gap"] == 1 and res2.tool_names["get_hits"] == 1


def test_role_permission_and_invalid_args_become_error_observations(synth_norm):
    paths, _ = synth_norm
    script = [delegate("extractor"), tool("detect_log_gap"), tool("search_events", {"bogus": 1}),
              WORKER_FINISH, PLANNER_FINISH]  # fmt: skip
    res, client = run(paths, script)
    assert res.status == "completed" and res.counts["tool_errors"] == 2
    assert res.counts["llm_calls"] == 5  # errors cost steps, not LLM failures
    tr = read_trace(paths.runs_dir / res.run_id / "trace.jsonl")
    kinds = [x.get("error_kind") for x in tr if x["action"] == "tool" and not x["ok"]]
    assert kinds == ["permission", "args"]
    last_worker = [r for r in client.requests if r["role"] == "extractor"][-1]
    assert "tool_error" in last_worker["messages"][1]["content"]


def test_invalid_json_is_retried_then_succeeds_and_exhaustion_is_a_logged_failure(synth_norm):
    paths, _ = synth_norm
    res, client = run(paths, ["not json", "{}", PLANNER_FINISH])
    assert res.status == "completed" and res.counts["invalid_json"] == 2
    assert res.counts["retries"] == 2 and res.counts["llm_calls"] == 3
    retry = client.requests[1]["messages"][-1]["content"]
    assert "rejected by the schema check" in retry and "not json" not in retry
    res2, _ = run(paths, ["x", "y", "z", "x", "y", "z", "x", "y", "z"], planner_max_rounds=3)
    assert res2.status == "failed" and res2.stop_reason == "consecutive_failures"
    assert res2.counts["invalid_json"] == 9 and not res2.findings


def test_budgets_stop_the_run_with_the_right_status(synth_norm):
    paths, _ = synth_norm
    loop = [delegate(), WORKER_FINISH] * 6
    r = run(paths, loop, planner_max_rounds=2)[0]
    assert (r.status, r.stop_reason) == ("budget_exhausted", "planner_max_rounds")
    steps = [delegate(), *[tool("graph_stats")] * 3, PLANNER_FINISH]
    r = run(paths, [delegate("correlator"), *[tool("graph_stats")] * 5, PLANNER_FINISH],
            worker_max_steps=3)[0]  # fmt: skip
    assert r.counts["tool_calls"] == 8 + 3 and r.status == "completed" and steps
    r = run(paths, [delegate(), WORKER_FINISH, delegate(), WORKER_FINISH], max_llm_calls_per_run=3)[
        0
    ]
    assert (r.status, r.stop_reason) == ("budget_exhausted", "max_llm_calls_per_run")
    clock = FakeClock()
    slow = [
        FakeReply(delegate(), advance_s=100),
        FakeReply(WORKER_FINISH, advance_s=100),
        PLANNER_FINISH,
    ]
    r = run(paths, slow, clock=clock, max_run_seconds=150)[0]
    assert (r.status, r.stop_reason) == ("budget_exhausted", "max_run_seconds")


def test_ctrl_c_flushes_the_trace_and_marks_the_run_aborted(synth_norm):
    paths, _ = synth_norm

    def boom(messages, role):
        raise KeyboardInterrupt

    res, _ = run(paths, [delegate(), boom])
    assert res.status == "aborted" and res.stop_reason == "keyboard_interrupt"
    tr = (paths.runs_dir / res.run_id / "trace.jsonl").read_text(encoding="utf-8")
    assert '"action":"round"' in tr and store.get_run(paths, res.run_id)["trace_sha256"]


def test_fatal_llm_error_fails_the_run(synth_norm):
    paths, _ = synth_norm
    res, _ = run(paths, [FakeReply({}, fatal=True, error="context mismatch")])
    assert res.status == "failed" and res.stop_reason.startswith("llm_fatal")


def test_same_script_twice_gives_identical_trace_and_findings_and_replay_matches(synth_norm):
    paths, _ = synth_norm
    e = events(paths, PERT, 1)[0]
    a, _ = run(paths, happy_script(e))
    b, _ = run(paths, happy_script(e))

    def norm(r):
        lines = read_trace(paths.runs_dir / r.run_id / "trace.jsonl")
        keep = (
            "role",
            "action",
            "tool",
            "args_sha256",
            "ok",
            "act",
            "rationale",
            "status",
            "codes",
        )
        return [{k: x[k] for k in keep if k in x} for x in lines]

    assert norm(a) == norm(b)
    assert [(f.claim, f.status) for f in a.findings] == [(f.claim, f.status) for f in b.findings]
    rep = replay_run(paths, a.run_id, settings())
    assert rep.ok, rep.problems
    assert store.get_run(paths, rep.replay)["replay_of"] == a.run_id
    assert (paths.runs_dir / a.run_id).is_dir() and a.run_id != rep.replay


def test_replay_reports_divergence_with_the_call_index(synth_norm):
    paths, _ = synth_norm
    e = events(paths, PERT, 1)[0]
    a, _ = run(paths, happy_script(e))
    f = paths.runs_dir / a.run_id / "llm" / "call_00002.json"
    rec = json.loads(f.read_text(encoding="utf-8"))
    rec["prompt_sha256"] = "0" * 64
    f.write_text(json.dumps(rec), encoding="utf-8")
    rep = replay_run(paths, a.run_id, settings())
    assert not rep.ok and any("replay diverged at call 2" in p for p in rep.problems)


def test_detector_hits_in_a_replay_come_from_the_original_scope(synth_norm):
    paths, _ = synth_norm
    script = [delegate("correlator"), tool("detect_log_gap"), tool("get_hits"), WORKER_FINISH,
              PLANNER_FINISH]  # fmt: skip
    a, _ = run(paths, script)
    rep = replay_run(paths, a.run_id, settings())
    assert rep.ok, rep.problems


def test_a_finding_citing_a_harness_hit_is_rejected(synth_norm):
    paths, _ = synth_norm
    from chainofproof.tools.detectors.runner import run_detector

    hid = run_detector(paths, PERT, "log_gap").hits[0].hit_id  # harness hit
    e = events(paths, PERT, 1)[0]
    bad = draft(e, cited_hit_ids=[hid])
    res, _ = run(paths, [delegate(), finding(bad), WORKER_FINISH, PLANNER_FINISH])
    assert res.findings[0].status == "rejected"
    assert res.findings[0].verification.problems == [f"V1 unknown_hit {hid}"]


def test_revision_flow_is_limited(synth_norm):
    paths, _ = synth_norm
    e = events(paths, PERT, 1)[0]
    bad = draft(e, users=["nobody_here"])
    ok = draft(e)
    script = [delegate(), finding(bad), finding({**bad, "revises": "F1"}),
              finding({**bad, "revises": "F2"}), finding({**bad, "revises": "F3"}),
              finding({**ok, "revises": "F3"}), WORKER_FINISH, PLANNER_FINISH]  # fmt: skip
    res, client = run(paths, script, finding_revisions=2, worker_max_steps=8)
    st = [(f.status, f.revised_from) for f in res.findings]
    assert [s for s, _ in st] == ["downgraded", "downgraded", "downgraded"]
    assert st[1][1] == res.findings[0].finding_id and st[2][1] == res.findings[1].finding_id
    assert res.findings[0].confidence == "low"
    texts = " ".join(r["messages"][1]["content"] for r in client.requests)
    assert "revision limit (2) reached" in texts
