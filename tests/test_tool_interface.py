"""Phase 5.1: typed signatures, lenient filters, templated errors, prompts v2, worker rules."""

import dataclasses
import json

import pytest

from agent_helpers import (
    PERT,
    PLANNER_FINISH,
    WORKER_FINISH,
    delegate,
    draft,
    events,
    finding,
    make_case,
    settings,
    tool,
)
from chainofproof.agents import prompts, store
from chainofproof.agents.planner import REVIEW_TASK
from chainofproof.agents.runner import run_agent
from chainofproof.agents.trace import read_trace
from chainofproof.llm.fake import FakeLLMClient
from chainofproof.tools import query, registry
from chainofproof.tools.describe import ISO_EXAMPLE, tool_signature, tool_signature_lines
from chainofproof.tools.registry import ROLES, TOOLS, ToolError, call_tool
from evfactory import ev
from test_agent_prompts import BLOCK, forbidden_in, plain

MARK = "ZZMARK_7731"


def harness(role, name, args, paths):
    return call_tool(role, name, args, paths, PERT, harness=True)


# ---- describe ----------------------------------------------------------------------------
def test_every_registered_tool_has_a_signature_line_and_roles_get_theirs():
    for name in TOOLS:
        line = tool_signature(name)
        assert line and line.startswith(f"{name}(") and "): " in line
    for role in ROLES:
        assert [x.split("(")[0] for x in tool_signature_lines(role)] == registry.allowed_tools(role)
    assert tool_signature("nope") is None


def test_signature_lines_show_types_enums_defaults_and_a_generic_time_example():
    s = tool_signature("search_events")
    assert "host?: str|list[str]" in s and "event_id?: int|list[int]" in s
    assert "event_type?: enum[process_create|" in s and "|list[enum[" in s
    assert f"time_from?: ISO-8601 UTC string like {ISO_EXAMPLE}" in s
    assert "limit?: int<=50" in s and "offset?: int=0" in s
    assert "evidence_label: str" in tool_signature("source_summary")  # required: no ?
    assert "direction?: enum[out|in|both]=both" in tool_signature("neighbors")
    assert "min_abs_delta_seconds?: float=2.0" in tool_signature("detect_clock_skew")
    assert "host: str|list[str]" in tool_signature("timeline_window")
    blob = "\n".join(tool_signature(n) or "" for n in TOOLS)
    assert "2024" not in blob and forbidden_in(blob) == []


# ---- lenient filters ---------------------------------------------------------------------
def search(paths, **args):
    return harness("extractor", "search_events", args, paths)


def test_host_filter_takes_one_value_a_list_or_an_empty_list(synth_norm):
    paths, _ = synth_norm
    a = search(paths, host="DC-01", limit=50)
    b = search(paths, host="SRV-FILE-02", limit=50)
    both = search(paths, host=["DC-01", "SRV-FILE-02"], limit=50)  # regression: a list works
    assert a["total_matches"] and b["total_matches"]
    assert both["total_matches"] == a["total_matches"] + b["total_matches"]
    assert {e["host"] for e in both["events"]} <= {"DC-01", "SRV-FILE-02"}
    assert search(paths, host=[])["total_matches"] == search(paths)["total_matches"]
    assert search(paths, host=["DC-01"])["total_matches"] == a["total_matches"]


def test_other_filters_accept_lists_enums_and_integers(synth_norm):
    paths, _ = synth_norm
    total = search(paths, event_type=["auth_logon", "auth_conn"])["total_matches"]
    one = search(paths, event_type="auth_logon")["total_matches"]
    assert total > one > 0
    eid = events(paths, PERT, 1)[0]
    lbl = eid["evidence_label"]
    assert search(paths, evidence_label=[lbl])["total_matches"] > 0
    assert search(paths, event_id=[1, 2, 3])["total_matches"] >= 0
    assert search(paths, event_id=4624)["total_matches"] >= 0
    uid = search(paths, conn_id=["CONN-0001", "CONN-0002"])
    assert {e["conn_id"] for e in uid["events"]} <= {"CONN-0001", "CONN-0002"}
    win = harness("extractor", "timeline_window",
                  {"host": ["DC-01", "WS-FIN-07"], "start": "2024-03-12T00:00:00Z",
                   "end": "2024-03-12T23:59:59Z", "limit": 5}, paths)  # fmt: skip
    assert win["returned"] == 5 and win["truncated"]
    det = harness("extractor", "get_detections", {"evidence_label": [lbl, "AUTH-000000"]}, paths)
    assert det["returned"] == 0  # synthetic-only data has no detections; the list form is accepted


def test_values_are_bound_as_parameters_never_string_built(synth_norm):
    paths, _ = synth_norm
    r = search(paths, host=["x' OR 1=1 --", "DC-01"])
    assert {e["host"] for e in r["events"]} == {"DC-01"}
    assert search(paths, user="' OR '1'='1")["total_matches"] == 0
    clauses, args = query._in_clauses({"host": ["a", "b", "c"], "user": None, "conn_id": []})
    assert clauses == ["e.host IN (?,?,?)"] and args == ["a", "b", "c"]


def test_bounds_and_truncation_flags_are_kept(synth_norm):
    paths, _ = synth_norm
    r = search(paths, host=["DC-01", "SRV-FILE-02", "WS-FIN-07"], limit=5000)
    assert r["returned"] == 50 and r["truncated"] and r["total_matches"] > 50
    assert search(paths, host="DC-01")["returned"] == 25  # default limit


@pytest.mark.parametrize("args,needle", [
    ({"host": ["a"] * 11}, "host expects str|list[str]"),
    ({"host": 5}, "host expects str|list[str]"),
    ({"host": {"a": MARK}}, "host expects"),
    ({"event_type": MARK}, "event_type expects enum["),
    ({"event_type": [MARK]}, "event_type expects enum["),
    ({"event_id": MARK}, "event_id expects int|list[int]"),
    ({"event_id": [1] * 11}, "event_id expects"),
    ({"time_from": MARK}, f"time_from expects ISO-8601 UTC string like {ISO_EXAMPLE}"),
    ({"time_to": "2024-03-12 09:00:00"}, "time_to expects ISO-8601 UTC string"),
    ({"time_to": "2024-03-12T09:00:00+02:00"}, "time_to expects"),
    ({"limit": MARK}, "limit expects int<=50"),
    ({MARK: 1}, "unknown parameter (allowed: conn_id, event_id,"),
])  # fmt: skip
def test_argument_errors_are_templated_and_never_echo_the_supplied_value(synth_norm, args, needle):
    paths, _ = synth_norm
    with pytest.raises(ToolError) as e:
        search(paths, **args)
    msg = str(e.value)
    assert msg.startswith("invalid arguments for search_events: ") and needle in msg
    assert MARK not in msg and "x'" not in msg and "\n" not in msg


def test_good_timestamps_with_and_without_fractions_are_accepted(synth_norm):
    paths, _ = synth_norm
    for t in ("2024-03-12T09:00:00Z", "2024-03-12T09:00:00.5Z", "2024-03-12T09:00:00.123456Z"):
        assert "events" in search(paths, time_from=t, limit=1)


def test_missing_required_and_unknown_tool_messages_do_not_echo(synth_norm):
    paths, _ = synth_norm
    with pytest.raises(
        ToolError, match="source_summary: evidence_label is required|evidence_label is required"
    ):
        harness("planner", "source_summary", {}, paths)
    with pytest.raises(ToolError) as e:
        harness("planner", MARK, {}, paths)
    assert MARK not in str(e.value) and str(e.value).startswith("unknown tool")
    with pytest.raises(ToolError) as e:
        harness("correlator", "entity_summary", {"node_id": MARK}, paths)
    assert MARK not in str(e.value)


# ---- prompts v2 --------------------------------------------------------------------------
def test_tools_and_workers_sections_are_generated_from_the_registry(monkeypatch):
    for role in prompts.WORKER_ROLES:
        sec = prompts.tools_section(role)
        assert all(line in sec for line in tool_signature_lines(role))
        assert prompts.CITATION_FORMAT in prompts.worker_system(role)
    w = prompts.workers_section()
    for role in prompts.WORKER_ROLES:
        for name in registry.allowed_tools(role):
            assert f"{name}: {TOOLS[name].description}" in w
    assert (
        "consistency checks across sources" in w and prompts.planner_system().count("WORKERS") == 1
    )
    v = prompts.prompt_version()
    spec = TOOLS["detect_log_gap"]
    monkeypatch.setitem(TOOLS, "detect_log_gap", dataclasses.replace(spec, description="other"))
    assert prompts.prompt_version() != v
    assert "detect_log_gap(" in prompts.tools_section("correlator")


def test_citation_format_text_and_system_prompt_sizes():
    from chainofproof.llm.budget import estimate_tokens

    assert "NOT citable" in prompts.CITATION_FORMAT and "EVT-" in prompts.CITATION_FORMAT
    assert estimate_tokens(prompts.worker_system("extractor")) <= 1600
    # "about 1600" estimated tokens (characters / 3, conservative: roughly 1300 real tokens)
    assert estimate_tokens(prompts.worker_system("correlator")) <= 1800
    assert estimate_tokens(prompts.planner_system()) <= 1300


def run(paths, script, case=PERT, **agent):
    client = FakeLLMClient(script)
    return run_agent(paths, case, client, settings(**agent)), client


def worker_report(paths, res):
    return [x for x in read_trace(paths.runs_dir / res.run_id / "trace.jsonl")
            if x["action"] == "worker_report"]  # fmt: skip


def test_rendered_prompts_of_a_seed_case_pass_the_a2_scan_and_show_ids_first(tmp_path):
    e1 = ev("EVTX-111111", "2024-03-12T09:00:00.000000Z", "DC-01", "logon", user="bob")
    paths = make_case(tmp_path, [e1], case="credtheft_lateral_v4_s201_clean")
    script = [delegate(), tool("search_events", {"limit": 3}), WORKER_FINISH, PLANNER_FINISH]
    res, client = run(paths, script, case="credtheft_lateral_v4_s201_clean")
    assert res.status == "completed"
    for req in client.requests:
        for m in req["messages"]:
            assert forbidden_in(plain(m["content"])) == []
    obs = client.requests[2]["messages"][1]["content"]
    body = [b for b in BLOCK.findall(obs) if b[1] == "tool:search_events"][0][2]
    lines = body.splitlines()
    assert lines[0] == prompts.LEGEND and lines[2].startswith("EVT-")  # legend, header, event
    assert "TOOLS (? = optional parameter" in client.requests[1]["messages"][0]["content"]


# ---- worker rules ------------------------------------------------------------------------
def test_a_list_valued_filter_now_succeeds_end_to_end(synth_norm):
    paths, _ = synth_norm
    args = {"host": ["DC-01", "SRV-FILE-02"], "limit": 3}
    res, _ = run(paths, [delegate(), tool("search_events", args), WORKER_FINISH, PLANNER_FINISH])
    assert res.status == "completed" and res.counts["tool_errors"] == 0
    ids = [
        x for x in read_trace(paths.runs_dir / res.run_id / "trace.jsonl") if x["action"] == "tool"
    ]
    assert ids[-1]["tool"] == "search_events" and len(ids[-1]["event_uids"]) == 3


def test_a_label_instead_of_an_id_is_a_free_format_error_and_nothing_is_stored(synth_norm):
    paths, _ = synth_norm
    e = events(paths, PERT, 1)[0]
    bad = draft(e, cited_event_uids=[e["evidence_label"]])
    script = [delegate(), finding(bad), finding(draft(e)), WORKER_FINISH, PLANNER_FINISH]
    res, client = run(paths, script, worker_max_steps=2)
    assert [f.status for f in res.findings] == ["verified"]  # the bad one was never stored
    assert (
        res.counts["format_errors"] == 1 and store.get_run(paths, res.run_id)["format_errors"] == 1
    )
    obs = client.requests[2]["messages"][1]["content"]
    assert ("format error: cited ids must be EVT- or HIT- ids; labels are not citable; "
            "offending count 1") in obs  # fmt: skip
    assert worker_report(paths, res)[0]["stop"] == "finished"  # the free error left steps to spare
    tr = read_trace(paths.runs_dir / res.run_id / "trace.jsonl")
    assert any(x["action"] == "finding_refused" and x["reason"] == "format" for x in tr)


def test_a_second_format_error_of_the_same_worker_consumes_a_step(synth_norm):
    paths, _ = synth_norm
    e = events(paths, PERT, 1)[0]
    bad = draft(e, cited_event_uids=["AUTH-123456"], cited_hit_ids=["HIT-1"])
    script = [delegate(), finding(bad), finding(bad), finding(bad), PLANNER_FINISH]
    res, _ = run(paths, script, worker_max_steps=2)
    assert not res.findings and res.counts["format_errors"] == 3
    assert worker_report(paths, res)[0]["stop"] == "step_budget"  # 1 free, then 2 steps used


def test_a_well_formed_but_nonexistent_id_is_stored_as_rejected_v1(synth_norm):
    paths, _ = synth_norm
    e = events(paths, PERT, 1)[0]
    script = [delegate(), finding(draft(e, cited_event_uids=["EVT-000000000000"])),
              WORKER_FINISH, PLANNER_FINISH]  # fmt: skip
    res, _ = run(paths, script)
    (f,) = res.findings
    assert f.status == "rejected" and f.verification.codes() == ["V1"]
    assert res.counts.get("format_errors", 0) == 0


def test_duplicates_are_refused_counted_and_not_findings(synth_norm):
    paths, _ = synth_norm
    e = events(paths, PERT, 3)
    a = draft(e[0])
    same_claim = draft(e[1], claim="  " + a["claim"].upper() + "\n")  # same normalised text
    same_ids = draft(e[0], claim="a different sentence about the same record")
    fresh = draft(e[1], claim="something else entirely")
    script = [delegate(), finding(a), finding(same_claim), finding(same_ids), finding(fresh),
              WORKER_FINISH, PLANNER_FINISH]  # fmt: skip
    res, client = run(paths, script)
    assert [f.claim for f in res.findings] == [a["claim"], "something else entirely"]
    assert res.counts["duplicate_refusals"] == 2
    assert store.get_run(paths, res.run_id)["duplicate_refusals"] == 2
    seen = " ".join(r["messages"][1]["content"] for r in client.requests)
    assert "duplicate refused: this repeats finding F1" in seen
    assert worker_report(paths, res)[0]["duplicates"] == 2


def test_a_revision_of_a_downgraded_finding_is_not_a_duplicate_of_its_parent(synth_norm):
    paths, _ = synth_norm
    e = events(paths, PERT, 1)[0]
    bad = draft(e, users=["nobody_here"])
    fixed = {**draft(e), "revises": "F1"}
    res, _ = run(paths, [delegate(), finding(bad), finding(fixed), WORKER_FINISH, PLANNER_FINISH])
    assert [f.status for f in res.findings] == ["downgraded", "verified"]
    assert res.findings[1].revised_from == res.findings[0].finding_id
    assert res.counts.get("duplicate_refusals", 0) == 0


def test_argument_errors_do_not_consume_steps_and_show_the_usage_line(synth_norm):
    paths, _ = synth_norm
    bad = tool("search_events", {"host": ["a"] * 11, "text": MARK})
    script = [delegate(), bad, bad, bad, tool("search_events", {"limit": 2}), WORKER_FINISH,
              PLANNER_FINISH]  # fmt: skip
    res, client = run(paths, script, worker_max_steps=2)
    rep = worker_report(paths, res)[0]
    assert rep["stop"] == "finished" and rep["arg_errors"] == 3 and rep["tool_calls"] == 4
    assert store.get_run(paths, res.run_id)["arg_errors"] == 3 and res.status == "completed"
    nxt = client.requests[3]["messages"][1]["content"]
    assert "usage: search_events(host?: str|list[str]" in nxt and MARK not in nxt
    assert "Step 1 of 2" in nxt  # the step counter did not move


def test_the_argument_error_budget_ends_the_worker_and_is_not_an_llm_failure(synth_norm):
    paths, _ = synth_norm
    bad = tool("search_events", {"limit": MARK})
    script = [delegate(), bad, bad, bad, bad, PLANNER_FINISH]
    res, _ = run(paths, script, consecutive_failure_limit=2)  # 4 arg errors > the failure limit
    rep = worker_report(paths, res)[0]
    assert rep["stop"] == "arg_error_budget" and rep["arg_errors"] == 4
    assert res.status == "completed" and res.counts["tool_errors"] == 4


def test_permission_errors_still_consume_a_step(synth_norm):
    paths, _ = synth_norm
    script = [delegate("extractor"), tool("detect_log_gap"), tool("detect_log_gap"),
              PLANNER_FINISH]  # fmt: skip
    res, _ = run(paths, script, worker_max_steps=2)
    rep = worker_report(paths, res)[0]
    assert rep["stop"] == "step_budget" and rep["steps"] == 2 and rep["arg_errors"] == 0


def test_mandatory_correlator_review_forces_one_delegation_only_when_enabled(synth_norm):
    paths, _ = synth_norm
    res, _ = run(paths, [PLANNER_FINISH])
    assert res.delegations == []  # default: off
    res, _ = run(paths, [PLANNER_FINISH, WORKER_FINISH], mandatory_correlator_review=True)
    assert res.delegations == [("correlator", len(REVIEW_TASK))] and res.status == "completed"
    tr = read_trace(paths.runs_dir / res.run_id / "trace.jsonl")
    assert any(x["action"] == "forced_delegation" for x in tr)
    chosen = [delegate("correlator"), WORKER_FINISH, PLANNER_FINISH]
    res, _ = run(paths, chosen, mandatory_correlator_review=True)
    assert [r for r, _ in res.delegations] == ["correlator"]  # already delegated: nothing injected
    after = [delegate(), WORKER_FINISH, WORKER_FINISH]
    res, _ = run(paths, after, planner_max_rounds=1, mandatory_correlator_review=True)
    assert [r for r, _ in res.delegations] == ["extractor", "correlator"]
    assert res.status == "budget_exhausted"


def test_round_fixes_hit_lines_hypothesis_ids_id_cap_and_the_format_hint(synth_norm):
    from chainofproof.agents.observe import hit_line
    from chainofproof.schemas.agent import MAX_CITED, FindingDraft, HypothesisUpdate

    h = {"hit_id": "HIT-000001", "detector": "d", "kind": "k", "severity": "low", "hosts": ["H1"],
         "measures": {"label": "AUTH-0a1b2c", "n": 3}, "explanation": "e", "limitations": ["l"],
         "event_uids": ["EVT-0123456789ab"]}  # fmt: skip
    line = hit_line(h)
    assert "source_label=AUTH-0a1b2c" in line and " label=" not in line
    assert "cite_events=EVT-0123456789ab" in line and "n=3" in line
    assert HypothesisUpdate(id="hypothesis 1", status="open").id == "hypothesis 1"  # not an error
    with pytest.raises(Exception):  # noqa: B017 - pydantic ValidationError
        FindingDraft(claim="c", claim_type="anomaly", cited_event_uids=["x"] * (MAX_CITED + 1))
    assert MAX_CITED == 8 and "at most 8 per finding" in prompts.CITATION_FORMAT
    paths, _ = synth_norm
    e = events(paths, PERT, 1)[0]
    bad = draft(e, cited_event_uids=["0123456789ab"])
    res, client = run(paths, [delegate(), finding(bad), WORKER_FINISH, PLANNER_FINISH])
    seen = " ".join(r["messages"][1]["content"] for r in client.requests)
    assert "An EVT id looks like EVT-0123456789ab" in seen and not res.findings
    assert "Thresholds only (no filters); {} = defaults." in tool_signature("detect_log_gap")


def test_the_json_schema_of_the_settings_defaults_keeps_both_new_settings():
    from chainofproof.config import AgentSettings

    d = AgentSettings()
    assert d.max_arg_errors_per_worker == 4 and d.mandatory_correlator_review is False
    assert json.loads(json.dumps(d.model_dump()))["max_arg_errors_per_worker"] == 4
    assert PLANNER_FINISH["action"] == "finish"
