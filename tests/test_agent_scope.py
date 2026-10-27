"""Agent scoping (rules A3, A7): agent_run_id, hit visibility, restricted DB access."""

import sqlite3
from contextlib import closing

import pytest

from agent_helpers import PERT
from chainofproof.custody.db import connect, restricted_reads
from chainofproof.tools import registry
from chainofproof.tools.detectors.runner import run_detector, stored_hits
from chainofproof.tools.registry import ToolError, call_tool


def test_a_tool_call_needs_exactly_one_of_agent_run_id_or_harness(synth_norm):
    paths, _ = synth_norm
    with pytest.raises(ToolError, match="exactly one of agent_run_id"):
        call_tool("planner", "graph_stats", {}, paths, PERT)
    with pytest.raises(ToolError, match="exactly one of agent_run_id"):
        call_tool("planner", "graph_stats", {}, paths, PERT, "RUN-800001", harness=True)
    assert call_tool("planner", "graph_stats", {}, paths, PERT, "RUN-800001")["node_count"] > 100
    assert call_tool("planner", "graph_stats", {}, paths, PERT, harness=True)["node_count"] > 100


def test_get_hits_is_empty_at_run_start_and_harness_hits_are_invisible(synth_norm):
    paths, _ = synth_norm
    run_detector(paths, PERT, "log_gap")  # a harness hit exists
    assert stored_hits(paths, PERT).total_matches > 0
    page = call_tool("correlator", "get_hits", {}, paths, PERT, "RUN-800002")
    assert page["total_matches"] == 0 and page["hits"] == []
    harness_id = stored_hits(paths, PERT, "log_gap").hits[0].hit_id
    one = call_tool("correlator", "get_hits", {"hit_id": harness_id}, paths, PERT, "RUN-800002")
    assert one["returned"] == 0  # not even by id


def test_agent_detector_run_is_stored_as_agent_origin_and_seen_only_by_its_run(synth_norm):
    paths, _ = synth_norm
    before = stored_hits(paths, PERT).total_matches
    r = call_tool("correlator", "detect_log_gap", {}, paths, PERT, "RUN-800003")
    assert r["hit_count"] > 0
    own = call_tool("correlator", "get_hits", {}, paths, PERT, "RUN-800003")
    assert {h["hit_id"] for h in own["hits"]} == {h["hit_id"] for h in r["hits"]}
    other = call_tool("correlator", "get_hits", {}, paths, PERT, "RUN-800004")
    assert other["total_matches"] == 0
    assert stored_hits(paths, PERT).total_matches == before  # the harness view is unchanged
    with closing(connect(paths.db_path)) as c:
        marks = ",".join("?" * len(r["hits"]))
        rows = c.execute(
            f"SELECT DISTINCT origin, agent_run_id FROM detector_hits WHERE hit_id IN ({marks})",
            [h["hit_id"] for h in r["hits"]],
        ).fetchall()
        assert [tuple(x) for x in rows] == [("agent", "RUN-800003")]


def test_agent_detector_rerun_is_idempotent_per_run_detector_and_params(synth_norm):
    paths, _ = synth_norm
    a = call_tool("correlator", "detect_log_gap", {}, paths, PERT, "RUN-800005")
    b = call_tool("correlator", "detect_log_gap", {}, paths, PERT, "RUN-800005")
    assert a == b and a["hit_count"] > 0
    c = call_tool("correlator", "detect_log_gap", {"max_other_events_listed": 3}, paths, PERT,
                  "RUN-800005")  # fmt: skip
    assert c["run_id"] != a["run_id"]  # other parameters: a new stored run
    d = call_tool("correlator", "detect_log_gap", {}, paths, PERT, "RUN-800006")
    assert d["run_id"] != a["run_id"]
    assert {h["hit_id"] for h in d["hits"]}.isdisjoint({h["hit_id"] for h in a["hits"]})
    with closing(connect(paths.db_path)) as conn:
        n = conn.execute("SELECT COUNT(*) FROM detector_runs WHERE agent_run_id = 'RUN-800005'")
        assert n.fetchone()[0] == 2


def test_the_restricted_connection_cannot_read_or_write_the_eval_table(synth_norm):
    paths, _ = synth_norm
    with closing(connect(paths.db_path)) as c:  # an unrestricted connection can, of course
        assert c.execute("SELECT COUNT(*) FROM event_eval_meta").fetchone()[0] > 0
    with restricted_reads(), closing(connect(paths.db_path)) as c:
        for sql in (
            "SELECT * FROM event_eval_meta",
            "SELECT source_key FROM event_eval_meta",
            "DELETE FROM event_eval_meta",
            "SELECT COUNT(*) FROM event_eval_meta",
        ):
            with pytest.raises(sqlite3.DatabaseError, match="prohibited|not authorized"):
                c.execute(sql)
        assert c.execute("SELECT COUNT(*) FROM events").fetchone()[0] > 0  # agent view still works
    with closing(connect(paths.db_path)) as c:  # the restriction ended with the block
        assert c.execute("SELECT COUNT(*) FROM event_eval_meta").fetchone()[0] > 0


def test_a_query_on_event_eval_meta_fails_inside_an_agent_tool_call(synth_norm, monkeypatch):
    paths, _ = synth_norm

    def probe(p, case, a):
        with closing(connect(p.db_path)) as c:
            c.execute("SELECT * FROM event_eval_meta").fetchall()
        raise AssertionError("the eval table was readable")

    spec = registry.TOOLS["graph_stats"]
    monkeypatch.setitem(registry.TOOLS, "graph_stats", type(spec)(
        spec.name, spec.description, spec.params, spec.returns, spec.roles, probe))  # fmt: skip
    with pytest.raises(ToolError, match="database access denied"):
        call_tool("planner", "graph_stats", {}, paths, PERT, "RUN-800007")
    with pytest.raises(AssertionError, match="was readable"):  # harness: not restricted
        call_tool("planner", "graph_stats", {}, paths, PERT, harness=True)
