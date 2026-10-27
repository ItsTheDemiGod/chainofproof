"""Tool registry: roles, argument validation, schemas, outputs, stored detector runs."""

import functools
import json

import pytest

from chainofproof.tools.detectors import DETECTORS
from chainofproof.tools.detectors.runner import run_detector, stored_hits
from chainofproof.tools.registry import (
    FORBIDDEN_KEYS,
    ROLES,
    TOOLS,
    ToolError,
    allowed_tools,
    export_schemas,
)
from chainofproof.tools.registry import call_tool as _call_tool

call_tool = functools.partial(_call_tool, harness=True)  # these tests act as the harness

PERT = "credtheft_lateral_v4_perturbed"
QUERY = {"list_evidence_labels", "search_events", "get_event", "timeline_window", "source_summary"}
GRAPH = {"graph_stats", "entity_summary", "neighbors", "find_paths", "host_links"}
DETS = {f"detect_{n}" for n in DETECTORS}


def test_permission_table_matches_the_documented_policy():
    assert set(allowed_tools("planner")) == {
        "list_evidence_labels", "source_summary", "graph_stats", "get_hits"}  # fmt: skip
    assert set(allowed_tools("extractor")) == QUERY | {"get_detections"}
    assert set(allowed_tools("correlator")) == GRAPH | DETS | {
        "search_events",
        "get_event",
        "get_hits",
    }
    assert set(allowed_tools("skeptic")) == (
        {"get_event", "search_events", "timeline_window", "get_hits"} | GRAPH | DETS
    )
    assert set(allowed_tools("reporter")) == {"get_event", "get_hits", "host_links"}
    assert len(TOOLS) == 17 and set(ROLES) == {
        "planner",
        "extractor",
        "correlator",
        "skeptic",
        "reporter",
    }


def test_every_tool_is_registered_with_a_schema_without_forbidden_keys():
    def keys(o, acc):
        if isinstance(o, dict):
            for k, v in o.items():
                acc.add(k)
                keys(v, acc)
        elif isinstance(o, list):
            for v in o:
                keys(v, acc)
        return acc

    schemas = export_schemas()
    assert len(schemas) == len(TOOLS)
    for s in schemas:
        assert (
            s["name"] and s["description"] and s["roles"] and s["input_schema"]["type"] == "object"
        )
        assert not keys(s["returns"], set()) & FORBIDDEN_KEYS, s["name"]
        assert not keys(s["input_schema"], set()) & FORBIDDEN_KEYS, s["name"]
    assert {s["name"] for s in export_schemas("reporter")} == set(allowed_tools("reporter"))
    json.dumps(schemas)


def test_role_permission_is_enforced_and_unknowns_rejected(synth_norm):
    paths, _ = synth_norm
    with pytest.raises(ToolError, match="may not call"):
        call_tool("planner", "search_events", {}, paths, PERT)
    with pytest.raises(ToolError, match="may not call"):
        call_tool("reporter", "detect_log_gap", {}, paths, PERT)
    with pytest.raises(ToolError, match="unknown tool"):
        call_tool("planner", "drop_tables", {}, paths, PERT)
    with pytest.raises(ToolError, match="unknown role"):
        call_tool("root", "get_hits", {}, paths, PERT)


def test_invalid_arguments_give_a_clean_error(synth_norm):
    paths, _ = synth_norm
    for args in ({"limit": "many"}, {"bogus": 1}, {"event_id": "x"}):
        with pytest.raises(ToolError, match="invalid arguments for search_events") as e:
            call_tool("extractor", "search_events", args, paths, PERT)
        assert "Traceback" not in str(e.value) and "\n" not in str(e.value)
    with pytest.raises(ToolError, match="invalid arguments"):
        call_tool(
            "correlator",
            "detect_clock_skew",
            {"agreement_seconds": 1, "min_independent_pairs": "x"},
            paths,
            PERT,
        )
    with pytest.raises(ToolError, match="failed"):
        call_tool("correlator", "entity_summary", {"node_id": "host:NOPE"}, paths, PERT)


def test_tools_return_bounded_json_serializable_dicts(synth_norm):
    paths, _ = synth_norm
    r = call_tool("extractor", "search_events", {"limit": 5000}, paths, PERT)
    assert r["returned"] == 50 and r["truncated"] and json.dumps(r)
    uid = r["events"][0]["event_uid"]
    assert call_tool("reporter", "get_event", {"event_uid": uid}, paths, PERT)["returned"] == 1
    assert (
        call_tool("reporter", "get_event", {"event_uid": "EVT-000000000000"}, paths, PERT)[
            "returned"
        ]
        == 0
    )
    labels = call_tool("planner", "list_evidence_labels", {}, paths, PERT)["labels"]
    assert len(labels) == 6
    s = call_tool("planner", "source_summary", {"evidence_label": labels[0]["label"]}, paths, PERT)
    assert s["event_count"] == labels[0]["event_count"]
    assert call_tool("planner", "graph_stats", {}, paths, PERT)["node_count"] > 100


def test_detectors_are_separate_tools_and_never_run_by_other_tools(synth_norm):
    paths, _ = synth_norm
    before = stored_hits(paths, PERT).total_matches
    call_tool("planner", "graph_stats", {}, paths, PERT)
    call_tool("extractor", "search_events", {}, paths, PERT)
    assert stored_hits(paths, PERT).total_matches == before  # no tool ran a detector implicitly
    r = call_tool("skeptic", "detect_timestomp", {"min_delta_seconds": 3600}, paths, PERT)
    assert (
        r["detector"] == "timestomp"
        and r["hit_count"] == 2
        and r["params"]["min_delta_seconds"] == 3600
    )
    assert all(h["limitations"] and h["event_uids"] and h["hit_key"] for h in r["hits"])
    got = call_tool("reporter", "get_hits", {"detector": "timestomp"}, paths, PERT)
    assert got["total_matches"] == 2 and got["hits"][0]["hit_id"].startswith("HIT-")
    one = call_tool("reporter", "get_hits", {"hit_id": got["hits"][0]["hit_id"]}, paths, PERT)
    assert one["returned"] == 1


def test_detector_runs_are_repeatable_and_latest_run_wins(synth_norm):
    paths, _ = synth_norm
    a, b = (run_detector(paths, PERT, "log_gap") for _ in range(2))
    assert [h.hit_key for h in a.hits] == [h.hit_key for h in b.hits] and a.hits
    assert (
        a.run_id != b.run_id
        and a.input_sha256 == b.input_sha256
        and a.output_sha256 == b.output_sha256
    )
    assert {h.hit_id for h in a.hits}.isdisjoint({h.hit_id for h in b.hits})
    latest = stored_hits(paths, PERT, "log_gap")
    assert [h.hit_id for h in latest.hits] == [h.hit_id for h in b.hits]
    with pytest.raises(Exception, match="unknown detector"):
        run_detector(paths, PERT, "nope")
    with pytest.raises(Exception, match="unknown parameter"):
        run_detector(paths, PERT, "log_gap", {"nope": 1})
