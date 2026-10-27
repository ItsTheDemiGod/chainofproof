"""Shared helpers for the agent tests: scripted replies built from real events of a test case."""

from __future__ import annotations

from contextlib import closing

from chainofproof.config import get_paths, load_settings
from chainofproof.custody.db import connect
from chainofproof.ingest.store import EvidenceStore
from chainofproof.tools.norm_store import insert_events, insert_run
from chainofproof.tools.registry import call_tool

PERT = "credtheft_lateral_v4_perturbed"
CLEAN = "credtheft_lateral_v4_clean"

PLANNER_FINISH = {"rationale": "enough", "action": "finish", "finish_reason": "done"}
WORKER_FINISH = {"rationale": "done", "action": "finish", "handoff": "nothing more"}


def make_case(tmp_path, evs, case="RICH"):
    """A fresh database holding one case with exactly these in-memory events."""
    paths = get_paths(base_dir=tmp_path / "b")
    paths.ensure_dirs()
    EvidenceStore(paths).create_case(case)
    with closing(connect(paths.db_path)) as conn:
        conn.execute(
            f"INSERT INTO evidence VALUES ('EV-000001','{case}','n','p','v',1,'ab','log_text',"
            "'x','2024-01-01','me')"
        )
        insert_run(conn, "RUN-000001", "EV-000001", case, 3, "abc", len(evs), "LED-000001")
        insert_events(conn, "RUN-000001", evs)
    return paths


def settings(**agent):
    """Default settings with agent overrides."""
    s = load_settings()
    s.agent = s.agent.model_copy(update=agent)
    return s


def events(paths, case, n=3, **filters):
    """The first ``n`` events matching the filters (harness query, agent-view dicts)."""
    args = {"limit": n, **filters}
    return call_tool("extractor", "search_events", args, paths, case, harness=True)["events"]


def delegate(role="extractor", task="look at the first source"):
    """A planner reply that delegates."""
    return {"rationale": "look", "action": "delegate", "worker_role": role, "task": task}


def tool(name, args=None):
    """A worker reply that calls a tool."""
    return {"rationale": "need data", "action": "call_tool", "tool": name, "args": args or {}}


def draft(e, **over):
    """A well-grounded finding draft about one event dict."""
    d = {
        "claim": f"{e['event_type']} on {e['host']}",
        "claim_type": "observation",
        "hosts": [e["host"]],
        "time_start": e["timestamp"][:19] + "Z",
        "cited_event_uids": [e["event_uid"]],
        "confidence": "medium",
    }
    d.update(over)
    return d


def finding(d):
    """A worker reply that records a finding."""
    return {"rationale": "record", "action": "record_finding", "finding": d}


def happy_script(e):
    """planner delegates -> worker searches, records one finding, finishes -> planner finishes."""
    return [delegate(), tool("search_events", {"limit": 5}), finding(draft(e)), WORKER_FINISH,
            PLANNER_FINISH]  # fmt: skip
