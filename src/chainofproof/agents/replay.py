"""Replay of a recorded run (offline): same data, recorded LLM replies, everything else real.

Only the LLM is non-deterministic. Tools, verifier and orchestration are executed again; a replay
must reproduce the findings (ids aside), their statuses and the trace's tool-call sequence. The
replay is a NEW run (``replay_of`` set); the original run is never touched. Detector hits are read
from the original run's scope (hit ids are global and are not re-allocated).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from chainofproof.agents import store
from chainofproof.agents.runner import AgentRunResult, run_agent
from chainofproof.agents.trace import read_trace, tool_sequence
from chainofproof.config import AgentSettings, Paths, Settings
from chainofproof.errors import UserError
from chainofproof.llm.replay import ReplayLLMClient
from chainofproof.schemas.findings import Finding
from chainofproof.tools.loader import case_input_sha


@dataclass
class ReplayReport:
    """Comparison of a replay with its original."""

    original: str
    replay: str
    ok: bool
    problems: list[str] = field(default_factory=list)


def _signature(findings: list[Finding]) -> list[tuple]:
    """Findings without their ids; ``revised_from`` becomes the ordinal of the parent."""
    order = {f.finding_id: i for i, f in enumerate(findings)}
    return [(f.worker_role, f.claim, f.claim_type, f.status, f.confidence,
             json.dumps(f.entities.model_dump(), sort_keys=True), tuple(sorted(f.cited_event_uids)),
             tuple(sorted(f.cited_hit_ids)), tuple(f.needs), order.get(f.revised_from or ""))
            for f in findings]  # fmt: skip


def compare(paths: Paths, original: str, res: AgentRunResult) -> ReplayReport:
    """Compare findings, statuses and the tool-call sequence of a replay with the original."""
    rep = ReplayReport(original, res.run_id, True)
    a_row, b_row = store.get_run(paths, original), store.get_run(paths, res.run_id)
    if (a_row["status"], a_row["stop_reason"]) != (b_row["status"], b_row["stop_reason"]):
        old = f"{a_row['status']}/{a_row['stop_reason']}"
        new = f"{b_row['status']}/{b_row['stop_reason']}"
        rep.problems.append(f"replay diverged: final status {old} vs {new}")
    la = read_trace(paths.runs_dir / original / "trace.jsonl")
    lb = read_trace(paths.runs_dir / res.run_id / "trace.jsonl")
    ta, tb = tool_sequence(la), tool_sequence(lb)
    steps = [x["step"] for x in lb if x["action"] == "tool"]
    for i in range(max(len(ta), len(tb))):
        if i >= len(ta) or i >= len(tb) or ta[i] != tb[i]:
            at = steps[i] if i < len(steps) else len(lb) + 1
            rep.problems.append(f"replay diverged at trace step {at} (tool call {i + 1})")
            break
    fa, fb = _signature(store.list_findings(paths, original)), _signature(res.findings)
    if fa != fb:
        i = next((k for k in range(min(len(fa), len(fb))) if fa[k] != fb[k]), min(len(fa), len(fb)))
        rep.problems.append(f"replay diverged at finding {i + 1}")
    rep.ok = not rep.problems
    return rep


def replay_run(paths: Paths, run_id: str, settings: Settings) -> ReplayReport:
    """Re-run ``run_id`` against the recorded LLM replies and compare."""
    row = store.get_run(paths, run_id)
    if row["status"] == "running":
        raise UserError(f"run {run_id} is still marked running")
    if case_input_sha(paths, row["case_id"]) != row["input_sha256"]:
        raise UserError("the normalized data of the case changed since the run; cannot replay")
    blob: dict[str, Any] = json.loads(row["settings_json"])
    s = settings.model_copy(deep=True)
    s.agent = AgentSettings.model_validate(blob["agent"])
    s.ollama.seed = blob["seed"]
    client = ReplayLLMClient(paths.runs_dir / run_id, blob["model"], blob["num_ctx"],
                             s.agent.json_retries)  # fmt: skip
    res = run_agent(paths, row["case_id"], client, s, replay_of=run_id)
    return compare(paths, run_id, res)
