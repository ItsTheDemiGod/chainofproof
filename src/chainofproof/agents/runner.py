"""Orchestrator: one agent run from survey to final status (plain Python, no agent framework).

``run_agent`` creates the run (database row, folder RUN-######, ledger ``run_start``), performs the
code-run initial survey through the registry as the planner, loops planner rounds, and always
finishes with a final status, a flushed trace and a ledger ``run_end`` that carries the trace hash.
Stop conditions: planner finish, planner_max_rounds, max_llm_calls_per_run, max_run_seconds,
consecutive failures, Ctrl+C, and fatal LLM errors (context mismatch, replay divergence).
"""

from __future__ import annotations

import json
import logging
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from chainofproof.agents import prompts, store
from chainofproof.agents.context import RunCtx, StopRun
from chainofproof.agents.notebook import Notebook
from chainofproof.agents.planner import run_planner
from chainofproof.agents.trace import Trace
from chainofproof.config import Paths, Settings
from chainofproof.custody.db import restricted_reads
from chainofproof.custody.hashing import iso_utc, sha256_json, utc_now
from chainofproof.custody.ledger import Ledger
from chainofproof.errors import UserError
from chainofproof.llm.base import LLMClient, LLMFatal
from chainofproof.protocol.guard import check_run_allowed, record_test_run
from chainofproof.protocol.splits import split_of
from chainofproof.schemas.findings import Finding
from chainofproof.tools.loader import case_input_sha
from chainofproof.tools.norm_store import require_version
from chainofproof.tools.runs import new_run_dir

log = logging.getLogger(__name__)


@dataclass
class AgentRunResult:
    """Outcome of ``run_agent``."""

    run_id: str
    case_id: str
    status: str
    stop_reason: str
    counts: dict[str, int]
    trace_sha256: str
    findings: list[Finding]
    delegations: list[tuple[str, int]] = field(default_factory=list)
    tool_names: dict[str, int] = field(default_factory=dict)
    elapsed_s: float = 0.0


def _survey(ctx: RunCtx) -> list[str]:
    """Initial survey by code, through the registry as the planner; returns the source labels."""
    out = ctx.tool("planner", "list_evidence_labels", {})
    if not out.ok or out.raw is None:
        raise StopRun("failed", "survey_failed")
    labels, lines = [], []
    for x in out.raw["labels"]:
        labels.append(x["label"])
        s = ctx.tool("planner", "source_summary", {"evidence_label": x["label"]})
        if not s.ok or s.raw is None:
            raise StopRun("failed", "survey_failed")
        types = " ".join(f"{k}={v}" for k, v in list(s.raw["by_event_type"].items())[:6])
        users = ",".join(f"{u}({n})" for u, n in s.raw["top_users"][:3])
        lines.append(
            f"{x['label']} {x['source_kind']} hosts={','.join(x['hosts'])} "
            f"events={x['event_count']} {str(x['first_timestamp'])[:19]}Z.."
            f"{str(x['last_timestamp'])[:19]}Z | {types} | users: {users or '-'}"
        )
    g = ctx.tool("planner", "graph_stats", {})
    if not g.ok or g.raw is None:
        raise StopRun("failed", "survey_failed")
    r = g.raw
    lines.append(
        f"graph: nodes={r['node_count']} edges={r['edge_count']} "
        f"ips_resolved={r['ips_resolved']} ips_unresolved={r['ips_unresolved']}"
    )
    ctx.notebook.set_survey(lines)
    return labels


def _settings_blob(settings: Settings, client: LLMClient) -> dict[str, Any]:
    return {"agent": settings.agent.model_dump(), "model": client.model, "num_ctx": client.num_ctx,
            "seed": settings.ollama.seed, "temperature": settings.ollama.temperature}  # fmt: skip


def run_agent(
    paths: Paths, case_id: str, client: LLMClient, settings: Settings, *,
    replay_of: str | None = None, clock: Callable[[], float] = time.monotonic,
) -> AgentRunResult:  # fmt: skip
    """Run the agent on a normalized case. Needs schema version 5 and normalized events.

    TEST-split cases (rules E1-E3) are refused unless a matching ``prompt_freeze`` exists.
    """
    require_version(paths, 5)
    if replay_of:  # a replay calls no LLM: allowed for any recorded run
        split, freeze_id = split_of(case_id), None
    else:
        split, freeze_id = check_run_allowed(paths, case_id, settings.agent)  # rules E1-E3
    input_sha = case_input_sha(paths, case_id)
    if input_sha == sha256_json([]):  # no latest normalization runs at all
        raise UserError(f"case {case_id!r} has no normalized events")
    run_id, run_dir = new_run_dir(paths)
    blob = _settings_blob(settings, client)
    store.insert_run(paths, {
        "run_id": run_id, "case_id": case_id, "model": client.model, "num_ctx": client.num_ctx,
        "seed": settings.ollama.seed, "settings_json": json.dumps(blob, sort_keys=True),
        "settings_sha256": sha256_json(blob), "prompt_version": prompts.prompt_version(),
        "input_sha256": input_sha, "replay_of": replay_of, "started_at": iso_utc(utc_now()),
        "status": "running", "split": split})  # fmt: skip
    ledger = Ledger(paths)
    ledger.append("agent:run", "run_start", f"agent-run {case_id}", [input_sha], None,
                  {"run_id": run_id, "case_id": case_id, "model": client.model,
                   "num_ctx": client.num_ctx, "prompt_version": prompts.prompt_version(),
                   "settings_sha256": sha256_json(blob), "replay_of": replay_of})  # fmt: skip
    if freeze_id:
        record_test_run(paths, freeze_id, case_id, run_id)
    ctx = RunCtx(paths, case_id, run_id, run_dir, store.root_run(paths, replay_of) if replay_of
                 else run_id, settings.agent, client, Trace(run_dir / "trace.jsonl"), ledger,
                 input_sha, clock, Notebook(settings.agent.known_events_cap))  # fmt: skip
    status, reason = "failed", "unknown"
    try:
        with restricted_reads():
            labels = _survey(ctx)
            reason = run_planner(ctx, labels)
        status = "completed" if reason == "planner_finish" else "budget_exhausted"
    except StopRun as e:
        status, reason = e.status, e.reason
    except LLMFatal as e:
        status, reason = "failed", f"llm_fatal: {str(e)[:120]}"
    except KeyboardInterrupt:
        status, reason = "aborted", "keyboard_interrupt"
    except Exception as e:  # noqa: BLE001 - recorded as a failed run; details go to a local file
        status, reason = "failed", f"unexpected {type(e).__name__}"
        (run_dir / "error.txt").write_text(traceback.format_exc(), encoding="utf-8")
        log.error("run %s failed: %s", run_id, type(e).__name__)
    ctx.notebook.save(run_dir / "notebook.json")
    trace_sha = ctx.trace.close()
    c = ctx.counts
    store.finish_run(paths, run_id, status=status, stop_reason=reason,
                     finished_at=iso_utc(utc_now()), llm_calls=c["llm_calls"],
                     tool_calls=c["tool_calls"], prompt_tokens=c["prompt_tokens"],
                     completion_tokens=c["completion_tokens"], trace_sha256=trace_sha,
                     arg_errors=c["arg_errors"], format_errors=c["format_errors"],
                     duplicate_refusals=c["duplicate_refusals"])  # fmt: skip
    ledger.append("agent:run", "run_end", f"agent-run {case_id}", [input_sha], trace_sha,
                  {"run_id": run_id, "status": status, "stop_reason": reason,
                   "trace_sha256": trace_sha, "llm_calls": c["llm_calls"],
                   "tool_calls": c["tool_calls"]})  # fmt: skip
    return AgentRunResult(run_id, case_id, status, reason, dict(c), trace_sha,
                          store.list_findings(paths, run_id), ctx.delegations, dict(ctx.tool_names),
                          clock() - ctx.t0)  # fmt: skip
