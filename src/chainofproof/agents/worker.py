"""Worker mini-loop (extractor / correlator): call tools, record findings, finish with a handoff.

Permissions are exactly the registry's. A permission or argument error is an error observation
(a step, not an LLM failure). A recorded finding goes through the deterministic verifier; the
worker sees the templated report and may submit up to ``finding_revisions`` corrected versions.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from chainofproof.agents import prompts, store
from chainofproof.agents.context import RunCtx
from chainofproof.agents.observe import short
from chainofproof.agents.verifier import verify_finding
from chainofproof.llm.budget import Block, PromptBuilder
from chainofproof.schemas.agent import FindingDraft, WorkerAction
from chainofproof.schemas.findings import FindingStatus

ONE_LINE = 100


@dataclass
class WorkerReport:
    """What the planner learns about a worker run (shown inside a data block)."""

    role: str
    steps: int = 0
    tool_calls: int = 0
    tool_errors: int = 0
    verified: list[tuple[str, str]] = field(default_factory=list)
    downgraded: int = 0
    rejected: int = 0
    problem_codes: Counter = field(default_factory=Counter)
    new_known_events: int = 0
    handoff: str = ""
    stop: str = "finished"

    def render(self) -> str:
        """Plain text of the report (wrapped by the caller)."""
        codes = " ".join(f"{k}={v}" for k, v in sorted(self.problem_codes.items())) or "none"
        lines = [f"worker={self.role} steps={self.steps} tool_calls={self.tool_calls} "
                 f"tool_errors={self.tool_errors} stop={self.stop}",
                 *(f"verified {i}: {c}" for i, c in self.verified),
                 f"downgraded={self.downgraded} rejected={self.rejected} problems: {codes}",
                 f"new_known_events={self.new_known_events}",
                 f"handoff: {self.handoff or '(none)'}"]  # fmt: skip
        return "\n".join(lines)


def _feedback(local: str, status: str, codes: list[str], problems: list[str], left: int) -> str:
    if status == "verified":
        return f"finding {local}: verified"
    why = "; ".join(problems[:6])
    tail = f" Confidence was set to low. You may submit a corrected version with revises={local} " \
           f"({left} revision(s) left)." if status == "downgraded" else \
           f" The finding was rejected. You may submit a corrected version with revises={local} " \
           f"({left} revision(s) left)."  # fmt: skip
    return f"finding {local}: {status}. Problems: {why}.{tail}"


def _record_finding(
    ctx: RunCtx, role: str, draft: FindingDraft, rep: WorkerReport
) -> tuple[str, str]:
    """Verify and store one finding; returns (observation text, status or 'refused')."""
    s = ctx.settings
    parent, depth = None, 0
    if draft.revises:
        pid = next((f for i, f in enumerate(ctx.finding_ids) if f"F{i + 1}" == draft.revises), None)
        if pid is None:
            return "finding refused: revises names an unknown finding id", "refused"
        if ctx.finding_status[pid] == "verified":
            return f"finding refused: {draft.revises} is already verified", "refused"
        depth = ctx.revision_depth.get(pid, 0) + 1
        if depth > s.finding_revisions:
            return f"finding refused: revision limit ({s.finding_revisions}) reached", "refused"
        parent = pid
    fi = draft.to_input()
    report = verify_finding(ctx.paths, ctx.case_id, ctx.hit_scope, fi)
    status: FindingStatus = report.status
    if status == "downgraded":
        fi.confidence = "low"
    f = store.add_finding(ctx.paths, ctx.run_id, ctx.case_id, role, fi, status, report, parent)
    ctx.finding_ids.append(f.finding_id)
    ctx.finding_status[f.finding_id] = status
    ctx.revision_depth[f.finding_id] = depth
    local = ctx.local_id(f.finding_id)
    if status == "verified":
        rep.verified.append((local, short(fi.claim, ONE_LINE)))
        ctx.notebook.add_finding(local, fi.claim)
    else:
        rep.downgraded += status == "downgraded"
        rep.rejected += status == "rejected"
    rep.problem_codes.update(report.codes())
    ctx.counts[f"findings_{status}"] += 1
    ctx.trace.add(role, "finding", finding_id=f.finding_id, status=status,
                  codes=sorted(set(report.codes())), counts=report.counts,
                  cited_events=len(fi.cited_event_uids), cited_hits=len(fi.cited_hit_ids),
                  revised_from=parent)  # fmt: skip
    return _feedback(
        local, status, report.codes(), report.problems, s.finding_revisions - depth
    ), status


def run_worker(ctx: RunCtx, role: str, task: str, focus: list[str], round_no: int) -> WorkerReport:
    """Run one worker for at most ``worker_max_steps`` steps and return its report."""
    s, rep = ctx.settings, WorkerReport(role)
    builder = PromptBuilder(prompts.worker_system(role), ctx.client.num_ctx, s.num_predict,
                            s.max_prompt_fraction)  # fmt: skip
    known_before = len(ctx.seen_events)
    assign = task + (f"\nFocus on sources: {', '.join(focus)}" if focus else "")
    task_block = ctx.wrap(role, assign, f"task-{round_no}", "lead_task")
    blocks: list[Block] = []
    for step in range(1, s.worker_max_steps + 1):
        core = (
            f"Step {step} of {s.worker_max_steps}.\n\n"
            f"{ctx.notebook_block(role, f'nb-{round_no}-{step}')}\n\n{task_block}"
        )

        def build(scale: float, core: str = core) -> list[dict[str, str]]:
            return builder.build(core, blocks, prompts.WORKER_TAIL, scale)[0]

        res = ctx.call_llm(role, WorkerAction, build)
        rep.steps = step
        info = {"tokens_in": res.prompt_tokens, "tokens_out": res.completion_tokens,
                "duration_ms": res.duration_ms, "attempts": res.attempts,
                "flags": ctx.last_events}  # fmt: skip
        if not res.ok:
            ctx.trace.add(role, "worker_step", ok=False, error=res.error, **info)
            rep.stop = "llm_failure"
            break
        act: WorkerAction = res.parsed  # type: ignore[assignment]
        ctx.trace.add(role, "worker_step", ok=True, act=act.action, rationale=act.rationale, **info)
        if act.action == "finish":
            rep.handoff = short(act.handoff or "", s.handoff_max_chars)
            break
        if act.action == "call_tool":
            out = ctx.tool(role, act.tool or "", act.args)
            rep.tool_calls += 1
            rep.tool_errors += not out.ok
            bid = ctx.next_obs()
            name = act.tool if out.ok else "error"
            text = ctx.wrap(role, out.text, bid, f"tool:{name}")
            ids = (out.compact.event_uids + out.compact.hit_ids) if out.compact else []
            blocks.append(Block("obs", bid, f"tool:{name}", text, ids))
        else:
            fb, _ = _record_finding(ctx, role, act.finding, rep)  # type: ignore[arg-type]
            bid = ctx.next_obs()
            blocks.append(Block("obs", bid, "verifier", ctx.wrap(role, fb, bid, "verifier"), []))
    else:
        rep.stop = "step_budget"
    rep.new_known_events = len(ctx.seen_events) - known_before
    return rep
