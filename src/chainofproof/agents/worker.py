"""Worker mini-loop (extractor / correlator): call tools, record findings, finish with a handoff.

Permissions are exactly the registry's. A permission error is an error observation that costs a
step. An invalid-argument call does NOT cost a step (each worker may make ``max_arg_errors_per_
worker`` of them, then it ends): a small model that mistypes an argument should get to correct it
without losing the investigation. A finding with a malformed citation (a label instead of an id)
is returned for correction without being stored (the first time per worker is free). A duplicate
of an earlier verified/downgraded finding is refused and counted. A recorded finding goes through
the deterministic verifier; the worker sees the templated report and may submit up to
``finding_revisions`` corrected versions.
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
from chainofproof.schemas.findings import EVT_RE, HIT_RE, FindingInput, FindingStatus

ONE_LINE = 100


@dataclass
class WorkerReport:
    """What the planner learns about a worker run (shown inside a data block)."""

    role: str
    steps: int = 0
    tool_calls: int = 0
    tool_errors: int = 0
    arg_errors: int = 0
    format_errors: int = 0
    duplicates: int = 0
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
                 f"tool_errors={self.tool_errors} arg_errors={self.arg_errors} stop={self.stop}",
                 *(f"verified {i}: {c}" for i, c in self.verified),
                 f"downgraded={self.downgraded} rejected={self.rejected} "
                 f"duplicates_refused={self.duplicates} format_errors={self.format_errors} "
                 f"problems: {codes}",
                 f"new_known_events={self.new_known_events}",
                 f"handoff: {self.handoff or '(none)'}"]  # fmt: skip
        return "\n".join(lines)


def normalise_claim(text: str) -> str:
    """Lower-cased, whitespace-collapsed claim text (duplicate detection)."""
    return " ".join(text.lower().split())


def _feedback(local: str, status: str, problems: list[str], left: int) -> str:
    if status == "verified":
        return f"finding {local}: verified"
    why = "; ".join(problems[:6])
    what = "Confidence was set to low." if status == "downgraded" else "The finding was rejected."
    return (f"finding {local}: {status}. Problems: {why}. {what} You may submit a corrected "
            f"version with revises={local} ({left} revision(s) left).")  # fmt: skip


def _bad_ids(draft: FindingDraft) -> int:
    """Number of cited ids that do not have the EVT- / HIT- shape (labels, free text)."""
    return sum(not EVT_RE.match(i) for i in draft.cited_event_uids) + sum(
        not HIT_RE.match(i) for i in draft.cited_hit_ids
    )


def _duplicate_of(ctx: RunCtx, fi: FindingInput, parent: str | None) -> str | None:
    """Run-local id of an earlier verified/downgraded finding this one repeats (not its parents)."""
    chain, p = set(), parent
    while p:
        chain.add(p)
        p = ctx.parent_of.get(p)
    ids, norm = frozenset([*fi.cited_event_uids, *fi.cited_hit_ids]), normalise_claim(fi.claim)
    for fid, (ctype, fids, nclaim) in ctx.finding_meta.items():
        if fid not in chain and (nclaim == norm or (ctype == fi.claim_type and fids == ids)):
            return ctx.local_id(fid)
    return None


def _record_finding(
    ctx: RunCtx, role: str, draft: FindingDraft, rep: WorkerReport
) -> tuple[str, str]:
    """Verify and store one finding; returns (observation, outcome).

    Outcomes: verified | downgraded | rejected | refused | format | duplicate.
    """
    s = ctx.settings
    ctx.counts["finding_attempts"] += 1
    if n := _bad_ids(draft):
        rep.format_errors += 1
        ctx.counts["format_errors"] += 1
        ctx.trace.add(role, "finding_refused", reason="format", offending=n)
        return (f"format error: cited ids must be EVT- or HIT- ids; labels are not citable; "
                f"offending count {n}. An EVT id looks like EVT-0123456789ab (EVT- and 12 hex "
                f"characters), a HIT id like HIT-000123.", "format")  # fmt: skip
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
    if (dup := _duplicate_of(ctx, fi, parent)) is not None:
        rep.duplicates += 1
        ctx.counts["duplicate_refusals"] += 1
        ctx.trace.add(role, "finding_refused", reason="duplicate", existing=dup)
        return (
            f"duplicate refused: this repeats finding {dup}; record a different claim",
            "duplicate",
        )
    report = verify_finding(ctx.paths, ctx.case_id, ctx.hit_scope, fi)
    status: FindingStatus = report.status
    if status == "downgraded":
        fi.confidence = "low"
    f = store.add_finding(ctx.paths, ctx.run_id, ctx.case_id, role, fi, status, report, parent)
    ctx.finding_ids.append(f.finding_id)
    ctx.finding_status[f.finding_id] = status
    ctx.revision_depth[f.finding_id] = depth
    if parent:
        ctx.parent_of[f.finding_id] = parent
    if status != "rejected":
        ids = frozenset([*fi.cited_event_uids, *fi.cited_hit_ids])
        ctx.finding_meta[f.finding_id] = (fi.claim_type, ids, normalise_claim(fi.claim))
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
    return _feedback(local, status, report.problems, s.finding_revisions - depth), status


def run_worker(ctx: RunCtx, role: str, task: str, focus: list[str], round_no: int) -> WorkerReport:
    """Run one worker for at most ``worker_max_steps`` steps and return its report."""
    s, rep = ctx.settings, WorkerReport(role)
    builder = PromptBuilder(prompts.worker_system(role), ctx.client.num_ctx, s.num_predict,
                            s.max_prompt_fraction)  # fmt: skip
    known_before = len(ctx.seen_events)
    assign = task + (f"\nFocus on sources: {', '.join(focus)}" if focus else "")
    task_block = ctx.wrap(role, assign, f"task-{round_no}", "lead_task")
    blocks: list[Block] = []
    while rep.steps < s.worker_max_steps:
        step = rep.steps + 1
        core = (
            f"Step {step} of {s.worker_max_steps}.\n\n"
            f"{ctx.notebook_block(role, f'nb-{round_no}-{step}-{rep.arg_errors}')}\n\n{task_block}"
        )

        def build(scale: float, core: str = core) -> list[dict[str, str]]:
            return builder.build(core, blocks, prompts.WORKER_TAIL, scale)[0]

        res = ctx.call_llm(role, WorkerAction, build)
        info = {"tokens_in": res.prompt_tokens, "tokens_out": res.completion_tokens,
                "duration_ms": res.duration_ms, "attempts": res.attempts,
                "flags": ctx.last_events}  # fmt: skip
        if not res.ok:
            rep.steps += 1
            ctx.trace.add(role, "worker_step", ok=False, error=res.error, **info)
            rep.stop = "llm_failure"
            break
        act: WorkerAction = res.parsed  # type: ignore[assignment]
        ctx.trace.add(role, "worker_step", ok=True, act=act.action, rationale=act.rationale, **info)
        consumed = True
        if act.action == "finish":
            rep.steps += 1
            rep.handoff = short(act.handoff or "", s.handoff_max_chars)
            break
        if act.action == "call_tool":
            out = ctx.tool(role, act.tool or "", act.args)
            rep.tool_calls += 1
            rep.tool_errors += not out.ok
            if out.error_kind == "args":
                rep.arg_errors += 1
                consumed = False  # a mistyped argument does not cost a step
            bid = ctx.next_obs()
            name = act.tool if out.ok else "error"
            text = ctx.wrap(role, f"{prompts.LEGEND}\n{out.text}" if out.ok else out.text, bid,
                            f"tool:{name}")  # fmt: skip
            ids = (out.compact.event_uids + out.compact.hit_ids) if out.compact else []
            blocks.append(Block("obs", bid, f"tool:{name}", text, ids))
        else:
            fb, outcome = _record_finding(ctx, role, act.finding, rep)  # type: ignore[arg-type]
            consumed = not (outcome == "format" and rep.format_errors == 1)  # first one is free
            bid = ctx.next_obs()
            blocks.append(Block("obs", bid, "verifier", ctx.wrap(role, fb, bid, "verifier"), []))
        rep.steps += consumed
        if rep.arg_errors >= s.max_arg_errors_per_worker:
            rep.stop = "arg_error_budget"
            break
    else:
        rep.stop = "step_budget"
    rep.new_known_events = len(ctx.seen_events) - known_before
    return rep
