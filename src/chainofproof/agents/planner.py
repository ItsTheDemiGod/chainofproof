"""Planner loop: one LLM call per round; delegate to a worker or finish.

The planner sees verified findings and worker reports only as data blocks (worker handoff notes
are model output that read evidence). There is NO automatic detector pipeline: whether a detector
runs is decided by the planner (delegating to the correlator) and the correlator (rule D2).
"""

from __future__ import annotations

from chainofproof.agents import prompts
from chainofproof.agents.context import RunCtx
from chainofproof.agents.observe import short
from chainofproof.agents.worker import run_worker
from chainofproof.llm.budget import Block, PromptBuilder
from chainofproof.schemas.agent import PlannerAction


def run_planner(ctx: RunCtx, labels: list[str]) -> str:
    """Run planner rounds; returns the stop reason (delegations are kept in ``ctx.delegations``)."""
    s = ctx.settings
    builder = PromptBuilder(prompts.planner_system(), ctx.client.num_ctx, s.num_predict,
                            s.max_prompt_fraction)  # fmt: skip
    reports: list[Block] = []
    for rnd in range(1, s.planner_max_rounds + 1):
        core = (
            f"Round {rnd} of {s.planner_max_rounds}. Verified findings so far: "
            f"{len(ctx.notebook.findings)}.\n\n{ctx.notebook_block('planner', f'nb-{rnd}')}"
        )

        def build(scale: float, core: str = core) -> list[dict[str, str]]:
            return builder.build(core, reports, prompts.PLANNER_TAIL, scale)[0]

        res = ctx.call_llm("planner", PlannerAction, build)
        info = {"tokens_in": res.prompt_tokens, "tokens_out": res.completion_tokens,
                "duration_ms": res.duration_ms, "attempts": res.attempts,
                "flags": ctx.last_events}  # fmt: skip
        if not res.ok:
            ctx.trace.add("planner", "round", round=rnd, ok=False, error=res.error, **info)
        else:
            act: PlannerAction = res.parsed  # type: ignore[assignment]
            ctx.notebook.apply(act.notebook)
            ctx.trace.add("planner", "round", round=rnd, ok=True, act=act.action,
                          rationale=act.rationale, worker_role=act.worker_role,
                          task_chars=len(act.task or ""), **info)  # fmt: skip
            if act.action == "finish":
                ctx.trace.flush()
                ctx.notebook.save(ctx.run_dir / "notebook.json")
                return "planner_finish"
            focus = [x for x in (act.focus_labels or []) if x in labels]
            task = short(act.task or "", 300)
            ctx.delegations.append((act.worker_role or "", len(task)))
            rep = run_worker(ctx, act.worker_role or "extractor", task, focus, rnd)
            bid = f"rep-{rnd}"
            text = ctx.wrap("planner", rep.render(), bid, "worker_report")
            reports.append(Block("report", bid, "worker_report", text, []))
            ctx.trace.add("planner", "worker_report", round=rnd, worker=rep.role, steps=rep.steps,
                          tool_calls=rep.tool_calls, verified=len(rep.verified),
                          downgraded=rep.downgraded, rejected=rep.rejected, stop=rep.stop,
                          new_known_events=rep.new_known_events)  # fmt: skip
        ctx.notebook.save(ctx.run_dir / "notebook.json")
        ctx.trace.flush()
    return "planner_max_rounds"
