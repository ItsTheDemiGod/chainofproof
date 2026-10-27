"""Shared state and services of one agent run: budgets, the LLM and tool gateways, recording.

Every LLM call and every tool call of the run passes through here, so each one is written to the
ledger (hashes, never contents), to ``agent_calls`` and to the trace, and each one is checked
against the run budgets (``StopRun``). Agents reach tools ONLY through ``registry.call_tool`` (A1).
"""

from __future__ import annotations

import json
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from chainofproof.agents import store
from chainofproof.agents.notebook import Notebook
from chainofproof.agents.observe import Compact, compact, wrap
from chainofproof.agents.trace import Trace
from chainofproof.config import AgentSettings, Paths
from chainofproof.custody.hashing import sha256_json, sha256_text
from chainofproof.custody.ledger import Ledger
from chainofproof.llm.base import CallCtx, CallRecord, LLMClient, LLMResult, Messages
from chainofproof.llm.budget import PromptTooLarge
from chainofproof.tools.registry import TOOLS, ToolError, call_tool

ERROR_CAP = 200


class StopRun(Exception):
    """A stop condition of the run (budget, failures); carries the final status and reason."""

    def __init__(self, status: str, reason: str) -> None:
        super().__init__(f"{status}: {reason}")
        self.status, self.reason = status, reason


@dataclass
class ToolOutcome:
    """Result of one tool call as the agent sees it."""

    ok: bool
    text: str  # compacted result, or a templated error message
    compact: Compact | None = None
    error_kind: str | None = None
    raw: dict[str, Any] | None = None  # the registry result (used by the code-run survey only)


def error_kind(message: str) -> str:
    """Coarse class of a registry error message (for the trace)."""
    for needle, kind in (("may not call", "permission"), ("invalid arguments", "args"),
                         ("unknown tool", "unknown_tool"), ("unknown role", "unknown_role"),
                         ("access denied", "denied")):  # fmt: skip
        if needle in message:
            return kind
    return "failed"


@dataclass
class RunCtx:
    """Everything the planner and the workers share during one run."""

    paths: Paths
    case_id: str
    run_id: str
    run_dir: Path
    hit_scope: str  # the agent run whose detector hits are visible (own id, or the original's)
    settings: AgentSettings
    client: LLMClient
    trace: Trace
    ledger: Ledger
    input_sha: str
    clock: Callable[[], float]
    notebook: Notebook
    t0: float = 0.0
    call_idx: int = 0
    obs_n: int = 0
    fail_streak: int = 0
    counts: Counter = field(default_factory=Counter)
    seen_events: set[str] = field(default_factory=set)
    seen_hits: set[str] = field(default_factory=set)
    finding_ids: list[str] = field(default_factory=list)  # FND ids in order; local id = F<i+1>
    finding_status: dict[str, str] = field(default_factory=dict)
    revision_depth: dict[str, int] = field(default_factory=dict)
    tool_names: dict[str, int] = field(default_factory=dict)
    delegations: list[tuple[str, int]] = field(default_factory=list)  # (worker role, task chars)
    last_events: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.t0 = self.clock()
        (self.run_dir / "llm").mkdir(exist_ok=True)

    # ---- ids and budgets -----------------------------------------------------------------
    def next_idx(self) -> int:
        """Run-wide call counter for ``agent_calls``."""
        self.call_idx += 1
        return self.call_idx

    def next_obs(self) -> str:
        """Next observation block id."""
        self.obs_n += 1
        return f"obs-{self.obs_n}"

    def local_id(self, fnd_id: str) -> str:
        """Run-local finding label (F1, F2...): prompts never contain global FND ids."""
        return f"F{self.finding_ids.index(fnd_id) + 1}"

    def check_budget(self) -> None:
        """Raise StopRun when an LLM-call or wall-time budget is used up."""
        s = self.settings
        if self.counts["llm_calls"] >= s.max_llm_calls_per_run:
            raise StopRun("budget_exhausted", "max_llm_calls_per_run")
        if self.clock() - self.t0 >= s.max_run_seconds:
            raise StopRun("budget_exhausted", "max_run_seconds")

    def _streak(self, failed: bool) -> None:
        self.fail_streak = self.fail_streak + 1 if failed else 0
        if self.fail_streak >= self.settings.consecutive_failure_limit:
            raise StopRun("failed", "consecutive_failures")

    def wrap(self, role: str, content: str, block_id: str, source: str) -> str:
        """Wrap text in a DATA block and trace its size and the number of delimiter escapes."""
        text, esc = wrap(content, block_id, source)
        self.counts["delimiter_escapes"] += esc
        self.trace.add(
            role, "block", block_id=block_id, source=source, chars=len(text), escapes=esc
        )
        return text

    def notebook_block(self, role: str, block_id: str) -> str:
        """The notebook as a DATA block (traced only when its content needed escaping)."""
        text, esc = self.notebook.render_block(block_id)
        if esc:
            self.counts["delimiter_escapes"] += esc
            self.trace.add(role, "block", block_id=block_id, source="notebook", escapes=esc)
        return text

    # ---- LLM gateway ---------------------------------------------------------------------
    def record(self, rec: CallRecord) -> None:
        """CallRecorder: call file, ledger entry (hashes only) and agent_calls row."""
        c = self.counts
        c["llm_calls"] += 1
        c["prompt_tokens"] += rec.prompt_tokens
        c["completion_tokens"] += rec.completion_tokens
        c["invalid_json"] += rec.status == "invalid"
        c["truncated"] += rec.status == "truncated"
        c["llm_errors"] += rec.status == "error"
        d = {k: getattr(rec, k) for k in rec.__dataclass_fields__}
        (self.run_dir / "llm" / f"call_{rec.idx:05d}.json").write_text(
            json.dumps(d, ensure_ascii=False), encoding="utf-8"
        )
        lid = None
        if self.settings.ledger_llm_calls:
            e = self.ledger.append(
                f"llm:{rec.role}", "llm_call", f"{self.run_id} call {rec.idx}", [rec.prompt_sha256],
                rec.response_sha256,
                {"run_id": self.run_id, "model": rec.model, "num_ctx": rec.num_ctx,
                 "prompt_sha256": rec.prompt_sha256, "response_sha256": rec.response_sha256,
                 "prompt_tokens": rec.prompt_tokens, "completion_tokens": rec.completion_tokens,
                 "duration_ms": rec.duration_ms, "status": rec.status},
            )  # fmt: skip
            lid = e.ledger_id
        store.insert_call(self.paths, self.run_id, self.next_idx(), "llm", rec.role,
                          rec.schema_name, input_sha256=rec.prompt_sha256,
                          output_sha256=rec.response_sha256, prompt_tokens=rec.prompt_tokens,
                          completion_tokens=rec.completion_tokens, duration_ms=rec.duration_ms,
                          ledger_id=lid, status=rec.status)  # fmt: skip

    def call_llm(
        self, role: str, schema: type[BaseModel], build: Callable[[float], Messages]
    ) -> LLMResult:
        """One structured call under the budgets; ``build(scale)`` rebuilds the prompt smaller."""
        self.check_budget()
        scale = [1.0]

        def shrink() -> Messages | None:
            scale[0] *= 0.75
            try:
                return build(scale[0])
            except PromptTooLarge:
                return None

        ctx = CallCtx(role, self, shrink)
        try:
            msgs = build(1.0)
        except PromptTooLarge:
            raise StopRun("failed", "prompt_too_large") from None
        res = self.client.chat(msgs, schema, role, ctx)
        self.counts["retries"] += max(0, res.attempts - 1)
        self.last_events = ctx.events
        self._streak(not res.ok)
        return res

    # ---- tool gateway --------------------------------------------------------------------
    def tool(self, role: str, name: str, args: Any) -> ToolOutcome:
        """Call a registry tool as ``role`` (ledger, agent_calls and trace entries included)."""
        a = args if isinstance(args, dict) else {}
        safe = name if name in TOOLS else "unknown"
        args_sha, idx, t0 = sha256_json(a), self.next_idx(), time.perf_counter()
        out: ToolOutcome
        err: str | None = None
        try:
            result = call_tool(role, name, a, self.paths, self.case_id, agent_run_id=self.hit_scope)
        except ToolError as e:
            err = str(e)[:ERROR_CAP]
            out = ToolOutcome(False, f"tool_error: {err}", error_kind=error_kind(err))
        except Exception as e:  # noqa: BLE001 - an unexpected failure counts toward the stop rule
            err = f"internal error {type(e).__name__}"
            out = ToolOutcome(False, f"tool_error: {err}", error_kind="internal")
        else:
            cp = compact(name, result, self.settings.max_tool_output_chars)
            out = ToolOutcome(True, cp.text, cp, raw=result)
            self.seen_events.update(cp.event_uids)
            self.seen_hits.update(cp.hit_ids)
            self.notebook.add_events(cp.events)
        ms = round((time.perf_counter() - t0) * 1000)
        osha = sha256_json(result) if out.ok else sha256_text(err or "")
        entry = self.ledger.append(
            f"agent:{role}", "tool_call" if out.ok else "tool_call_failed",
            f"{safe} args_sha256={args_sha}", [self.input_sha], osha,
            {"run_id": self.run_id, "tool": safe, "duration_ms": ms,
             **({"error_kind": out.error_kind} if not out.ok else {})},
        )  # fmt: skip
        self.counts["tool_calls"] += 1
        self.counts["tool_errors"] += not out.ok
        self.tool_names[safe] = self.tool_names.get(safe, 0) + 1
        store.insert_call(self.paths, self.run_id, idx, "tool", role, safe, input_sha256=args_sha,
                          output_sha256=osha, duration_ms=ms, ledger_id=entry.ledger_id,
                          status="ok" if out.ok else "error")  # fmt: skip
        cp = out.compact
        self.trace.add(role, "tool", tool=safe, args_sha256=args_sha, ok=out.ok,
                       error_kind=out.error_kind, error_sha256=None if out.ok else osha,
                       shown=cp.shown if cp else None, total=cp.total if cp else None,
                       event_uids=cp.event_uids[:50] if cp else None,
                       hit_ids=cp.hit_ids[:50] if cp else None, duration_ms=ms,
                       ledger_id=entry.ledger_id)  # fmt: skip
        self._streak(out.error_kind == "internal")
        return out
