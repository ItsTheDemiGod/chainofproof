"""Phase 5 commands (registered on the main typer app by ``register``).

Prints only ids, counts, hashes, timings, statuses, virtual host names, labels and numbers. The one
exception is the clearly labeled, capped claim column of ``findings-show`` (model-produced text).
``agent-peek`` is EVAL ONLY (it reads the answer key).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, Literal

import ollama
import typer
from pydantic import BaseModel
from rich.console import Console
from rich.table import Table
from rich.text import Text

from chainofproof.agents import store
from chainofproof.agents.replay import replay_run
from chainofproof.agents.runner import run_agent
from chainofproof.agents.trace import read_trace
from chainofproof.config import Paths, Settings, load_settings
from chainofproof.custody.migrations import migrate_to_v4
from chainofproof.errors import UserError
from chainofproof.llm.base import LLMClient
from chainofproof.llm.fake import FakeLLMClient
from chainofproof.llm.ollama_client import OllamaClient

CLAIM_COLUMN_CAP = 120


class Ping(BaseModel):
    """Schema of the tiny structured call of ``llm-check``."""

    status: Literal["ok"]


def installed_models(host: str) -> set[str]:
    """Names of the models installed on the Ollama server (raises UserError when unreachable)."""
    try:
        return {m.model for m in ollama.Client(host=host, timeout=10).list().models if m.model}
    except Exception as e:  # noqa: BLE001 - every connection problem reads the same
        raise UserError(f"cannot reach Ollama at {host} ({type(e).__name__})") from None


def make_client(spec: str, s: Settings, model: str | None = None) -> LLMClient:
    """``ollama`` (default) or ``fake:PATH`` (tests and demos only)."""
    a, o = s.agent, s.ollama
    if spec.startswith("fake:"):
        return FakeLLMClient.from_file(
            Path(spec[5:]), num_ctx=o.num_ctx, json_retries=a.json_retries
        )
    if spec != "ollama":
        raise UserError("--llm must be 'ollama' or 'fake:PATH'")
    return OllamaClient(
        o.host,
        model or a.default_model,
        o.num_ctx,
        o.seed,
        o.temperature,
        a.num_predict,
        a.keep_alive,
        a.json_retries,
        a.request_timeout_seconds,
    )


def register(app: typer.Typer, handled: Callable[..., Any], out: Console, err: Console) -> None:
    """Add the Phase 5 commands to ``app``."""

    def paths_of(ctx: typer.Context) -> Paths:
        return ctx.obj

    @app.command("llm-check")
    @handled
    def llm_check(
        model: Annotated[str | None, typer.Option(help="Model (default from settings)")] = None,
    ) -> None:
        """Ollama reachable, models present, a tiny structured call, latency, tokens/s, context."""
        s = load_settings()
        have = installed_models(s.ollama.host)
        want = model or s.agent.default_model
        out.print(f"ollama reachable at {s.ollama.host}; {len(have)} model(s) installed")
        for m in dict.fromkeys([want, s.ollama.secondary_model]):
            out.print(f"model {m}: {'present' if m in have else 'MISSING'}")
        if want not in have:
            raise UserError(f"model {want} is not installed (this tool never pulls models)")
        client = make_client("ollama", s, want)
        res = client.chat([{"role": "user", "content": 'Reply with {"status":"ok"}.'}], Ping,
                          "check")  # fmt: skip
        if not res.ok:
            raise UserError(f"the structured test call failed: {res.error}")
        tps = res.completion_tokens / (res.duration_ms / 1000) if res.duration_ms else 0.0
        loaded = getattr(client, "loaded_ctx", None)
        out.print(
            f"structured call OK: {res.duration_ms} ms, prompt {res.prompt_tokens} + "
            f"completion {res.completion_tokens} tokens, about {tps:.1f} tokens/s"
        )
        out.print(f"num_ctx sent: {res.num_ctx}; loaded context reported by server: "
                  f"{loaded if loaded is not None else 'not exposed'}")  # fmt: skip

    @app.command("agent-run")
    @handled
    def agent_run(
        ctx: typer.Context,
        case_id: str,
        model: Annotated[str | None, typer.Option(help="Model name")] = None,
        max_rounds: Annotated[int | None, typer.Option(help="Planner rounds")] = None,
        seed: Annotated[int | None, typer.Option(help="Sampling seed")] = None,
        llm: Annotated[str, typer.Option("--llm", help="ollama or fake:PATH")] = "ollama",
    ) -> None:
        """Run the agent on a normalized case (migrates the database to schema v4 first)."""
        paths, s = paths_of(ctx), load_settings()
        if max_rounds is not None:
            s.agent.planner_max_rounds = max_rounds
        if seed is not None:
            s.ollama.seed = seed
        migrate_to_v4(paths)
        res = run_agent(paths, case_id, make_client(llm, s, model), s)
        c = res.counts
        by = Counter(f.status for f in res.findings)
        out.print(f"{res.run_id}: {res.status} ({res.stop_reason}) in {res.elapsed_s:.1f} s")
        out.print(f"llm calls {c.get('llm_calls', 0)}, tool calls {c.get('tool_calls', 0)}, tokens "
                  f"{c.get('prompt_tokens', 0)}+{c.get('completion_tokens', 0)}, invalid json "
                  f"{c.get('invalid_json', 0)}, retries {c.get('retries', 0)}, truncated "
                  f"{c.get('truncated', 0)}")  # fmt: skip
        out.print(f"findings: {dict(by) or 'none'}; trace sha256 {res.trace_sha256[:16]}...")
        if res.status in ("failed", "aborted"):
            raise typer.Exit(1)

    @app.command("agent-runs")
    @handled
    def agent_runs(ctx: typer.Context, case: Annotated[str | None, typer.Option()] = None) -> None:
        """List agent runs."""
        t = Table("run", "case", "model", "status", "stop", "llm", "tool", "findings", "started")
        for r in store.list_runs(paths_of(ctx), case):
            n = len(store.list_findings(paths_of(ctx), r["run_id"]))
            t.add_row(
                r["run_id"],
                r["case_id"],
                r["model"],
                r["status"],
                r["stop_reason"] or "",
                str(r["llm_calls"]),
                str(r["tool_calls"]),
                str(n),
                r["started_at"][:19],
            )
        out.print(t)

    @app.command("findings-show")
    @handled
    def findings_show(
        ctx: typer.Context,
        run_id: str,
        status: Annotated[str | None, typer.Option(help="verified|downgraded|rejected")] = None,
    ) -> None:
        """Findings of a run. The claim column is MODEL-PRODUCED text, capped at 120 characters."""
        t = Table("finding", "status", "type", "conf", "evt", "hit", "revises", "problems",
                  f"claim (MODEL TEXT, max {CLAIM_COLUMN_CAP} chars)")  # fmt: skip
        for f in store.list_findings(paths_of(ctx), run_id, status):
            codes = ",".join(sorted(set(f.verification.codes()))) or "-"
            t.add_row(f.finding_id, f.status, f.claim_type, f.confidence,
                      str(len(f.cited_event_uids)), str(len(f.cited_hit_ids)),
                      f.revised_from or "-", codes, Text(f.claim[:CLAIM_COLUMN_CAP]))  # fmt: skip
        out.print(t)

    @app.command("agent-trace")
    @handled
    def agent_trace(
        ctx: typer.Context, run_id: str, limit: Annotated[int, typer.Option()] = 60
    ) -> None:
        """Structured summary of a run's trace (ids, counts, statuses; no model text)."""
        lines = read_trace(paths_of(ctx).runs_dir / run_id / "trace.jsonl")
        t = Table("step", "role", "action", "detail", "tokens in/out", "ms")
        for x in lines[:limit]:
            d = " ".join(f"{k}={x[k]}" for k in ("tool", "ok", "error_kind", "act", "status",
                         "finding_id", "stop", "worker_role", "round") if k in x)  # fmt: skip
            for k in ("shown", "total", "verified", "downgraded", "rejected"):
                d += f" {k}={x[k]}" if k in x else ""
            toks = f"{x.get('tokens_in', '')}/{x.get('tokens_out', '')}" if "tokens_in" in x else ""
            t.add_row(
                str(x["step"]), x["role"], x["action"], d, toks, str(x.get("duration_ms", ""))
            )
        out.print(t, highlight=False)
        out.print(f"{len(lines)} trace step(s); showing {min(limit, len(lines))}")

    @app.command("agent-replay")
    @handled
    def agent_replay(ctx: typer.Context, run_id: str) -> None:
        """Re-run a recorded run offline against its recorded LLM replies and compare."""
        rep = replay_run(paths_of(ctx), run_id, load_settings())
        if rep.ok:
            out.print(f"replay OK: {rep.replay} reproduces {rep.original} "
                      "(findings, statuses and tool-call sequence identical)")  # fmt: skip
            return
        for p in rep.problems:
            err.print(p, highlight=False, markup=False)
        raise typer.Exit(1)

    @app.command("agent-peek")
    @handled
    def agent_peek(ctx: typer.Context, run_id: str) -> None:
        """EVAL ONLY, PRELIMINARY mechanics check against the answer key (not the Phase 9 eval)."""
        from chainofproof.eval.agent_peek import peek, render

        out.print(render(peek(paths_of(ctx), run_id)), highlight=False, markup=False)
