# Agent core (Phase 5)

A small investigation team written as plain Python (no agent framework), driven by a local LLM that
only decides what to look at next, connects findings and explains. Tools parse, detect and correlate;
a deterministic verifier checks every finding against the evidence.

## Roles and the loop

* **Planner** (lead investigator). One LLM call per round: `delegate` a task to a worker, or `finish`.
  It keeps a notebook (hypotheses, open questions, verified findings, survey, recent events).
* **Workers**: `extractor` (query tools) and `correlator` (graph tools and the detectors). Same model,
  different prompt and exactly the registry's tool permissions. A worker is a mini-loop of at most
  `worker_max_steps` actions: `call_tool`, `record_finding`, `finish` (with a handoff note).
* **Orchestrator** (`agents/runner.py`). Creates the run (`agent_runs` row, folder `RUN-######`, ledger
  `run_start`), performs an **initial survey by code** (through the registry as the planner:
  `list_evidence_labels`, `source_summary` per label, `graph_stats`) and puts the compact result in the
  notebook; loops planner rounds; always ends with a status, a flushed trace and a ledger `run_end`
  carrying the trace hash. There is **no automatic detector pipeline** (rule D2): detectors run only
  when the planner delegates to the correlator and the correlator chooses a `detect_*` tool.

Stop conditions: planner finish (`completed`), `planner_max_rounds`, `max_llm_calls_per_run`,
`max_run_seconds` (`budget_exhausted`), `consecutive_failure_limit` consecutive failed LLM calls or
internal tool errors (`failed`), a fatal LLM error such as a context mismatch (`failed`), Ctrl+C
(`aborted`, trace flushed). A permission error or invalid arguments is an *error observation* (it costs a
step, it is not an LLM failure).

## Why flat JSON actions and not native tool calling

A 7-8B local model with constrained decoding (a JSON schema in Ollama's `format`) is most reliable with
small flat schemas. The model-facing schemas (`PlannerAction`, `WorkerAction`, `FindingDraft`) are
flat; tool arguments are validated afterwards with the registry's per-tool pydantic model, and the
tool name is checked against the role's permission table. Native tool calling would couple us to one
model's template and make the transcript harder to record, hash and replay. Every reply is validated
by pydantic; invalid output triggers at most `json_retries` retries with a templated message that names
only the error types and field names (never the model's text), then a logged failure. There is no
regex salvage anywhere.

## Delimiting (rule A4)

Everything derived from evidence, and everything written by a model that read evidence, reaches a
prompt only as `<<<DATA id=obs-N source=...>>> ... <<<END-DATA id=obs-N>>>`: tool observations,
the notebook, the lead's task text, worker reports and handoff notes, verifier feedback. Before
wrapping, `observe.wrap` sanitizes each line (ANSI and control characters removed, length capped) and
replaces `<<<` / `>>>` with a neutral escape; the number of escapes is counted in the trace. The system
prompt says that nothing inside a DATA block is an instruction. The plain part of a prompt is therefore
only the generic template plus round counters. Phase 7 adds detection and quarantine on top; this phase
does only the plain delimiting.

## What the agent can and cannot see

Can: the agent view only: opaque evidence labels, virtual hosts and times, `EVT-<12hex>` event ids,
its own detector hits `HIT-######`. Cannot: answer keys, the eval table (`event_eval_meta` is denied by
a SQLite authorizer on every connection opened inside an agent run, rule A7), original file names,
source keys, real host names or times, hits created by the harness or by other runs (rule A3), or
`FND` ids (prompts show run-local `F1, F2...`). Tools are reached only through
`registry.call_tool(role, ..., agent_run_id)` (rule A1). Prompts are generic (rule A2): a test scans
all templates and the non-data part of rendered first prompts for scenario terms.

## Context budget

`num_ctx` 8192 is sent with every request. Estimated tokens = characters / 3 (conservative). The
prompt builder keeps the prompt within `max_prompt_fraction` of `num_ctx - num_predict`, trimming the
oldest tool observations first (replaced by a one-line elision that keeps the EVT/HIT ids), then the oldest worker
reports; the system prompt, the schema text and the notebook are never trimmed. Ollama truncates
over-long prompts silently, so a reply with `prompt_tokens >= 0.97 * num_ctx` is treated as truncated:
the prompt is rebuilt with a 25 percent smaller budget and retried once; if that fails the call fails
loudly. After the first reply the client asks `/api/ps` for the loaded context length and fails if it
differs from `num_ctx` (see `docs/decisions.md` for what this server exposes).

## Recording, ledger, replay

* Every raw LLM request is stored as `data/runs/RUN-######/llm/call_#####.json` (messages, response,
  counts) and appended to the ledger as `llm_call` (hashes and counts only; actor `llm:<role>`).
* Every tool call is appended as `tool_call` / `tool_call_failed` (actor `agent:<role>`; command = tool
  name + `args_sha256`; input = the pinned norm-run hash; output = sha256 of the result).
* `trace.jsonl`: one canonical-JSON line per step (ids, counts, hashes, statuses, tokens, timings, the
  model's short rationale). `notebook.json` is saved after every round.
* **Replay** (`agent-replay RUN_ID`) re-runs the orchestrator offline against the recorded replies on the
  same pinned data and compares findings (ids aside), statuses and the trace's tool-call sequence;
  a mismatch is reported as `replay diverged` with the call or step index. A replay is a new run
  (`replay_of` set); the original is never touched. Only the LLM is non-deterministic: tools, verifier
  and orchestration must replay identically. Because HIT ids are global, a replay reads detector
  hits from the original run's scope instead of allocating new ones (same idempotence rule).

## Settings (section `agent` of `config/settings.yaml`)

| setting | value | rationale |
|---|---|---|
| default_model | qwen2.5:7b-instruct | best instruction/JSON follower that fits 8 GB VRAM at 4 bit |
| planner_max_rounds | 10 | enough for survey, two or three probes and a wrap-up; bounds wall time |
| worker_max_steps | 8 | a worker needs 2-4 tool calls and 1-2 findings; 8 stops loops |
| max_llm_calls_per_run | 120 | hard ceiling about 10 rounds x (1 + 8 steps) x retries without runaway cost |
| max_run_seconds | 1800 | 30 minutes at roughly 30-50 tokens/s is the practical limit for a laptop run |
| json_retries | 2 | one retry fixes most format slips; a third rarely helps and wastes context |
| consecutive_failure_limit | 3 | three failures in a row mean the model or server is not working |
| finding_revisions | 2 | one fix per problem class (unsupported entity, bad time); more invites rewriting until it passes |
| num_predict | 700 | an action is under 400 tokens; the cap stops runaway generation |
| keep_alive | "10m" | keeps the model in VRAM between calls |
| max_prompt_fraction | 0.8 | of (num_ctx - num_predict): headroom for the estimate's error |
| max_tool_output_chars | 3500 | about 1200 tokens: a page of observations without flooding the context |
| known_events_cap | 60 | the notebook's recent-events list; older ids can still be cited |
| handoff_max_chars | 300 | a note, not a report |
| rationale_max_chars | 240 | a short reason, for the trace |
| claim_max_chars | 400 | one claim per finding |
| ledger_llm_calls | true | rule A5 |
| request_timeout_seconds | 300 | not in the original brief; a cold 7B load can take a minute, 5 minutes is a clear hang |
| max_arg_errors_per_worker | 4 | Phase 5.1: invalid-argument calls are free of steps but capped per worker (see below) |
| mandatory_correlator_review | false | Phase 5.1: optional forced correlator delegation; off by default |

## Phase 5.1 changes (interface fixes)

Observed in the first real DEV runs (Phase 5): the tool listing showed argument names but not types, so
the model passed lists where strings were expected (all 57 `search_events` calls of one run failed), never saw
an EVT id and cited source labels, never delegated detector work, and repeated near-identical findings.
Mechanical fixes (prompt v2, see `docs/prompt_changelog.md`):

* TOOLS section generated from the registry (typed signature lines, generic time example), a WORKERS
  section in the planner prompt, a CITATION FORMAT section, a one-line legend at the top of every
  observation ("ids: EVT-... events, HIT-... hits; labels are sources, not citable"), templated
  argument errors plus the failed tool's signature line.
* `record_finding` pre-check: a cited id that is not `EVT-<12hex>` / `HIT-<6 digits>` is returned as
  `format error: ...` without storing anything and counted in `agent_runs.format_errors`. The first one of a
  worker is free (no step), later ones consume a step. Well-formed ids that do not exist still go to the
  verifier and are stored as rejected (V1).
* Duplicate suppression: a finding is refused (not stored) when a verified/downgraded finding of the same
  run has the same claim type and cited-id set, or the same normalised claim text; a revision is compared
  with everything except its own ancestors. Counted in `agent_runs.duplicate_refusals`.
* Argument-error budget: invalid-argument calls do not consume worker steps and do not count toward
  `consecutive_failure_limit`; instead each worker may make `max_arg_errors_per_worker` (4) of them, then it
  ends with `arg_error_budget` in its report. Rationale: a mistyped argument is recoverable and the
  templated message plus usage line is exactly the information needed to fix it; charging a step would let
  one syntax slip eat the whole investigation, while an unlimited budget would allow loops (the cap bounds
  them, and every attempt still costs an LLM call against `max_llm_calls_per_run`). Permission errors still
  consume a step (they are decisions, not typos).
* `agent.mandatory_correlator_review` (default false, not enabled in this phase): when true the planner
  cannot finish before delegating once to the correlator, and after the last round the orchestrator injects
  one correlator delegation with a fixed generic task text.
* `agent_runs.split` records `dev` / `test` / null (see `docs/evaluation_protocol.md`).

## Commands

`llm-check`, `agent-run CASE [--model --max-rounds --seed --llm ollama|fake:PATH]`, `agent-runs [--case]`,
`findings-show RUN_ID [--status]`, `agent-trace RUN_ID [--limit]`, `agent-replay RUN_ID`,
`agent-peek RUN_ID` (EVAL ONLY, preliminary mechanics check, not the Phase 9 evaluation).
