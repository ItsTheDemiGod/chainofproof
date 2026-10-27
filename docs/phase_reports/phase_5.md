# Phase 5: agent core

## Built
LLM package (`llm/`: base with retry/truncation/recording, Ollama client, fake, replay, budget), schemas
(`schemas/agent.py`, `findings.py`), schema v4 migration (agent_runs, agent_calls, findings, origin and
agent_run_id on detector tables), agent scoping (`tools/scope.py`, restricted connection), deterministic
citation verifier (V1-V6), agent runtime (`agents/`: runner, planner, worker, context, notebook, observe,
prompts, store, trace, replay), CLI (`cli_agent.py`), preliminary peek (`eval/agent_peek.py`).
Docs: `agents.md`, `verifier.md`, `prompt_changelog.md`, `tools.md`, `decisions.md`, `style_audit_history.md`.

## Run
`agent-run CASE`, `agent-runs`, `findings-show`, `agent-trace`, `agent-replay`, `llm-check`, `agent-peek`.

## Tests
Baseline 376 passed / 4 skipped / 1 deselected; now 512 passed / 4 skipped / 1 deselected. ruff clean. Verifier tests by
rule (test functions): V1 3, V2 3, V3 6, V4 3, V5 4 (+3 tolerance/helper tests), V6 1.

## Migration
Backup `chainofproof.db.pre-v4` (sha256 `add9f392e47518ce...`), ledger `db_migrate` LED-000512 (v3 -> v4).

## Real-model mechanics check (qwen2.5:7b-instruct, defaults, prompt_version `0dc201de...`)
| | clean (RUN-000126) | perturbed (RUN-000127) |
|---|---|---|
| wall time | 611 s | 733 s |
| status / stop | budget_exhausted / planner_max_rounds | same |
| LLM calls / tool calls | 90 / 72 | 93 / 53 |
| tokens prompt+completion | 241795+24158 | 272944+30026 |
| invalid JSON / retries / truncation | 0 / 0 / 0 | 8 / 7 / 0 (one call failed after 3 attempts) |
| findings | 23 rejected | 28 rejected, 9 downgraded |
| problem codes | V1 x72 | V6 x28, V4 x18 |
| tools chosen | search_events 57 (all invalid args), source_summary 13 (6 survey + 7), labels 1, graph_stats 1 | search_events 38 (27 invalid args), same others |
| detectors run | none | none |
Replay of RUN-000127 offline: OK (RUN-000128). `agent-peek`: 0 of 14 (clean) and 0 of 17 (perturbed) key items touched (PRELIMINARY; not an evaluation).
No mechanical bug appeared (no crash, no overflow, no unhandled error), so no code or prompt was changed after the first real run.

## Model behaviour worth knowing for Phase 6
* Cited source labels (`AUTH-xxxxxx`) instead of `EVT-` ids (clean: all 23 findings V1-rejected); in the perturbed run, findings cited nothing (V6) or had times outside the cited window (V4). The verifier did its job: no unsupported claim survived as `verified`.
* Passed lists where tools expect scalars (`host: [..]`); the tool listing shows argument names but not types. A prompt change would be needed (prompt v2, log it in `prompt_changelog.md`); deliberately not done in Phase 5.
* Never delegated a detector run to the correlator effectively (one correlator round in the clean run, none useful), so the contradiction detectors were never used by the agent.
* Repeated near-identical findings (up to 12 versions of one claim) show the revision/dedup behaviour needs the skeptic.

## Open issues
Prompt v2 (arg types, "cite EVT ids, not labels") is a Phase 6 decision. Replay of an interrupted/aborted run is untested on real data.
