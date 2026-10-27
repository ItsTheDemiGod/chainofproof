# Phase 5.1: agent interface fixes and dev/test split

## Built
* `protocol/` package (neutral): `splits.py` (DEV/TEST split from `scenarios/credtheft_lateral_v4/splits.yaml`),
  `guard.py` (freeze fingerprint, `write_freeze`, `check_run_allowed`, `record_test_run`). `run_agent` calls the
  guard itself; `agent-freeze --confirm` (humans only); `agent-peek` refuses TEST runs without a matching freeze.
* Schema v5 (`agent_runs`: `arg_errors`, `format_errors`, `duplicate_refusals`, `split`).
* Seed-scoped scenario build (`--seed S` on scenario-keys/generate/build/verify; `scenarios/invariants.py`;
  seed-aware `source_map`). Base-seed key hashes unchanged (a test pins them).
* `tools/describe.py` typed signature lines, lenient list filters, templated argument errors (no echo).
* Prompts v2 to v4 (generated TOOLS/WORKERS sections, citation format, legend line), format-error pre-check,
  duplicate suppression, argument-error budget, optional `mandatory_correlator_review` (off).
* Docs: `evaluation_protocol.md`, `agents.md`, `tools.md`, `prompt_changelog.md`, `decisions.md`, README.

## Tests
Baseline 512 passed / 4 skipped / 1 deselected; now 598 passed / 4 skipped / 1 deselected (`-m "not llm"`), ruff clean.

## Cases
16 new cases (seeds 201-203 DEV, 301-305 TEST, both variants) built, normalized (0 corrupt) and graphed;
`verify_all` OK (13 evidence items each). `scenario-verify --seed S` OK for all 8 seeds. DEV seeds: detectors found
3/3 planted contradictions on every perturbed case with 0 unexpected hits and all collateral explained; clean cases
only the log_clear hit. No agent run, no detector run and no evaluation touched a TEST case.

## Mechanical dev check (qwen2.5:7b-instruct, default settings)
See the summary table in `docs/decisions.md` (Phase 5.1). Round 0 (v2): 1 of 4 runs passed all criteria; round 1
(v3): 2 of 4; round 2 (v4, the last allowed): 1 of 4 (RUN-000617). Remaining failure: correlator-only runs on
clean cases see no EVT id (no detector hit exists) and cite labels. Not iterated further (protocol).
