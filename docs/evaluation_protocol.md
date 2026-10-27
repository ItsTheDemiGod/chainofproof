# Evaluation protocol (Phase 5.1)

Rules E1 to E3 (also in `CLAUDE.md`). Code: `chainofproof/protocol/` (`splits.py`, `guard.py`),
`scenarios/credtheft_lateral_v4/splits.yaml`.

## Split

| split | cases | use |
|---|---|---|
| DEV | `credtheft_lateral_v4_{clean,perturbed}` (base seed), seeds 201, 202, 203: `credtheft_lateral_v4_s<seed>_{clean,perturbed}` | judging prompt, tool and error-message fixes on MECHANICAL metrics only |
| TEST | seeds 301 to 305: `credtheft_lateral_v4_s<seed>_{clean,perturbed}` | final evaluation (Phase 9), never run before a freeze |
| unassigned | v1 to v3 and any case not listed | unrestricted |

Seed cases are built with `scenario-keys / scenario-verify / scenario-build --seed S`; generated files
go to `data/scenarios_generated/credtheft_lateral_v4/seed_<S>/<variant>/` (gitignored), keys to
`scenarios/credtheft_lateral_v4/seeds/<S>/key_<variant>.yaml` (committed). The base seed's files and key
hashes are unchanged (a test pins them). `scenario-verify --seed S` checks dataset hashes, determinism,
keys vs schemas, the collateral list and the Phase 4.1 generator invariants (`scenarios/invariants.py`).

## Rules

* **E1.** DEV cases may be used to judge prompt and tool fixes, on mechanical metrics only (tool-error
  rate, JSON validity after retries, citation-format validity, run completion), never on whether the agent
  found the attack. TEST cases are never run by any agent until a human has frozen prompts and parameters
  with `agent-freeze`; the guard is enforced in code (`run_agent` itself calls it, not only the CLI).
* **E2.** After the first agent run on a TEST case, any change to prompts, agent parameters or tools used by
  agents invalidates the freeze (a new freeze and a statement in the write-up are required). Every prompt or
  parameter change after the first real DEV run needs an entry in `docs/prompt_changelog.md` with the
  observed MECHANICAL problem that caused it.
* **E3.** Claude Code must not run `agent-run` on a TEST case, must not execute `agent-freeze`, and must not
  read, print or summarise any agent output for TEST cases. `agent-peek` output must not be used to change
  prompts, parameters or tools in the same phase.

## Freeze and guard

`agent-freeze --confirm [--note TEXT]` (humans only) appends a ledger entry `prompt_freeze` with exactly:
`prompt_version`, `settings_sha256` (hash of the `agent` settings block), `model`, `tool_registry_sha256`
(sha256 over the canonical JSON of every registered tool spec: name, description, parameter and return
schemas, roles) and the optional `note`. Without `--confirm` it prints what would be frozen and refuses.

`run_agent` calls `check_run_allowed` before it creates the run: DEV and unassigned cases pass; a TEST case
needs a `prompt_freeze` entry whose three values equal the CURRENT values (a later change of a template, a
setting or a tool spec makes the freeze stale: one-line refusal naming what changed). A TEST run appends
`test_split_run` (freeze ledger id, case id, run id) at run start and stores `agent_runs.split`. `agent-peek`
applies the same check to TEST runs. `agent-replay` is allowed for every recorded run (it calls no LLM).

## Mechanical success criteria (fixed BEFORE the Phase 5.1 dev runs)

Per run, over the four DEV runs (`credtheft_lateral_v4_perturbed`, `credtheft_lateral_v4_clean`,
`credtheft_lateral_v4_s201_perturbed`, `credtheft_lateral_v4_s202_clean`), default settings, qwen2.5:7b-instruct:

| criterion | pass when |
|---|---|
| tool_error_rate | tool calls returning an error / all tool calls <= 0.15 |
| invalid JSON | calls failed with invalid output after retries = 0 |
| format_errors / record_finding attempts | <= 0.20 |
| run status | not `failed` |
| citable ids seen | at least one EVT id appears in a worker observation |

Reported, not criteria: delegations per role, detectors run by the agent, findings by status, duplicate
refusals, arg errors, wall time, tokens per second. At most TWO rounds of fixes (prompts, tool descriptions,
error messages, argument handling) are allowed, only for the mechanical problem observed, each with a
changelog entry; after two rounds the state is reported as is. Nothing is changed because of which findings
the agent did or did not make; `agent-peek` runs only after the last round and nothing changes after it.

## Honest limitation

The real attack events are identical across all seeds: the seeds change only the synthetic background,
timing, benign-pair placement and perturbation placement. The split therefore tests generalisation over
synthetic variation, not over different real attacks.

## Intended use in Phase 9

Decide and write down the final prompts and parameters on DEV; run `agent-freeze --confirm`; run the agent
on the five TEST seeds (both variants) once each; score with the Phase 9 evaluation; report DEV and TEST
separately. Any change after the first TEST run requires a new freeze and a statement in the write-up.
