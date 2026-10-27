# ChainOfProof

Autonomous digital forensics and evidence correlation agent (solo Agentic AI course project).
Multi-agent investigation of simulated incident evidence (event logs, memory dump, network logs)
where every claim cites evidence IDs. Fully local (Ollama), free, reproducible.
See `CLAUDE.md` for principles, architecture and phases.

## Status
Phases 0 to 3 done (ingestion and custody, datasets and answer keys, cross-host links, forensic tool layer with normalized events). Next: Phase 4 (evidence graph and contradiction detection). See `docs/tools.md`.

## Setup (Windows, PowerShell)
```powershell
python -m venv .venv
.venv\Scripts\pip.exe install -e ".[dev]"
copy .env.example .env   # optional
ollama pull qwen2.5:7b-instruct
ollama pull llama3.1:8b
.venv\Scripts\python.exe scripts\check_ollama.py
.venv\Scripts\python.exe -m pytest -m "not llm"
```

## How to use (CLI)
Run `chainofproof <command>` (or `.venv\Scripts\python.exe -m chainofproof <command>`).
Set `CHAINOFPROOF_BASE_DIR` to use a throwaway data root instead of `data/`.

| Command | Purpose |
|---|---|
| `case-create CASE_ID --title "..." --description "..."` | create a case |
| `case-list` | list cases |
| `ingest CASE_ID FILE [--description "..."] [--type evtx]` | hash, copy to the read-only vault, register, log |
| `evidence-list [--case CASE_ID]` / `evidence-show EV-000001` | browse evidence |
| `verify-evidence [EV-000001] [--case CASE_ID]` | re-hash vault files (exit 1 on mismatch) |
| `working-copy EV-000001` | verified read-only working copy; tools must read this, never `evidence_raw` |
| `ledger-show [--tail N]` | recent ledger entries |
| `ledger-verify` | check hash chain + head anchor (exit 1 if broken) |
| `ledger-head` | head as JSON (publish it externally) |
| `ledger-recover` | explicit crash recovery: re-sync a head anchor that lags by exactly one entry (refuses anything that looks like truncation or tampering) |
| `scenario-list` | scenarios and their answer-key variants |
| `scenario-inventory SCENARIO_ID [--force]` | metadata inventory + key-event discovery of the real EVTX files, writes `inventory.json` |
| `scenario-keys SCENARIO_ID` | (re)write `key_clean.yaml` / `key_perturbed.yaml` |
| `scenario-generate SCENARIO_ID clean\|perturbed [--force]` | write the SYNTHETIC companion files |
| `scenario-build SCENARIO_ID clean\|perturbed [--force]` | verify dataset hashes, generate, create case `<id>_<variant>`, ingest everything |
| `scenario-verify SCENARIO_ID` | dataset hashes, alignment, keys, generator determinism, adjudication list (exit 0/1) |
| `scenario-key-show SCENARIO_ID clean\|perturbed` | answer key as tables |
| `tools-check` | Hayabusa present? version, exe hash, rules-tree hash, can it run help |
| `hayabusa-run EV-000001` | run Hayabusa on the working copy of one EVTX item (output in `data/runs/RUN-######/`) |
| `db-migrate` | migrate the database to schema v2 (online backup first; no-op when already v2) |
| `normalize CASE_ID [--evidence EV-ID]` | migrate if needed, normalize all evidence (agent view + eval layer) and run Hayabusa on every EVTX |
| `events-stats CASE_ID` | per-source counts and event types (agent view only) |
| `events-show CASE_ID [--host H] [--type T] [--limit N]` | normalized events (agent view only, max 50) |
| `eval-coverage CASE_ID... [--baseline-md FILE]` | EVAL ONLY: answer-key coverage, count/alignment checks, Hayabusa-only baseline |

Datasets live in `data/downloads/` (gitignored); see `docs/scenarios.md`. The current scenario is
`credtheft_lateral_v3`: real EVTX captures plus labeled SYNTHETIC companions, including a few
`synth_only` cross-host connection lines (`conn_id`) and the link ground truth (`GT-LNK`); see
"Cross-host links" in `docs/scenarios.md`.

Tamper demo (temp dir only): `.venv\Scripts\python.exe scripts\demo_tamper.py`
