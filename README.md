# ChainOfProof

Autonomous digital forensics and evidence correlation agent (solo Agentic AI course project).
Multi-agent investigation of simulated incident evidence (event logs, memory dump, network logs)
where every claim cites evidence IDs. Fully local (Ollama), free, reproducible.
See `CLAUDE.md` for principles, architecture and phases.

## Status
Phases 0 (setup) and 1 (evidence ingestion and chain of custody) done. Next: Phase 2 (datasets and ground truth).

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

## How to use (Phase 1 CLI)
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

Tamper demo (temp dir only): `.venv\Scripts\python.exe scripts\demo_tamper.py`
