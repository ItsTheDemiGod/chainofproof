# ChainOfProof

Autonomous digital forensics and evidence correlation agent (solo Agentic AI course project).
Multi-agent investigation of simulated incident evidence (event logs, memory dump, network logs)
where every claim cites evidence IDs. Fully local (Ollama), free, reproducible.
See `CLAUDE.md` for principles, architecture and phases.

## Status
Phase 0 (setup) done. Next: Phase 1 (evidence ingestion and chain of custody).

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
