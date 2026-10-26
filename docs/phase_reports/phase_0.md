# Phase 0 report: Setup

## Built
- CLAUDE.md (project charter), README.md, folder structure with package skeleton under `src/chainofproof/`.
- `pyproject.toml` (deps: pydantic, pyyaml, python-dotenv, httpx, ollama, rich, typer; dev: pytest, ruff), `.gitignore`, `.env.example`.
- `config/settings.yaml` and `src/chainofproof/config.py` (`load_settings()`).
- `scripts/check_ollama.py` smoke test; `tests/test_config.py`; `tests/test_ollama_smoke.py` (`@pytest.mark.llm`).

## Run
```powershell
.venv\Scripts\python.exe -m ruff check .
.venv\Scripts\python.exe -m pytest -m "not llm"
.venv\Scripts\python.exe -m pytest -m llm
.venv\Scripts\python.exe scripts\check_ollama.py
```

## Results
- ruff check/format clean; 2 non-llm tests pass; llm smoke test passes.
- check_ollama: OK `{'status': 'ok'}`, latency about 3.5 s, about 47 tokens/s (qwen2.5:7b-instruct).

## Decisions
See docs/decisions.md (Phase 0 section).

## Open issues
- Project path in CLAUDE.md environment notes differs from the actual location (Desktop).