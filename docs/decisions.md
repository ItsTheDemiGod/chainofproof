# Decisions

## Phase 0
- **Project path:** work was done in `C:\Users\demia\Desktop\chainofproof` (the session's current directory), not `C:\Users\demia\chainofproof` as written in CLAUDE.md. CLAUDE.md text kept verbatim; paths in code are resolved relative to the project root, so the location does not matter.
- **Python:** `python` on PATH is MSYS2 Python 3.14 (venv layout `bin/`, not `Scripts/`). The venv uses the official CPython 3.12.4 at `AppData\Local\Programs\Python\Python312` instead (satisfies >=3.11).
- **Build backend:** setuptools (src layout), added because pyproject needs one; not a runtime dependency.
- **Ruff rules:** E, F, I, UP, B on top of line length 100.
- **.env:** `load_settings()` overrides `OLLAMA_HOST` and reads the three optional API keys into `optional_cloud`.
- **.gitignore:** `data/**` with `!data/**/` and `!data/**/.gitkeep` negations.