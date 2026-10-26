# Decisions

## Phase 0
- **Project path:** work was done in `C:\Users\demia\Desktop\chainofproof` (the session's current directory), not `C:\Users\demia\chainofproof` as written in CLAUDE.md. CLAUDE.md text kept verbatim; paths in code are resolved relative to the project root, so the location does not matter.
- **Python:** `python` on PATH is MSYS2 Python 3.14 (venv layout `bin/`, not `Scripts/`). The venv uses the official CPython 3.12.4 at `AppData\Local\Programs\Python\Python312` instead (satisfies >=3.11).
- **Build backend:** setuptools (src layout), added because pyproject needs one; not a runtime dependency.
- **Ruff rules:** E, F, I, UP, B on top of line length 100.
- **.env:** `load_settings()` overrides `OLLAMA_HOST` and reads the three optional API keys into `optional_cloud`.
- **.gitignore:** `data/**` with `!data/**/` and `!data/**/.gitkeep` negations.
## Phase 1
- **Paths:** one `Paths` model (`get_paths`) feeds all Phase 1 code. With `base_dir` the layout is `evidence_raw/`, `evidence_working/`, `db/`, `ledger/`, `runs/` under it. From settings, `base_dir` is the parent of `evidence_raw` (i.e. `data/`), so `vault_path` is stored relative to it with forward slashes.
- **Tamper-evident, not tamper-proof:** hash chain + SQLite `ledger_head` anchor detect edits, deletes, reorders and tail truncation. An attacker who can rewrite BOTH `ledger.jsonl` and `chainofproof.db` can forge a consistent history. Exporting `ledger-head` externally (later: in reports) strengthens it.
- **Append refuses a mismatched anchor:** `Ledger.append` raises if the file end and the anchor disagree, so truncation cannot be hidden by the next append.
- **Hash of an entry** is computed over the raw JSON dict (timestamp as `...Z` string with microseconds), not a pydantic round trip, so verification does not depend on pydantic serialization.
- **Verify reports per-entry problems and resyncs** on the entry's own stored hash/ID, so one tamper yields one message with the ledger ID. A deleted middle entry is reported at the entry after the gap (non-sequential ID); a swap at the first out-of-order ID.
- **Locking:** `ledger.jsonl.lock` with `msvcrt.locking` (Windows) / `fcntl.flock`, plus a per-path `threading.Lock`. The last line is re-read under the lock.
- **Evidence ID allocation** is `MAX+1` in an immediate transaction, before the copy (the ID is in the vault filename). The insert is a separate transaction; the primary key catches a race and ingest cleans up.
- **Rollback:** any failure after the vault copy removes the vault file, deletes the DB row if inserted, and writes `ingest_failed` (best effort).
- **Duplicates** are per `(case_id, sha256)`; the same file in another case is ingested again.
- **Filename sanitizing** is ASCII-only (unicode letters become `_`), capped at 100 chars keeping the extension, leading dots replaced by `_`.
- **Read-only on Windows** is the file attribute; stops accidental edits only. A cleared flag is a `WARN:` problem, not a failure; hash/size/missing are failures.
- **`SourceType`** is a `StrEnum` (ruff UP042); behaves as a str Enum.
- **Case creation** from the CLI is logged to the ledger (`case_create`); `EvidenceStore.create_case` itself does not log.
- **Errors:** expected failures subclass `UserError`; the CLI prints one `error: ...` line and exits 1.
- **Logging in the CLI:** ingest progress and the duplicate notice go through `logging` (RichHandler on stderr).
- **Symlink test** is skipped on this machine (no symlink privilege).
