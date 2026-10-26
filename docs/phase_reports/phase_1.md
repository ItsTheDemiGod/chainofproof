# Phase 1: Evidence ingestion and chain of custody

## What was built
- `config.py`: `Paths` model + `get_paths(settings=None, base_dir=None)`. Tests pass `base_dir=tmp_path` and never touch `data/`.
- `schemas/custody.py`: `SourceType`, `EvidenceRecord`, `LedgerEntry`, `IntegrityResult`, `CaseRecord`, ID patterns and `make_evidence_id` / `make_ledger_id` (single source of truth).
- `custody/hashing.py`, `custody/locking.py` (msvcrt / fcntl file lock + threading lock), `custody/ledger.py`, `custody/recorder.py` (`record_tool_call`, `ToolRun`; not wired to tools yet), `custody/db.py`.
- `ingest/store.py` (SQLite), `ingest/detect.py`, `ingest/vault.py`, `ingest/ingest.py`, `ingest/integrity.py`.
- `cli.py` (typer + rich), `__main__.py`, `scripts/demo_tamper.py`.

## How to run
Set `CHAINOFPROOF_BASE_DIR` (or hidden `--base-dir`) to use a throwaway data root; otherwise `data/` is used.
```powershell
chainofproof case-create CASE1 --title "Demo" --description "..."
chainofproof case-list
chainofproof ingest CASE1 C:\path\Security.evtx --description "DC security log" [--type evtx]
chainofproof evidence-list [--case CASE1]
chainofproof evidence-show EV-000001
chainofproof verify-evidence [EV-000001] [--case CASE1]   # exit 1 on hash/size/missing problems
chainofproof working-copy EV-000001                       # prints verified read-only working copy path
chainofproof ledger-show --tail 10
chainofproof ledger-verify                                # exit 1 + first problem if broken
chainofproof ledger-head                                  # JSON, publish it externally
.venv\Scripts\python.exe scripts\demo_tamper.py           # tamper-detection demo, temp dir only
```
Equivalent: `.venv\Scripts\python.exe -m chainofproof <command>`.

## Ledger format
One JSON object per line in `data/ledger/ledger.jsonl`:
```json
{"ledger_id":"LED-000002","timestamp":"2026-10-26T15:49:02.512345Z","actor":"ingest","action":"ingest","command":null,"input_hashes":["0c6b18bd...1d3c"],"output_hash":"9a1f...","details":{"case_id":"DEMO","evidence_id":"EV-000001","original_name":"sample.log","size_bytes":20,"source_type":"log_text"},"prev_hash":"<entry_hash of LED-000001>","entry_hash":"6ecf9e18..."}
```
`entry_hash` = SHA-256 of the canonical JSON (sorted keys, compact) of the entry without `entry_hash`. The first `prev_hash` is 64 zeros. The head `(ledger_id, count, entry_hash)` is mirrored in SQLite table `ledger_head`.

## Threat model and limits
Detected: edited entries, deleted/reordered entries, malformed lines, wrong genesis, truncation of the end (via the SQLite anchor), modified/deleted/resized vault files, cleared read-only flag (warning). `append` refuses to extend a ledger whose anchor does not match, so truncation cannot be "healed" silently.

**The design is tamper-EVIDENT, not tamper-PROOF.** Someone with write access to both `ledger.jsonl` and `chainofproof.db` can rewrite both consistently; an admin can also clear read-only flags. Mitigation: print `ledger-head` output in reports / save it elsewhere, so a rewritten history no longer matches the published head. The ledger records names, sizes and hashes only, never evidence content.

## Tests
`pytest -m "not llm"`: 59 passed, 1 skipped (symlink creation not permitted without privileges on this Windows account), 1 deselected (llm). `pytest -m llm` smoke test: 1 passed (Ollama up). `ruff check` and `ruff format --check`: clean. `scripts/demo_tamper.py`: exit 0, all 5 experiments detected.

## Decisions
See `docs/decisions.md` (Phase 1 section).

## Open issues
- Symlink-rejection test is skipped here; it needs Developer Mode or admin to create symlinks.
- Evidence ID is allocated before the copy (needed for the vault filename); two concurrent ingests could race for the same ID, in which case the second fails cleanly on the primary key and cleans up.
- Crash between the ledger line write and the head upsert leaves the anchor one behind; `ledger-verify` reports it (fail-safe, no auto-repair).
