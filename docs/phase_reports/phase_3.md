# Phase 3: forensic tool layer and normalized event format

## What was built
* Sanitizer (`ingest/sanitize.py`), three parsers (EVTX, file-system CSV, auth log), per-source alignment, normalizer and case pipeline, Hayabusa 4.2.0 wrapper with fingerprint, schema v2 migration, agent-facing query API, eval helpers (`gt_link`, `coverage`, `baseline`), CLI commands.
* Two layers: the agent view (`events`, `detections`) and the eval layer (`event_eval_meta`), enforced by a leakage scan over full table dumps and an import-boundary test. Details in `docs/tools.md`; decisions in `docs/decisions.md` (section Phase 3).
* Housekeeping: GT-ADJ-001 and GT-ADJ-006 are `true_finding`, all adjudication entries signed off; `verify_all` writes one summary ledger entry.

## How to run
```
.venv\Scripts\python.exe -m chainofproof tools-check
.venv\Scripts\python.exe -m chainofproof normalize credtheft_lateral_v3_clean
.venv\Scripts\python.exe -m chainofproof normalize credtheft_lateral_v3_perturbed
.venv\Scripts\python.exe -m chainofproof eval-coverage credtheft_lateral_v3_clean credtheft_lateral_v3_perturbed --baseline-md docs/hayabusa_baseline.md
.venv\Scripts\python.exe -m chainofproof events-stats credtheft_lateral_v3_clean
```

## Results on the real database
* Migration: backup `chainofproof.db.pre-v2` (sha256 `24985995...`), ledger entry LED-000215 `db_migrate` (v1 to v2).
* Both cases: 13 evidence items each, 0 corrupt records, 0 unlinked detections; real-source event counts equal the inventory; 0 unresolved key references (49 clean, 62 perturbed); 8 of 8 alignment checks exact; GT-CON-001/002/003 still present after normalization.
* Hayabusa-only baseline: 8 of 8 GT-ACT have at least one firing rule (high 4, medium 1, informational 3); the 2 `true_finding` adjudication events fire informational rules only (`docs/hayabusa_baseline.md`).
* Free-text leakage report (not failures): 18 occurrences of a real computer name per case inside free-text columns (pipe names such as `svchost-MSEDGEWIN10-8116-stdin`, a real content value); 0 pre-2024 dates in free text.
* Final ledger: 325 entries, chain and head anchor OK; both cases verify OK (one `verify_all` entry each).

## Tests
189 passed at the start of the phase; now 260 passed, 1 skipped, 1 deselected (`-m "not llm"`): 250 non-dataset plus 10 dataset-marked (4 earlier, 6 new integration tests with the real Hayabusa and EVTX in a temp base). Ruff check and format clean on `src tests scripts`.

## Open issues
* Instruction-like text inside evidence is only made inert (sanitizer); detection and quarantine are Phase 7. `injection_flags` is reserved and empty.
* Real content values (pipe names with a lab computer name) stay visible to agents by design.
* Hayabusa timestamps differ by up to 2 microseconds from python-evtx (rounding); detections link by RecordID and never by time.
* Volatility and Plaso are not used (no memory image; sources are EVTX/CSV/text).
