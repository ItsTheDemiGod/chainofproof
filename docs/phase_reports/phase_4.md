# Phase 4: evidence graph and contradiction detectors

## What was built
* Schema v3 (`detector_runs`, `detector_hits`, `graph_runs`) with the safe backup-then-migrate pattern.
* Evidence graph (`graph/`): deterministic node/edge rules, entity resolution, byte-identical export, IP resolution only from agent-view evidence; agent tools `graph_stats`, `entity_summary`, `neighbors`, `find_paths`, `host_links`.
* Five separate detectors (`tools/detectors/`): timestomp, clock_skew, log_gap, log_clear, unmatched_connection; stored runs and hits (`HIT-######`), deterministic `hit_key`s.
* Tool registry with pydantic arguments, role permissions and JSON-schema export (no LLM).
* Eval only: detector evaluation (`eval/detector_eval.py`, `robustness.py`, `detector_report.py`) and the style-tell audit (`eval/style_audit.py`).
* CLI: `graph-build`, `graph-show`, `detect`, `detect-all`, `hits-show`, `eval-detectors`, `style-audit`.

## Results on the real database (no threshold was changed after the first run)
* Perturbed: 3 of 3 planted contradictions found (timestomp 2 files, +420 s skew on the SRV-FILE-02 auth log, DC-01 seq 144-156 gap); precision timestomp 2/2, clock_skew 1/1, log_gap 1/1, unmatched_connection 1/1 (CONN-002), log_clear 1/1 (GT-ACT-008 indicator); 0 unexpected hits.
* Clean: 0 contradictions; only the log_clear hit for GT-ACT-008; 0 unexpected hits.
* Seeds 101-105, both variants: same result every time (`docs/detector_baseline.md`).
* Style audit: auth `event`, `user`, `src_ip`, `key_presence` and timeline `extension`, `dir_prefix`, `depth`, `name_stem` separate referenced from benign lines cleanly; timestamps and sizes do not (`docs/style_audit.md`). Nothing was changed in the generator.
* Hayabusa-only: 0 of 3 contradictions, by construction (trivial comparison).

## Tests
260 passed at the start of the phase; now 335 passed, 1 skipped, 1 deselected (`-m "not llm"`), including the dataset-marked leakage run of every registered tool on both real cases. Ruff check and format clean on `src tests scripts`.

## Open issues
* The detectors were designed knowing which perturbations exist; the robustness run shows they are stable across seeds, not that they would find unknown anomalies.
* A style tell exists (see the audit); whether to fix it and rebuild as scenario v4 is the owner's decision.
* A clock offset below 2 s is invisible by design (`min_abs_delta_seconds`).
* Detector tools write run records even when called by the skeptic role.
