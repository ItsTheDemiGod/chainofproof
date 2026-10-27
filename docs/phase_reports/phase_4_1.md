# Phase 4.1: generator realism rebuild, scenario v4

## Why
The Phase 4 style audit showed that lines named by the answer key could be told apart from benign
synthetic lines by generator habits (event types, users, source addresses, round times, middle-of-log
position, file extension/directory/depth) and that benign traffic had no complete connection pairs,
so the `unmatched_connection` detector only ever saw the two planted links. An LLM could exploit
those habits, and the detector precision numbers proved little.

## What was built
* Scenario `credtheft_lateral_v4` (`git mv` from v3; v1-v3 cases stay as SUPERSEDED history).
* Generator (`scenarios/gen_*.py`, all under 300 lines): shared vocabulary (`gen_vocab`), per-host
  spans and density (`gen_time`), benign standalone lines (`gen_benign`), connections built by ONE
  builder for benign and key links with time-ordered ids `CONN-0001...` (`gen_conns`, `gen_links`),
  filesystem vocabulary (`gen_fs`, `gen_fs_vocab`), perturbations (`gen_perturb`).
* New non-round stage times, per-host log spans, seeded P3 window (720 s, DCSync inside, never on a
  minute boundary), innocuous credential-dump file name.
* Key schema: `expected_collateral_conn_ids` on the log-gap contradiction, validated by the schema and
  by `scenario-verify` against both generated variants.
* Detector fix (precision guard, not a threshold): clock_skew pairs by pipe name only on the same
  virtual host, within `pair_window_seconds` (900), one-to-one.
* Evaluation: explained collateral reported separately; robustness table shows it per seed.
* `tools/registry.py` split into `registry.py` + `registry_args.py`; `generator.py` split into
  `generator.py` + `gen_perturb.py`.

## How to run
```
.venv\Scripts\python.exe -m chainofproof scenario-keys credtheft_lateral_v4
.venv\Scripts\python.exe -m chainofproof scenario-verify credtheft_lateral_v4
.venv\Scripts\python.exe -m chainofproof scenario-build credtheft_lateral_v4 clean      # and perturbed
.venv\Scripts\python.exe -m chainofproof normalize credtheft_lateral_v4_clean           # and _perturbed
.venv\Scripts\python.exe -m chainofproof graph-build credtheft_lateral_v4_clean
.venv\Scripts\python.exe -m chainofproof detect-all credtheft_lateral_v4_clean
.venv\Scripts\python.exe -m chainofproof eval-detectors credtheft_lateral_v4_clean credtheft_lateral_v4_perturbed --baseline-md docs/detector_baseline.md
.venv\Scripts\python.exe -m chainofproof style-audit credtheft_lateral_v4_clean credtheft_lateral_v4_perturbed --out docs/style_audit.md
```
(`style-audit` overwrites the generated part of `docs/style_audit.md`; the hand-written "Phase 4.1"
section at its end must be re-appended.)

## Results (no threshold was changed)
* `scenario-verify credtheft_lateral_v4`: OK (hashes, alignment, keys incl. links and collateral,
  determinism, adjudication).
* Cases `credtheft_lateral_v4_clean` (EV-000079..EV-000091) and `credtheft_lateral_v4_perturbed`
  (EV-000092..EV-000104); normalization runs RUN-000064..RUN-000103, graphs RUN-000104/105,
  detect-all RUN-000106..115, evaluation runs RUN-000116..125.
* Detectors: perturbed 3 of 3 contradictions, precision 1/1 per detector (timestomp 2/2), explained
  collateral 2 of 2 (CONN-0053, CONN-0055), GT-LNK-004 (CONN-0054) flagged, 0 unexpected hits. Clean:
  only the log_clear hit for GT-ACT-008, 0 unexpected hits. Seeds 101-105: same, collateral recomputed
  per seed (4, 3, 1, 3, 1 ids), 0 unexpected hits (`docs/detector_baseline.md`).
* Style audit: 8 features separated cleanly in v3, 1 in v4 (`name_stem`, an exception documented as
  unavoidable); `dir_prefix` weak (0.20). See the before/after table in `docs/style_audit.md`.
* Tests: 376 passed, 4 skipped, 1 deselected (`-m "not llm"`; baseline 335 / 1 / 1). The 3 new
  skips are on the small fixture scenario: two v4-only timing tests (the fixture keeps round stage
  times on purpose) and the pipe-guard test that needs the committed files. Ruff check and format clean on `src tests scripts`.

## Decisions and assumptions
See `docs/decisions.md`, section "Phase 4.1". The ones to review: benign `drsuapi` name-resolution
pairs and benign replication-style requests of a sync service account (needed by the vocabulary
invariant), benign type 9 logons of user01, and no benign sub-second values (the formats have none).

## Open issues
* Residual tells (`docs/style_audit.md`): real names in the key pipe lines, `mimikatz.exe`,
  `PsExec.exe` and the prefetch hash name, the depth-2 `C:\Windows\svchost.exe` prefix.
* The detectors still know which perturbation types exist; v4 removes the style shortcuts, not the
  design-time knowledge.
* Both ends of every benign connection have delta 0 s; real logs have small jitter. Kept because the
  oracle for the planted skew (`delta 0 s` in the clean variant) relies on it.
* Hayabusa-only comparison is unchanged (0 of 3 contradictions, by construction).
