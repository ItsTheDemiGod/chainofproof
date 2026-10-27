# Phase 2.1: Synthetic/real alignment and key completion

## What was built
- **Field inspection** (`scenarios/fieldscan.py`, `scripts/field_inspect.py`): metadata-only
  `field_inspection.json` (per-event rows for S1 to S5, EventID counts and the noteworthy-EventID scan
  for all seven real files). Command lines are reduced to length plus boolean flags.
- **Pairing rules R1 to R3** in the generator: every synthetic attacker record carries
  `pair=<field>:<value>` or `synth_only=1` (file) and `pairing_*` / `synthetic_only` (key);
  `PSEXESVC.exe`, the SMB admin-share line and the S3 PsExec artifacts are gone; PsExec artifacts
  exist only at S4, paired by image basename or pipe name.
- **Key completion:** GT-ACT-008 (Security 1102, T1070.001, medium), richer S3/S4 key events, new
  GT-MIS-004, reworded S3/S4 descriptions, appended-ID mechanism so GT-ACT-001 to 007 did not move.
- **Adjudication list** (`schemas/adjudication.py`, `adjudication.yaml`, 10 draft entries) with
  loader, validation and the scoring policy.
- **Scenario v2:** `git mv` of v1 to `credtheft_lateral_v2` (`supersedes` note); v1 cases kept as
  superseded history; new cases `credtheft_lateral_v2_clean` / `_perturbed` ingested.
- **Test-only oracles** (`tests/oracles.py`) proving P1, P2, P3 are detectable and that the key
  matches the data.
- **Splits:** `schemas/{common,groundtruth,scenario,adjudication}.py`,
  `scenarios/{keyevents,keyevents_base,rules_early,rules_lateral}.py`; all files under 300 lines.

## How to run
```powershell
.venv\Scripts\python.exe scripts\field_inspect.py credtheft_lateral_v2
.venv\Scripts\python.exe -m chainofproof scenario-inventory credtheft_lateral_v2 --force
.venv\Scripts\python.exe -m chainofproof scenario-keys credtheft_lateral_v2
.venv\Scripts\python.exe -m chainofproof scenario-verify credtheft_lateral_v2
.venv\Scripts\python.exe -m chainofproof scenario-build credtheft_lateral_v2 clean
.venv\Scripts\python.exe -m chainofproof scenario-build credtheft_lateral_v2 perturbed
```

## Results
- Tests: **149 passed, 1 skipped (symlink privilege), 1 deselected (llm)**; baseline was 113 passed.
  New: oracles (5), pairing rules R1 to R3 and schema pairing (12), adjudication and 1102 (10),
  field inspection / rules / dataset cross-check (9).
- `ruff check` and `ruff format --check` on `src tests scripts`: clean.
- `scenario-verify credtheft_lateral_v2`: OK (dataset hashes, alignment, keys, determinism,
  adjudication). Dataset clone clean. Ledger: 108 entries, verified (was 80).
- Cases: `credtheft_lateral_v2_clean` EV-000027 to EV-000039, `credtheft_lateral_v2_perturbed`
  EV-000040 to EV-000052.

## Perturbations (exact)
| ID | Magnitude | Pairing | Claimed checks (all proven by oracle tests) |
|---|---|---|---|
| P1 timestomp | 2 files, 86476700 s and 86470528 s | image basename svchost.exe / psexec.exe | `si_fn_mismatch` only |
| P2 clock skew | +420 s on 270 lines | `pipe_name` -> real Sysmon 18 records 409650/51/52; clean delta 0 s, perturbed +420 s | `paired_line_time_delta` |
| P3 log gap | 720 s, seq 144-155 | real S5 4662 records 202791 to 202793 inside the window | `seq_discontinuity`, `real_events_inside_gap` |

## Decisions and open issues
See `docs/decisions.md` (Phase 2.1). Open: adjudication entries are drafts pending human review;
the S2 log clear may be lab preparation (medium); S3/S4 origin of the connection is not shown by any
source; P1 has no cross-source check; v1 cases remain in the vault as superseded history.
