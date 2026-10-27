# Phase 2.2: Cross-host synthetic links

## What was built
- **Two synthetic connections** (`scenarios/gen_links.py`), four auth-log lines, all `synth_only=1`
  with a shared `conn_id`: CONN-001 WS-FIN-07 to SRV-FILE-02 (smb, type-3 logon of user01) at the S3
  start, CONN-002 SRV-FILE-02 to DC-01 (drsuapi) at the S5 time. `seq` stays contiguous in the clean
  variant (assigned after insertion). Parser validates `conn_id`.
- **Link ground truth:** `GroundTruthLink` (GT-LNK-###, kinds `credential_reuse`, `lateral_movement`,
  `remote_replication`, `stage_continuation`; basis `synthetic_only` / `alignment_constructed`),
  `LinkRef`, `AnswerKey.links`, validators; four links in both keys (`scenarios/keylinks.py`);
  `check_link_refs` proves each ref resolves.
- **Two extra detection checks:** `cross_host_pair_delta` (P2) and `unmatched_connection` (P3), with
  test-only oracles in `tests/oracles.py` (not the Phase 4 detectors).
- **Scenario v3:** `git mv` v2 to `credtheft_lateral_v3` (`supersedes: credtheft_lateral_v2`); v1/v2
  cases remain as SUPERSEDED history. Cases `credtheft_lateral_v3_clean` EV-000053 to EV-000065 and
  `credtheft_lateral_v3_perturbed` EV-000066 to EV-000078.
- GT-MIS-004 reworded; link evaluation policy in `docs/scenarios.md`.

## How to run
```powershell
.venv\Scripts\python.exe -m chainofproof scenario-keys credtheft_lateral_v3
.venv\Scripts\python.exe -m chainofproof scenario-verify credtheft_lateral_v3
.venv\Scripts\python.exe -m chainofproof scenario-build credtheft_lateral_v3 clean
.venv\Scripts\python.exe -m chainofproof scenario-build credtheft_lateral_v3 perturbed
.venv\Scripts\python.exe -m chainofproof scenario-key-show credtheft_lateral_v3 perturbed
```

## Results
- Tests: **189 passed, 1 skipped (symlink privilege), 1 deselected (llm)**; baseline 149 passed.
- `ruff check` / `ruff format --check` on `src tests scripts`: clean.
- `scenario-verify credtheft_lateral_v3`: OK. Dataset clone clean. Ledger 214 entries, verified
  (was 160); `verify-evidence --case` run once per case: 13 items OK each.

## Perturbations (exact, v3)
| ID | Magnitude | Claimed checks (all proven by oracle tests) |
|---|---|---|
| P1 timestomp | 2 files, 86476700 s and 86470528 s (unchanged) | `si_fn_mismatch` |
| P2 clock skew | +420 s on 272 SRV-FILE-02 lines (was 270) | `paired_line_time_delta`, `cross_host_pair_delta` (CONN-001: 0 s clean, +420 s perturbed, synthetic vs synthetic) |
| P3 log gap | 720 s, 13 lines, seq 144-156 (was 12, 144-155) | `seq_discontinuity`, `real_events_inside_gap`, `unmatched_connection` (CONN-002) |

## Decisions and open issues
See `docs/decisions.md` (Phase 2.2). Open: all cross-host evidence is synthetic, so link results must
be reported in the two separate categories; LINK-A is deliberately not paired with the real inbound
445 record; adjudication entries remain drafts pending human review.
