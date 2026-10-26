# Phase 2: Datasets, scenario definition, answer keys

## What was built
- **Task 0 (Phase 1 fixes):** `Ledger.recover()` + `ledger-recover` (explicit, refuses truncation/tampering); `EvidenceStore.create_case` now logs `case_create` itself.
- `schemas/scenario.py`: strict pydantic models (SourceSpec, Stage, AlignmentEntry, GroundTruth*, AnswerKey, Scenario), ID patterns in one place, YAML load/save with deterministic key order, reference validators.
- `scenarios/`: `evtx_meta.py` (python-evtx + defusedxml streaming reader), `keyevents.py` (per-stage rules), `inventory.py`, `dataset.py` (paths, hash/commit drift check), `companions.py` (formats + parsers), `gen_context.py`, `gen_fs.py`, `gen_auth.py`, `generator.py` (variants + perturbations), `keys.py`, `build.py` (workflows).
- `cli_scenarios.py` registered on the main app; `scripts/bootstrap_credtheft_v1.py` (how `scenario.yaml` was authored, kept for provenance).
- Committed data: `scenarios/credtheft_lateral_v1/{scenario.yaml, inventory.json, key_clean.yaml, key_perturbed.yaml}`.
- Docs: `docs/scenarios.md`, `docs/decisions.md` (Phase 2 section).

## How to run
```powershell
.venv\Scripts\python.exe -m chainofproof scenario-list
.venv\Scripts\python.exe -m chainofproof scenario-inventory credtheft_lateral_v1 --force   # rewrites inventory.json
.venv\Scripts\python.exe -m chainofproof scenario-keys credtheft_lateral_v1
.venv\Scripts\python.exe -m chainofproof scenario-generate credtheft_lateral_v1 perturbed
.venv\Scripts\python.exe -m chainofproof scenario-build credtheft_lateral_v1 clean         # case + ingest of 13 sources
.venv\Scripts\python.exe -m chainofproof scenario-verify credtheft_lateral_v1              # exit 0/1
.venv\Scripts\python.exe -m chainofproof scenario-key-show credtheft_lateral_v1 perturbed
.venv\Scripts\python.exe -m chainofproof ledger-recover
```
Example: `scenario-verify` prints `scenario credtheft_lateral_v1: OK (dataset hashes, keys, determinism)`.

## Stage table
| Stage | Real file | Virtual host | Techniques (verified) | Offset s | Virtual start |
|---|---|---|---|---|---|
| S1 | Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords | WS-FIN-07 | T1003.001 | 157382569 | 09:00:00 |
| S2 | Lateral Movement/LM_4624_mimikatz_sekurlsa_pth_source_machine | WS-FIN-07 | T1550.002 (medium) | 157328311 | 09:25:00 |
| S3 | Lateral Movement/LM_sysmon_psexec_smb_meterpreter | SRV-FILE-02 | T1021.002, T1569.002 (both medium) | 153580389 | 09:40:00 |
| S4 | Defense Evasion/DE_renamed_psexec_service_sysmon_17_18 | SRV-FILE-02 | T1036.003 (medium), T1569.002 (high) | 109023180 | 09:55:00 |
| S5 | Credential Access/CA_DCSync_4662 | DC-01 | T1003.006 | 152958257 | 10:35:00 |
| D1 | Persistence/sysmon_13_1_persistence_via_winlogon_shell | WS-HR-03 | decoy (T1547.004) | 149693863 | 12:00:00 |
| D2 | Execution/exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX | SRV-WEB-01 | decoy (T1218.011) | 152581317 | 14:00:00 |

No stage was unresolved; every expected technique had supporting events. No stage is low confidence.
S2 and S3 are medium for the reasons in `docs/scenarios.md`.

## Key events (clean key)
| GT-ACT | Stage | Technique | Real EventRecordIDs (EventID) | Real time (UTC) | Virtual time | Conf. |
|---|---|---|---|---|---|---|
| 001 | S1 | T1003.001 | 4807 (10) | 2019-03-17T19:37:11.661928Z | 2024-03-12T09:00:00.661928Z | high |
| 002 | S2 | T1550.002 | 432903 (4624), 432904 (4672) | 2019-03-18T11:06:29.911579Z | 2024-03-12T09:25:00.911579Z | medium |
| 003 | S3 | T1021.002 | 9804 (18) | 2019-04-30T20:26:51.793589Z | 2024-03-12T09:40:00.793589Z | medium |
| 004 | S3 | T1569.002 | 9806 (13), 9807 (1) | 2019-04-30T20:26:51.981089Z | 2024-03-12T09:40:00.981089Z | medium |
| 005 | S4 | T1036.003 | 409645 (17) | 2020-09-27T13:42:00.726774Z | 2024-03-12T09:55:00.726774Z | medium |
| 006 | S4 | T1569.002 | 409647 (17), 409650 (18) | 2020-09-27T13:42:01.092665Z | 2024-03-12T09:55:01.092665Z | high |
| 007 | S5 | T1003.006 | 202791-202793 (4662) | 2019-05-08T02:10:43.487217Z | 2024-03-12T10:35:00.487217Z | high |

Rationale per row is in the key (`rationale` field, names only the fields used).

## Tests
`pytest -m "not llm"`: 113 passed, 1 skipped (symlink privilege, Phase 1), 1 deselected (llm). New: ledger-recover and case-logging (12), schema (7), generator/perturbation/key-agreement/parsers, key-event rules + corrupt-record + billion-laughs (9), CLI/build idempotency, and 3 `@pytest.mark.dataset` tests that run on the real files (they skip if the dataset is missing). Ruff check and format are clean on `src tests scripts`.

## Decisions
See `docs/decisions.md` (Phase 2): technique verification, host/account mapping, decoy choice, alignment anchor, schema additions, ruff-scope incident.

## Open issues
- Phase 2 key events were found with python-evtx + Python rules; Phase 3 must link normalized (Hayabusa) events to these `GT-ACT` record IDs.
- S3's real payload is Meterpreter PowerShell, so the synthetic PSEXESVC.exe is an assumption.
- Decoy techniques are only lightly verified (no key events needed).
- The real S2 file has a Security 1102 (audit log cleared); not in the key, but a real anti-forensics signal for Phase 4.
- Dataset license unverified; do not redistribute raw files.
- Only one scenario exists; evaluation (Phase 9) should vary seeds and the `noise` knobs.
