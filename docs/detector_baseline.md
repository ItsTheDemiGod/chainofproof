# Detector baseline (deterministic, no LLM)

All five detectors were run with their default parameters (`config/settings.yaml`, section
`detectors`, fixed before the first run) on the real v4 cases. A hit counts as *found* only under
the matching rules in `eval/detector_eval.py` (exact file set for timestomp, exact missing seq range
for the log gap, offset within 1 s of the key for clock skew). Unmatched-connection hits on benign
connections whose DC-01 end the gap removed are *explained collateral* (listed separately, not
counted as unexpected hits or in the precision denominator). Nothing was tuned.

## credtheft_lateral_v4_clean

This variant has no planted contradictions.

Action indicators (not contradictions): GT-ACT-008 <- HIT-000024

| detector | matched / total hits |
|---|---|
| log_clear | 1 / 1 |

Unexpected hits: **0**


Link check (unmatched_connection per conn_id of each GT-LNK):

* GT-LNK-002 CONN-0036: flagged = False
* GT-LNK-004 CONN-0054: flagged = False

## credtheft_lateral_v4_perturbed

Recall: **3 of 3** planted contradictions found.

| contradiction | kind | found | matching hits | measured | key |
|---|---|---|---|---|---|
| GT-CON-001 | timestomp | yes | HIT-000025, HIT-000026 | 2 files, max deltas [86470681.0, 86476853.0] | 2 files, deltas [86470681, 86476853] |
| GT-CON-002 | clock_skew | yes | HIT-000027 | offsets [420.0] | 420 s |
| GT-CON-003 | log_gap | yes | HIT-000028 | ranges [(216, 238)] | seq 216-238 |

Action indicators (not contradictions): GT-ACT-008 <- HIT-000029

| detector | matched / total hits |
|---|---|
| clock_skew | 1 / 1 |
| log_clear | 1 / 1 |
| log_gap | 1 / 1 |
| timestomp | 2 / 2 |
| unmatched_connection | 1 / 1 |

Explained collateral (unmatched_connection on benign connections broken by the gap): **2 of 2** expected conn_ids flagged (CONN-0053, CONN-0055); missed: none.

Unexpected hits: **0**


Link check (unmatched_connection per conn_id of each GT-LNK):

* GT-LNK-002 CONN-0036: flagged = False
* GT-LNK-004 CONN-0054: flagged = True

## Robustness across seeds

Synthetic files regenerated into a temp folder per seed (nothing ingested), combined with the real EVTX events of the existing case, all detectors in memory.

| variant | seed | found | explained collateral | unexpected hits |
|---|---|---|---|---|
| clean | 101 | - | 0 of 0 | none |
| clean | 102 | - | 0 of 0 | none |
| clean | 103 | - | 0 of 0 | none |
| clean | 104 | - | 0 of 0 | none |
| clean | 105 | - | 0 of 0 | none |
| perturbed | 101 | GT-CON-001=yes, GT-CON-002=yes, GT-CON-003=yes | 4 of 4 | none |
| perturbed | 102 | GT-CON-001=yes, GT-CON-002=yes, GT-CON-003=yes | 3 of 3 | none |
| perturbed | 103 | GT-CON-001=yes, GT-CON-002=yes, GT-CON-003=yes | 1 of 1 | none |
| perturbed | 104 | GT-CON-001=yes, GT-CON-002=yes, GT-CON-003=yes | 3 of 3 | none |
| perturbed | 105 | GT-CON-001=yes, GT-CON-002=yes, GT-CON-003=yes | 1 of 1 | none |

## Hayabusa-only comparison (trivial)

| system | contradictions found |
|---|---|
| Hayabusa-only (`docs/hayabusa_baseline.md`) | 0 of 3, by construction |

Hayabusa reads EVTX files one at a time. The three contradictions live in the synthetic file-system and auth sources and in disagreement BETWEEN sources, which a single-source rule engine cannot see; the comparison is trivial and is listed only for completeness.

