# Style-tell audit (report only)

"Referenced" lines are the synthetic lines (auth logs, file-system timelines) named anywhere in
the answer key (GT-ACT, GT-LNK, GT-CON, adjudication); "benign" lines are all the others.

Verdict rule (fixed before the first run), applied identically to every feature after turning it
into a categorical bucket: ``coverage`` = share of referenced lines whose bucket value occurs in NO
benign line of the same source kind.  coverage >= 0.5 -> "separates cleanly"; 0 < coverage < 0.5
-> "weak"; coverage == 0 -> "none". Counts only, no statistical tests (about 20 referenced lines).
Nothing is changed in the generator by this module.

`si_*` vs `fn_*` differences are not listed as a feature: they ARE the planted timestomp perturbation, not a style tell.

## credtheft_lateral_v4_clean

* auth_log: 9 referenced lines, 980 benign lines
* fs_timeline: 5 referenced lines, 1147 benign lines

| source | feature | verdict | coverage | referenced-only (ref/ben) |
|---|---|---|---|---|
| auth_log | event | none | 0.00 | - |
| auth_log | user | none | 0.00 | - |
| auth_log | logon_type | none | 0.00 | - |
| auth_log | service | none | 0.00 | - |
| auth_log | dst_host | none | 0.00 | - |
| auth_log | src_ip | none | 0.00 | - |
| auth_log | key_presence | none | 0.00 | - |
| auth_log | second_of_minute | none | 0.00 | - |
| auth_log | minute_of_hour | none | 0.00 | - |
| auth_log | zero_microseconds | none | 0.00 | - |
| auth_log | position_decile | none | 0.00 | - |
| fs_timeline | extension | none | 0.00 | - |
| fs_timeline | dir_prefix | weak | 0.20 | c:\windows\svchost.exe (1/0) |
| fs_timeline | depth | none | 0.00 | - |
| fs_timeline | size_bucket | none | 0.00 | - |
| fs_timeline | name_stem | separates cleanly | 0.60 | mimikatz (1/0); powershell.exe-bfc (1/0); psexec (1/0) |
| fs_timeline | second_of_minute | none | 0.00 | - |
| fs_timeline | minute_of_hour | none | 0.00 | - |
| fs_timeline | zero_microseconds | none | 0.00 | - |
| fs_timeline | position_decile | none | 0.00 | - |

Position deciles (auth_log), referenced: [0, 0, 4, 2, 1, 0, 0, 2, 0, 0]; benign: [98, 99, 95, 98, 97, 99, 100, 97, 99, 98]

Position deciles (fs_timeline), referenced: [0, 0, 0, 2, 0, 0, 2, 0, 1, 0]; benign: [114, 115, 116, 113, 116, 115, 114, 115, 115, 114]

## credtheft_lateral_v4_perturbed

* auth_log: 7 referenced lines, 959 benign lines
* fs_timeline: 5 referenced lines, 1147 benign lines

| source | feature | verdict | coverage | referenced-only (ref/ben) |
|---|---|---|---|---|
| auth_log | event | none | 0.00 | - |
| auth_log | user | none | 0.00 | - |
| auth_log | logon_type | none | 0.00 | - |
| auth_log | service | none | 0.00 | - |
| auth_log | dst_host | none | 0.00 | - |
| auth_log | src_ip | none | 0.00 | - |
| auth_log | key_presence | none | 0.00 | - |
| auth_log | second_of_minute | none | 0.00 | - |
| auth_log | minute_of_hour | none | 0.00 | - |
| auth_log | zero_microseconds | none | 0.00 | - |
| auth_log | position_decile | none | 0.00 | - |
| fs_timeline | extension | none | 0.00 | - |
| fs_timeline | dir_prefix | weak | 0.20 | c:\windows\svchost.exe (1/0) |
| fs_timeline | depth | none | 0.00 | - |
| fs_timeline | size_bucket | none | 0.00 | - |
| fs_timeline | name_stem | separates cleanly | 0.60 | mimikatz (1/0); powershell.exe-bfc (1/0); psexec (1/0) |
| fs_timeline | second_of_minute | none | 0.00 | - |
| fs_timeline | minute_of_hour | none | 0.00 | - |
| fs_timeline | zero_microseconds | none | 0.00 | - |
| fs_timeline | position_decile | none | 0.00 | - |

Position deciles (auth_log), referenced: [0, 0, 4, 2, 1, 0, 0, 0, 0, 0]; benign: [98, 99, 95, 98, 97, 99, 93, 83, 99, 98]

Position deciles (fs_timeline), referenced: [0, 0, 0, 2, 0, 0, 2, 0, 1, 0]; benign: [114, 115, 116, 113, 116, 115, 114, 115, 115, 114]

## Features that separate cleanly (in at least one case)

* name_stem

## Recommended generator changes (NOT applied; ordered by number of cases)

1. `name_stem`: Generate benign file names from a vocabulary that includes tool-like names (and avoid names that appear only in key rows).

