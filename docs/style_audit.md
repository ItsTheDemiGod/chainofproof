# Style-tell audit (report only)

"Referenced" lines are the synthetic lines (auth logs, file-system timelines) named anywhere in
the answer key (GT-ACT, GT-LNK, GT-CON, adjudication); "benign" lines are all the others.

Verdict rule (fixed before the first run), applied identically to every feature after turning it
into a categorical bucket: ``coverage`` = share of referenced lines whose bucket value occurs in NO
benign line of the same source kind.  coverage >= 0.5 -> "separates cleanly"; 0 < coverage < 0.5
-> "weak"; coverage == 0 -> "none". Counts only, no statistical tests (about 20 referenced lines).
Nothing is changed in the generator by this module.

`si_*` vs `fn_*` differences are not listed as a feature: they ARE the planted timestomp perturbation, not a style tell.

## credtheft_lateral_v3_clean

* auth_log: 9 referenced lines, 800 benign lines
* fs_timeline: 5 referenced lines, 1187 benign lines

| source | feature | verdict | coverage | referenced-only (ref/ben) |
|---|---|---|---|---|
| auth_log | event | separates cleanly | 0.78 | NAMED_PIPE_OPEN (3/0); CONN_OUT (2/0); CONN_ACCEPTED (1/0); DIRECTORY_REPLICATION_REQUEST (1/0) |
| auth_log | user | separates cleanly | 1.00 | None (6/0); user01 (2/0); Administrator (1/0) |
| auth_log | logon_type | weak | 0.11 | 9 (1/0) |
| auth_log | service | weak | 0.33 | drsuapi (2/0); smb (1/0) |
| auth_log | dst_host | none | 0.00 | - |
| auth_log | src_ip | separates cleanly | 1.00 | 10.20.2.2 (5/0); 10.20.1.7 (3/0); None (1/0) |
| auth_log | key_presence | separates cleanly | 0.89 | conn_id,dst_host,service,src_ip (3/0); dst_host,pipe_name,src_ip (3/0); conn_id,dst_host,logon_type,src_ip,user (1/0); dst_host,logon_id,user (1/0) |
| auth_log | second_of_minute | none | 0.00 | - |
| auth_log | minute_of_hour | none | 0.00 | - |
| auth_log | zero_microseconds | none | 0.00 | - |
| auth_log | position_decile | none | 0.00 | - |
| fs_timeline | extension | separates cleanly | 0.80 | .exe (3/0); .pf (1/0) |
| fs_timeline | dir_prefix | separates cleanly | 0.80 | c:\users\ieuser (2/0); c:\windows\prefetch (1/0); c:\windows\svchost.exe (1/0) |
| fs_timeline | depth | separates cleanly | 0.60 | 6 (2/0); 2 (1/0) |
| fs_timeline | size_bucket | none | 0.00 | - |
| fs_timeline | name_stem | separates cleanly | 1.00 | mimikatz (1/0); powershell.exe-bfc (1/0); psexec (1/0); sekurlsa_out (1/0); svchost (1/0) |
| fs_timeline | second_of_minute | none | 0.00 | - |
| fs_timeline | minute_of_hour | none | 0.00 | - |
| fs_timeline | zero_microseconds | none | 0.00 | - |
| fs_timeline | position_decile | none | 0.00 | - |

Position deciles (auth_log), referenced: [0, 0, 0, 0, 5, 4, 0, 0, 0, 0]; benign: [79, 81, 81, 82, 76, 77, 82, 81, 81, 80]

Position deciles (fs_timeline), referenced: [0, 0, 0, 2, 0, 0, 2, 0, 1, 0]; benign: [118, 119, 120, 117, 120, 119, 118, 119, 119, 118]

## credtheft_lateral_v3_perturbed

* auth_log: 7 referenced lines, 789 benign lines
* fs_timeline: 5 referenced lines, 1187 benign lines

| source | feature | verdict | coverage | referenced-only (ref/ben) |
|---|---|---|---|---|
| auth_log | event | separates cleanly | 0.71 | NAMED_PIPE_OPEN (3/0); CONN_OUT (2/0) |
| auth_log | user | separates cleanly | 1.00 | None (5/0); user01 (2/0) |
| auth_log | logon_type | weak | 0.14 | 9 (1/0) |
| auth_log | service | weak | 0.29 | drsuapi (1/0); smb (1/0) |
| auth_log | dst_host | none | 0.00 | - |
| auth_log | src_ip | separates cleanly | 1.00 | 10.20.2.2 (4/0); 10.20.1.7 (3/0) |
| auth_log | key_presence | separates cleanly | 0.86 | dst_host,pipe_name,src_ip (3/0); conn_id,dst_host,service,src_ip (2/0); conn_id,dst_host,logon_type,src_ip,user (1/0) |
| auth_log | second_of_minute | none | 0.00 | - |
| auth_log | minute_of_hour | none | 0.00 | - |
| auth_log | zero_microseconds | none | 0.00 | - |
| auth_log | position_decile | none | 0.00 | - |
| fs_timeline | extension | separates cleanly | 0.80 | .exe (3/0); .pf (1/0) |
| fs_timeline | dir_prefix | separates cleanly | 0.80 | c:\users\ieuser (2/0); c:\windows\prefetch (1/0); c:\windows\svchost.exe (1/0) |
| fs_timeline | depth | separates cleanly | 0.60 | 6 (2/0); 2 (1/0) |
| fs_timeline | size_bucket | none | 0.00 | - |
| fs_timeline | name_stem | separates cleanly | 1.00 | mimikatz (1/0); powershell.exe-bfc (1/0); psexec (1/0); sekurlsa_out (1/0); svchost (1/0) |
| fs_timeline | second_of_minute | none | 0.00 | - |
| fs_timeline | minute_of_hour | none | 0.00 | - |
| fs_timeline | zero_microseconds | none | 0.00 | - |
| fs_timeline | position_decile | none | 0.00 | - |

Position deciles (auth_log), referenced: [0, 0, 0, 0, 5, 2, 0, 0, 0, 0]; benign: [79, 81, 81, 82, 76, 66, 82, 81, 81, 80]

Position deciles (fs_timeline), referenced: [0, 0, 0, 2, 0, 0, 2, 0, 1, 0]; benign: [118, 119, 120, 117, 120, 119, 118, 119, 119, 118]

## Features that separate cleanly (in at least one case)

* depth
* dir_prefix
* event
* extension
* key_presence
* name_stem
* src_ip
* user

## Recommended generator changes (NOT applied; ordered by number of cases)

1. `event`: Draw benign event names from the same pool the key lines use (e.g. add benign CONN_OUT/CONN_ACCEPTED and NAMED_PIPE_OPEN lines).
2. `user`: Use the same account vocabulary for benign and key lines (the key lines use `user01`, `unknown` or machine names that no benign line uses).
3. `src_ip`: Draw benign source addresses from the virtual hosts' own addresses as well.
4. `key_presence`: Make the set of keys per line identical across benign and key lines.
5. `extension`: Give benign files the same extensions as the key files (.exe, .pf, .txt).
6. `dir_prefix`: Place benign files in the same directories as the key files.
7. `depth`: Match path depth distributions.
8. `name_stem`: Generate benign file names from a vocabulary that includes tool-like names (and avoid names that appear only in key rows).
