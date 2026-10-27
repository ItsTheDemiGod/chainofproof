# Evidence graph (Phase 4)

A `networkx.MultiDiGraph` built from agent-view events ONLY (latest completed normalization run per
evidence). Code: `graph/entities.py` (ids and entity resolution), `graph/builder.py` (rules),
`graph/export.py` (deterministic export, `graph_runs` row, ledger entry). Agents reach it through
`tools/graph_query.py` (`graph_stats`, `entity_summary`, `neighbors`, `find_paths`, `host_links`).

## Nodes

| id | type | notes |
|---|---|---|
| `host:<virtual host>` | host | |
| `user:<account>` | user | lower case, domain prefix removed; `display_forms` keeps the original spellings; `is_machine_account` for names ending in `$` |
| `proc:<host>:<image basename, lower>` | proc | the same image on two hosts is two nodes |
| `file:<host>:<path>` | file | path as given (sanitized, id capped at 200 chars) |
| `ip:<address>` | ip | |
| `conn:<conn_id>` | conn | |
| `pipe:<name>` | pipe | leading backslashes dropped (`\p` and `p` are one pipe) |
| `svc:<host>:<name>` | svc | |
| `regkey:<host>:<target>` | regkey | capped |
| `source:<evidence label>` | source | the evidence source itself |

Every node has `type`, `first_seen`, `last_seen` (virtual time) and `event_count` (events that touch it).

## Edges

One edge per (source, target, relation), aggregating all supporting events. Every edge has
`relation`, `event_uids` (at most 50; `event_count` keeps the true total), `first_ts`, `last_ts`,
`evidence_labels`.

| relation | rule |
|---|---|
| `logged_on` host -> user | `logon` (EVTX 4624) and `auth_logon` events with a user (failed logons excluded) |
| `authenticated_to` user -> host | `auth_logon` events with a user (attribute `src_ips`) |
| `ran_on` proc -> host | any event with a process image; also the parent process |
| `ran_as` proc -> user | process event with a user |
| `spawned` proc -> proc | `process_create` / `process_create_security` with a parent image (same host) |
| `accessed` proc -> proc | `process_access` |
| `created` proc -> file | `file_create` |
| `wrote` proc -> regkey | `registry_set` |
| `created_pipe` / `connected_pipe` proc -> pipe | `pipe_created` / `pipe_connected` |
| `opened_pipe` host -> pipe | an event with a pipe name and no process (auth-log pipe lines) |
| `connected_to` proc -> ip | `network_connect` (attribute `directions`) |
| `connected_to` host -> host | shared `conn_id` (see below); attributes `conn_ids`, `ends_seen` |
| `saw_conn` host -> conn | any event carrying a `conn_id` (attribute `ends`) |
| `used_by` ip -> host | ONLY when the events show it (see below) |
| `seen_from` ip -> host | an auth/connection line on the host names this source address (association NOT claimed) |
| `has_service` host -> svc | `service_install`, or a registry write under `...\Services\<name>\...` |
| `has_file` host -> file | `file_timeline` rows (extra relation, added so timeline files are nodes) |
| `observed_on` source -> host | the source contains events of that host (extra relation) |

## Host-to-host links

Events are grouped by `conn_id`. A `CONN_OUT` event on host A with `dst_host` B gives `A -> B`.
If only a destination end exists, the source host is taken from the IP map built from `used_by`
edges when that IP maps to exactly one host; otherwise no host edge is made. `ends_seen` lists
which end each host's log showed, so a connection with a missing end is visible (CONN-002 in the
perturbed case has only `SRV-FILE-02: CONN_OUT`).

## Unresolved IPs

The scenario IP map is never used. An IP is attached to a host (`used_by`) only when the
agent-view data itself shows it: a Sysmon 3 event with `Initiated=true` (source address is local) or
`Initiated=false` (destination address is local), or a `CONN_OUT` line (the sender's own address).
Every other IP stays unresolved and is counted (`ips_resolved` / `ips_unresolved` in `graph_stats`
and `graph-build`). In the v4 cases: 4 resolved, 57 unresolved (the benign source addresses).

## Determinism

Events are processed in (timestamp, label, record id, uid) order; the export is canonical JSON
with sorted nodes and edges, so two builds on the same data are byte-identical. The file is
`data/runs/RUN-######/graph_<case>.json`, with a `graph_runs` row and a ledger entry (input hash =
sha256 of the sorted JSONL hashes of the normalization runs used, output hash = file hash).
