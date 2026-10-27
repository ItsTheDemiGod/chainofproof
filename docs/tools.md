# Phase 3: forensic tool layer and normalized events

Plain-words guide to what each tool does, why there are two layers, and how to rerun everything.

## What was built

| Piece | Where | What it does |
|---|---|---|
| Sanitizer | `ingest/sanitize.py` | Every string that comes out of evidence passes through `sanitize(text, max_len)`: ANSI escapes, NUL, control and invisible-format characters (bidi, zero-width) are removed, tab/newline become a space, the length is capped (2048 default, 4096 command lines, 512 per extra field). It returns `(text, truncated, original_length)`. It does not try to detect instructions (Phase 7): text that imitates instructions to an AI is kept as inert data. |
| EVTX parser | `tools/evtx_parser.py` | python-evtx + defusedxml only. Streams records, counts and skips corrupt ones, handles `EventData` and `UserData` layouts, maps (channel, EventID) to a small event-type enum and extracts users, processes (basenames), pipes, services, IPs, ports. The raw XML is never stored. |
| File-system CSV parser | `tools/fs_timeline_parser.py` | One `file_timeline` event per row; all eight `si_*`/`fn_*` times stay in `fields` for the Phase 4 timestomp detector. |
| Auth log parser | `tools/auth_log_parser.py` | `key=value` lines; `LOGON_*` is `auth_logon`, `CONN_*` is `auth_conn`, the rest `other`. |
| Alignment | `tools/alignment.py` | Per SOURCE FILE (never per computer name): `virtual = real + time_offset_seconds`, host alias from that file's alignment entry. |
| Normalizer | `tools/normalize.py`, `case_run.py` | Reads only the verified working copy, writes `data/runs/RUN-######/normalized_<EV>.jsonl` (deterministic) and database rows, ledger-logged. |
| Hayabusa wrapper | `tools/hayabusa.py`, `hayabusa_fp.py` | Runs Hayabusa on a working copy; parses its JSONL into sanitized `Detection` objects; fingerprints version, exe hash and rules-tree hash. |
| Query API | `tools/query.py` | The only thing agents may call (see below). |
| Eval helpers | `eval/gt_link.py`, `coverage.py`, `baseline.py` | Evaluation only: answer-key references to event ids, coverage checks and the Hayabusa-only baseline. |

## The two layers and why

* **Agent view** (`events`, `detections` tables, `NormalizedEvent`): opaque evidence labels (`EVTX-3fa91c`: kind plus the first six hex characters of the file's sha256, never a file name), opaque event ids `EVT-<12 hex>` (sha256 of the file hash plus the record locator), VIRTUAL timestamps and VIRTUAL hosts only, no ground-truth hints.
* **Eval layer** (`event_eval_meta` table): source key, raw locator, real computer, real timestamp, `synth_only`, pairing field and value, `is_synthetic`, raw note. Readable only from `chainofproof/eval/`, `chainofproof/scenarios/`, `scripts/`, `tests/` and CLI modules.

Why: if an agent could see a source key like `s4_renamed_psexec`, a pairing marker, or a real 2019 timestamp, it could "find" the answer from labels instead of from evidence, and the evaluation would measure nothing. The rules are enforced by tests (a leakage scan over full dumps of the agent-view tables of both variants, and an import-boundary test over `tools/query.py` and the agent-side packages).

Event types: `process_create, network_connect, image_load, process_access, file_create, registry_set, pipe_created, pipe_connected, logon, special_privileges, audit_log_cleared, directory_service_access, service_install, process_create_security, file_timeline, auth_logon, auth_conn, other`.

## Agent query API (`tools/query.py`)

`list_evidence_labels`, `search_events`, `get_event`, `timeline_window`, `get_detections`, `source_summary`. Every result is bounded: default limit 25, hard maximum 50, with `total_matches` and a `truncated` flag. The text filter is a bounded substring match (at most 100 characters, `%` and `_` are literal).

## The alignment layer, per source file

Real EVTX captures are independent. `scenario.yaml` gives every real file its own time offset and host aliases. `IEWIN7` appears in three real files and maps to `SRV-FILE-02`, `WS-HR-03` and `SRV-WEB-01` depending on the file, so aliases are looked up by source key, never globally. Synthetic files are already in virtual time (offset 0). Time-looking field values (Sysmon `UtcTime` and similar) are shifted by the same offset so the agent never sees a 2019 date next to a 2024 timestamp. Field values that are exactly a real computer name are replaced by the virtual host. The normalizer does NOT correct the planted perturbations (the +420 s clock skew, timestomped `si_*` times, removed DC-01 lines): the Phase 4 correlator has to find them.

## The exact Hayabusa command (version 4.2.0)

Hayabusa 4.2.0 has no `csv-timeline`/`json-timeline` commands; the timeline command is `dfir-timeline`. Run with the Hayabusa folder as the working directory:

```
tools_bin/hayabusa/hayabusa-4.2.0-win-x64.exe dfir-timeline -f <working copy> -o data/runs/RUN-######/hayabusa_<EV>.jsonl -t jsonl -p verbose -w -K -q -N -U -O -b -r rules
```

`-t jsonl` JSON lines; `-p verbose` includes timestamp, rule title, level, computer, channel, event id, MITRE tactics and tags, RecordID, rule id; `-w` no wizard; `-K` no colors; `-q` no banner; `-N` no summary; `-U -O` UTC ISO-8601; `-b` full channel names (no abbreviations); `-r rules` the bundled rules folder only. No network is used (`update-rules` is never run). The call is a subprocess argument list (never a shell) with a timeout (300 s from `config/settings.yaml`).

## How to rerun everything

```
.venv\Scripts\python.exe -m chainofproof tools-check
.venv\Scripts\python.exe -m chainofproof normalize credtheft_lateral_v4_clean
.venv\Scripts\python.exe -m chainofproof normalize credtheft_lateral_v4_perturbed
.venv\Scripts\python.exe -m chainofproof events-stats credtheft_lateral_v4_clean
.venv\Scripts\python.exe -m chainofproof events-show credtheft_lateral_v4_clean --host DC-01 --limit 10
.venv\Scripts\python.exe -m chainofproof eval-coverage credtheft_lateral_v4_clean credtheft_lateral_v4_perturbed --baseline-md docs/hayabusa_baseline.md
.venv\Scripts\python.exe -m chainofproof ledger-verify
```

`normalize` first migrates the database to schema version 2 if needed (online backup into `data/db/backups/`, then one transaction). A rerun never deletes anything: it adds a new normalization run and queries use the latest completed run per evidence.

## Tool registry and roles (Phase 4)

`tools/registry.py` registers every agent-facing tool with a pydantic argument model (unknown
arguments are rejected), a returns model, the roles allowed to call it, and a JSON schema
(`export_schemas()`, for Phase 5 tool calling). `call_tool(role, name, args, paths, case_id)` validates
the arguments, enforces the role, bounds the output (items capped at 50, 200 000 characters in total)
and returns a JSON-serializable dict. No LLM is involved.

| tool | what it does | roles |
|---|---|---|
| list_evidence_labels, source_summary | sources and per-source counts | planner, extractor |
| search_events, timeline_window, get_event, get_detections | event queries (get_detections: extractor only) | extractor; search_events/get_event also correlator, skeptic; get_event also reporter; timeline_window also skeptic |
| graph_stats | counts and IP resolution | planner, correlator, skeptic |
| entity_summary, neighbors, find_paths | graph reads | correlator, skeptic |
| host_links | host-to-host links with conn ids | correlator, skeptic, reporter |
| detect_timestomp, detect_clock_skew, detect_log_gap, detect_log_clear, detect_unmatched_connection | one detector each, explicit parameters | correlator, skeptic |
| get_hits | stored hits (latest run per detector) or one by id | planner, correlator, skeptic, reporter |

Detector tools record a run (ledger entry, `detector_runs`, `detector_hits`) but never alter evidence.
Citation ids for later phases: `EVT-<12hex>` for events and `HIT-######` for detector hits.
New CLI: `graph-build`, `graph-show`, `detect`, `detect-all` (humans and eval only), `hits-show`,
`eval-detectors` and `style-audit` (EVAL ONLY).

## Agent scoping (Phase 5, rules A1, A3, A7)

`call_tool(role, name, args, paths, case_id, agent_run_id=None, *, harness=False)` now needs exactly one
of `agent_run_id` (an agent) or `harness=True` (humans, the CLI, the eval harness, tests): a call with
neither, or with both, is refused, so an agent role can never be mistaken for a harness call.

* With an `agent_run_id` the call runs inside `tools/scope.py: agent_scope`: every database connection
  opened in it has a SQLite authorizer that denies reading or writing `event_eval_meta` (rule A7), and
  `get_hits` / the `detect_*` tools see and create only the hits of that agent run.
* Detector runs and hits carry `origin` (`harness` for everything before Phase 5 and for human/eval
  calls, `agent` for agent calls) and `agent_run_id`. Harness readers see only harness runs; an agent sees
  only its own run's hits, so `get_hits` is empty at the start of a run (rule A3). A detector call is
  idempotent per (agent run, detector, params sha): a repeat returns the stored hits.
* The citation verifier resolves HIT ids only inside the citing agent run, so a harness hit id cited by
  an agent is rejected.
* Agents may import neither the registry's implementation modules nor query functions directly: a test
  scans `agents/` and `llm/` for tool-function imports (`call_tool` appears only in `agents/context.py`).

## Typed signatures, lenient filters, templated errors (Phase 5.1)

* `tools/describe.py`: `tool_signature_lines(role)` builds ONE compact line per allowed tool from the
  registry's pydantic parameter models: `name(param?: type[=default], ...): description`, e.g.
  `search_events(host?: str|list[str], event_type?: enum[...]|list[enum[...]], time_from?: ISO-8601 UTC string like 2000-01-01T00:00:00Z, limit?: int<=50 (default 25), ...)`.
  The prompts' TOOLS and WORKERS sections come from it (never hand-written); the example time is
  generic. Agents may read specs; they still call tools only through `agents/context.py`.
* String filters (`host`, `event_type`, `user`, `process_image`, `evidence_label`, `conn_id`; `event_id` as
  int) of `search_events` (and `host` of `timeline_window`, `evidence_label` of `get_detections`) take one
  value or a list of up to 10 values; an empty list is no filter. They are matched with parameterized
  `IN (?,..)` clauses (only the placeholders are string-built). Bounds are unchanged: limit default 25,
  hard maximum 50, `total_matches`, `truncated`. `event_type` is validated against the event-type enum;
  times are ISO-8601 UTC with `Z` and optional fractional seconds (anything else is rejected).
* Argument errors returned to an agent are templated from the validation error: `invalid arguments for
  <tool>: <param> expects <type>; ...` (enum values listed, the ISO example for times, `unknown parameter
  (allowed: ...)`) and never contain the value the model supplied. The same holds for an unknown tool name
  and an unknown graph node id. The agent observation of a failed call also carries the tool's signature line.
* Detector descriptions are generic and factual: what each check does, with its limitation.
