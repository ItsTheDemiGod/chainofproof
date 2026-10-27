# Detectors (Phase 4)

Five separate tools in `tools/detectors/`. Each is a pure function `detector(events, params) ->
list[Hit]` over agent-view events (sorted by timestamp, label, record id), plus a runner
(`run_detector`) that loads the latest normalized events of a case, stores a `detector_runs` row and
the hits (`HIT-######`), and ledger-logs the call. They are **separate on purpose**: nothing runs
them automatically (rule D2). A later agent has to decide to call each one; "run all" exists only in
the eval harness and the `detect-all` CLI command. That keeps a clean no-LLM baseline possible.

A hit carries: `event_uids` (citable), `measures` (numbers and structured values), a templated
`explanation` (fixed text over structured fields, never copied free text), `limitations` (what the
hit cannot show), `severity`, and `hit_key` = sha256 of canonical JSON of (detector, kind, sorted
uids, measures), so the same data always yields the same keys.

## Parameters (config/settings.yaml, section `detectors`; fixed before the first run, never tuned)

| parameter | default | rationale |
|---|---|---|
| timestomp.min_delta_seconds | 3600 | ordinary si/fn jitter is seconds; one hour is far beyond it |
| clock_skew.min_abs_delta_seconds | 2.0 | the sources have 1 s resolution; under 2 s is rounding noise |
| clock_skew.min_independent_pairs | 2 | one pair can be a coincidence; two agreeing pairs are a pattern |
| clock_skew.agreement_seconds | 1.0 | pairs agree when they differ by at most the 1 s resolution |
| clock_skew.pair_window_seconds | 900 | pipe-name pairs only (Phase 4.1 guard): typical clock errors are well below 15 minutes |
| log_gap.max_other_events_listed | 10 | listing cap only, not a detection threshold |
| log_clear.window_seconds | 60 | "immediately after": one minute of follow-on activity |

## The detectors

* **timestomp** (`si_fn_mismatch`): for file-timeline rows, compares each `si_*` time with its `fn_*`
  counterpart; hit when any pair differs by at least `min_delta_seconds`. Measures: file basename,
  host, record id, max delta, which pairs differ, direction. Compares only the two timestamp sets
  inside one record; it makes no cross-source claim.
* **clock_skew** (`source_offset`, `pair_time_offset`): pairs are found from SHARED FIELDS only: the
  same `conn_id` or the same pipe name (leading backslashes ignored, case-insensitive) in events of
  different sources, on timestamps truncated to whole seconds (the coarsest source has 1 s
  resolution). For a `conn_id` (unique per connection) the closest events are used. **Pairing guard
  for pipe names (Phase 4.1):** realistic benign data repeats ordinary pipe names (`spoolss`,
  `srvsvc`...) all day on every host, which would pair unrelated events. Pipe pairs must therefore
  be on the SAME virtual host, at most `pair_window_seconds` apart, and are matched one-to-one by
  nearest time (an event is in at most one pair). This guard was added to prevent spurious pairs; it
  was not measured on the unguarded code, and it is not a threshold tuned for a score: `min_abs_delta_seconds`, `min_independent_pairs`
  and `agreement_seconds` were NOT changed, and `conn_id` pairing is untouched. A source is reported as
  consistently late/early when at least 2 pairs agree within 1 s and they involve 2+ partner sources
  or 2+ shared keys. A wrong clock is wrong against every partner while the partner only mirrors it,
  so candidates are ranked by number of partners, then pairs, and a candidate whose pairs a better
  one already explains is dropped (noted as `ambiguous_with` when it ranked equally). Single pairs no
  offset explains are low-severity `pair_time_offset` hits.
* **log_gap** (`sequence_gap`): in sequence-numbered auth logs, every interior jump in `seq`: missing
  range, last time before and first time after, interval seconds, and the events from OTHER sources
  on the same virtual host inside the interval (counts per source and type, up to 10 uids). Not
  applied to file-timeline record ids (they may legitimately skip). A gap at the very start or end of
  a log cannot be seen.
* **log_clear** (`audit_log_cleared`): Security 1102 / System 104 events, plus the logon/process
  events on the same host within `window_seconds` after them.
* **unmatched_connection** (`missing_counterpart`): a `conn_id` with only a source end (`CONN_OUT`) or
  only a destination end (`CONN_ACCEPTED` / `LOGON_SUCCESS`). If the host that should hold the
  missing end has a `sequence_gap` whose interval contains the present end's time, that gap's
  `hit_key` is named as a possible explanation (generic rule). With benign connection pairs in the
  data (v4), the same rule also reports every benign connection whose other end fell into a log gap
  (collateral of the gap, each naming the gap hit); the evaluation lists these as "explained
  collateral".

## Severity table (fixed)

| detector / kind | severity |
|---|---|
| timestomp: si earlier than fn by >= 1 day | high |
| timestomp: any other direction or smaller delta | medium |
| clock_skew source_offset: offset >= 60 s and >= 3 pairs | high |
| clock_skew source_offset: otherwise | medium |
| clock_skew pair_time_offset | low |
| log_gap: other-source events inside the interval | high |
| log_gap: none inside | medium |
| log_clear | medium |
| unmatched_connection: unexplained | medium |
| unmatched_connection: explained by a gap hit | low |

## Limitations (also stored in every hit)

* timestomp: a mismatch can occur through legitimate moves or restores; intent is not shown.
* clock_skew: cannot tell which of two clocks is wrong; relies on identifiers present in both sources.
* log_gap: shows lines are missing, not who removed them or why.
* log_clear: a cleared log can be routine administration or lab preparation.
* unmatched_connection: absence of a line does not prove the connection did not happen.
