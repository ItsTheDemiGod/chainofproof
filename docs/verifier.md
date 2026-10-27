# Citation verifier (Phase 5)

`agents/verifier.py` + `agents/entities.py`. Deterministic plain code (rule A6): no LLM, no randomness,
no clock. It reads only agent-view data: events of the latest normalization runs of the case, and
detector hits that belong to THIS agent run (`origin='agent'`, `agent_run_id` = the run's hit scope).
It never imports `chainofproof.eval`, scenarios or the eval table (a test pins this).

`verify_finding(paths, case_id, agent_run_id, finding) -> VerificationReport` with
`status` (`verified` | `downgraded` | `rejected`), `checks` (`{check, passed, detail}`), `problems`
(templated strings: a code such as `V3 unsupported_entity` plus ids/field names only; a model-provided
name is echoed only after `safe_name`: letters, digits and `._-\$@:` only, at most 60 characters),
`unsupported_entities` and `counts`. Output order is deterministic.

## Rules

| rule | what is checked | outcome when it fails |
|---|---|---|
| V6 | the finding cites at least one EVT or HIT id | `rejected` (`V6 no_citation`) |
| V1 | every cited EVT id exists in the latest norm runs of THIS case; every cited HIT id exists with origin `agent` and this agent run | `rejected` (`V1 unknown_event/unknown_hit <id>`, `V1 malformed_*_id`) |
| V2 | minimum support by `claim_type`. observation, anomaly, attack_action: at least 1 EVT or HIT. contradiction: at least 1 HIT, or at least 2 EVT from at least 2 different evidence labels. link: `entities.hosts` has at least 2 hosts and the cited material covers each | `rejected` |
| V3 | entity grounding. host = host of a cited event or hit; user (case-insensitive, `DOM\` prefix ignored) in a cited event's `user` or `fields`; process basename in `process_image`, `parent_image`, `target_image`, `service_name` or `fields` (with or without `.exe`); IP in `src_ip`, `dst_ip` or `fields` | `downgraded`, confidence forced to `low`, the exact entities listed (`host:X`, `user:X`, `process:X`, `ip:X`) |
| V4 | `time_start` / `time_end` lie within [min cited time - 60 s, max cited time + 60 s]; hits contribute the ISO times in their measures. An unparsable time or no reference time is a problem too | `downgraded` |
| V5 | claim-text scan (below) | `downgraded` |

Order: V6, V1, V2 can reject (checked in that order, the first failing group ends the check);
V3, V4 and V5 always all run and only downgrade.

### V5: what the claim-text scan extracts

Fixed regexes over the claim text: IPv4 addresses; the virtual host names of this case (every host
with events in the case); `EVT-<12hex>` and `HIT-<6 digits>` ids; ISO timestamps and `HH:MM:SS` times
(a `HH:MM:SS` inside an ISO time is not counted twice); `*.exe` basenames; and, only for
`claim_type = contradiction`, numbers followed by a unit (`s`, `sec(s)`, `second(s)`, `min(s)`,
`minute(s)`, minutes are converted to seconds). Each token must be supported:

* IP and exe: occur as whole tokens in the text of the cited events/hits.
* host: is the host (or `dst_host`) of a cited event, or a host of a cited hit.
* ids: must be among the finding's cited ids.
* times: within 2 s of a cited event time or a time in a cited hit's measures (`HH:MM:SS` compares the
  time of day).
* numbers with a unit: within `max(1 s, 1 percent)` of a numeric measure of a cited hit.

### Limits (honest)

The scan checks only the tokens its regexes can extract; it checks neither meaning nor negation nor
who did what. A claim such as "host A attacked host B" is verified when A and B are named and cited, even
if the cited records do not show an attack. A fabricated fact that avoids all extractable tokens (no
host, IP, id, time, exe or unit number) passes V5. Users and processes are matched by name only, so a
common name can be "supported" by an unrelated cited record. Numbers without a unit are not checked.
Words like "yesterday" are not parsed. The verifier therefore catches invented ids, invented entities and
invented numbers/times, which is the dominant failure of small models; it does not make a claim true.
Semantic review is the skeptic's job (Phase 6) and the manual review of the evaluation (Phase 9).

## Feedback loop

The worker receives the report (templated problems only, never ground-truth information) and may
submit up to `finding_revisions` (2) corrected versions of a downgraded or rejected finding by naming
the run-local id (`revises: F2`). A verified finding cannot be revised. Every version is stored with
its final status and `revised_from`; rejected findings are stored too (they feed the hallucination
count in Phase 9). Prompts show findings as run-local `F<n>` (so replays hash identically); the
database ids are `FND-####`.

## Tests

`tests/test_verifier.py` (rules V1 to V6, boundaries 59 s / 61 s and 1 percent, hostile claim strings,
determinism, foreign cases, harness hits cited by an agent), `tests/test_agent_scope.py`,
`tests/test_agent_runtime.py` (revision flow limited to `finding_revisions`).
