"""Database access of the agent runtime: agent_runs, agent_calls and findings (insert-only rows).

Every statement is parameterized; nothing is ever deleted. Finding ids (FND-####) are allocated
here, in the transaction that stores the finding: the model never invents them.
"""

from __future__ import annotations

import json
from contextlib import closing
from typing import Any

from chainofproof.config import Paths
from chainofproof.custody.db import connect
from chainofproof.custody.hashing import canonical_json, iso_utc, utc_now
from chainofproof.errors import UserError
from chainofproof.schemas.findings import Finding, FindingInput, FindingStatus, VerificationReport


class AgentStoreError(UserError):
    """Unknown run or finding."""


def insert_run(paths: Paths, row: dict[str, Any]) -> None:
    """Create the ``agent_runs`` row (status running)."""
    cols = ",".join(row)
    with closing(connect(paths.db_path)) as conn:
        conn.execute(
            f"INSERT INTO agent_runs({cols}) VALUES ({','.join('?' * len(row))})",  # noqa: S608
            list(row.values()),
        )


def finish_run(paths: Paths, run_id: str, **fields: Any) -> None:
    """Update the final fields of a run (status, stop_reason, counters, trace hash)."""
    sets = ",".join(f"{k} = ?" for k in fields)
    with closing(connect(paths.db_path)) as conn:
        conn.execute(
            f"UPDATE agent_runs SET {sets} WHERE run_id = ?",  # noqa: S608
            [*fields.values(), run_id],
        )


def get_run(paths: Paths, run_id: str) -> dict[str, Any]:
    """One agent run row as a dict; raises AgentStoreError when unknown."""
    with closing(connect(paths.db_path)) as conn:
        r = conn.execute("SELECT * FROM agent_runs WHERE run_id = ?", (run_id,)).fetchone()
    if r is None:
        raise AgentStoreError(f"unknown agent run {run_id!r}")
    return dict(r)


def list_runs(paths: Paths, case_id: str | None = None) -> list[dict[str, Any]]:
    """Agent runs, oldest first, optionally of one case."""
    sql, args = "SELECT * FROM agent_runs", []
    if case_id:
        sql, args = sql + " WHERE case_id = ?", [case_id]
    with closing(connect(paths.db_path)) as conn:
        return [dict(r) for r in conn.execute(sql + " ORDER BY run_id", args)]


def insert_call(paths: Paths, run_id: str, idx: int, kind: str, role: str, name: str,
                **f: Any) -> None:  # fmt: skip
    """One row per LLM call or tool call of a run."""
    with closing(connect(paths.db_path)) as conn:
        conn.execute(
            "INSERT INTO agent_calls(run_id, call_idx, kind, role, name, input_sha256, "
            "output_sha256, prompt_tokens, completion_tokens, duration_ms, ledger_id, status) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, idx, kind, role, name, f.get("input_sha256"), f.get("output_sha256"),
             f.get("prompt_tokens"), f.get("completion_tokens"), f.get("duration_ms"),
             f.get("ledger_id"), f.get("status", "ok")),
        )  # fmt: skip


def add_finding(
    paths: Paths, run_id: str, case_id: str, role: str, fi: FindingInput,
    status: FindingStatus, report: VerificationReport, revised_from: str | None = None,
) -> Finding:  # fmt: skip
    """Store a finding (any status) and return it with its newly allocated FND id."""
    now = iso_utc(utc_now())
    with closing(connect(paths.db_path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            n = (
                conn.execute(
                    "SELECT MAX(CAST(SUBSTR(finding_id, 5) AS INTEGER)) FROM findings"
                ).fetchone()[0]
                or 0
            )
            fid = f"FND-{n + 1:04d}"
            conn.execute(
                "INSERT INTO findings(finding_id, run_id, case_id, worker_role, claim, claim_type, "
                "entities_json, cited_event_uids_json, cited_hit_ids_json, confidence, needs_json, "
                "status, verification_json, revised_from, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (fid, run_id, case_id, role, fi.claim, fi.claim_type,
                 canonical_json(fi.entities.model_dump()), json.dumps(fi.cited_event_uids),
                 json.dumps(fi.cited_hit_ids), fi.confidence, json.dumps(fi.needs), status,
                 canonical_json(report.model_dump()), revised_from, now),
            )  # fmt: skip
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")
    return Finding(**fi.model_dump(), finding_id=fid, run_id=run_id, case_id=case_id,
                   worker_role=role, status=status, verification=report,  # type: ignore[arg-type]
                   revised_from=revised_from, created_at=now)  # fmt: skip


def _finding(r: Any) -> Finding:
    return Finding(
        finding_id=r["finding_id"], run_id=r["run_id"], case_id=r["case_id"],
        worker_role=r["worker_role"], claim=r["claim"], claim_type=r["claim_type"],
        entities=json.loads(r["entities_json"]), confidence=r["confidence"],
        cited_event_uids=json.loads(r["cited_event_uids_json"]),
        cited_hit_ids=json.loads(r["cited_hit_ids_json"]), needs=json.loads(r["needs_json"]),
        status=r["status"], verification=json.loads(r["verification_json"]),
        revised_from=r["revised_from"], created_at=r["created_at"],
    )  # fmt: skip


def list_findings(paths: Paths, run_id: str, status: str | None = None) -> list[Finding]:
    """Findings of a run in id order, optionally of one status."""
    sql, args = "SELECT * FROM findings WHERE run_id = ?", [run_id]
    if status:
        sql, args = sql + " AND status = ?", [run_id, status]
    with closing(connect(paths.db_path)) as conn:
        return [_finding(r) for r in conn.execute(sql + " ORDER BY finding_id", args)]


def root_run(paths: Paths, run_id: str) -> str:
    """The original run behind a chain of replays (the run itself when it is no replay)."""
    seen = set()
    while run_id not in seen:
        seen.add(run_id)
        parent = get_run(paths, run_id).get("replay_of")
        if not parent:
            break
        run_id = parent
    return run_id
