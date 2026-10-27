"""Model-facing action schemas (flat and small: constrained decoding works best on those).

The model never invents ids for findings: the system assigns them. Tool arguments are validated
afterwards with the per-tool pydantic model from the registry.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, model_validator

from chainofproof.schemas.findings import (
    CLAIM_MAX,
    NEEDS_MAX,
    ClaimType,
    Confidence,
    Entities,
    FindingInput,
    Strict,
)

RATIONALE_MAX = 240  # = settings.agent.rationale_max_chars default
HANDOFF_MAX = 300  # = settings.agent.handoff_max_chars default
TASK_MAX = 300
MAX_CITED = 8  # per list; long id lists hit the num_predict cap (prompt v3, changelog)
ID_MAX = 20


class HypothesisUpdate(Strict):
    """Change of status of an existing hypothesis (H1, H2, ...)."""

    id: str = Field(max_length=20)  # like H1; an unknown id is ignored and counted, not an error
    status: Literal["open", "supported", "refuted"]
    note: str = Field(default="", max_length=120)


class NotebookUpdate(Strict):
    """What the planner adds to its notebook this round."""

    new_hypotheses: list[str] = Field(default_factory=list, max_length=3)
    hypothesis_updates: list[HypothesisUpdate] = Field(default_factory=list, max_length=5)
    new_questions: list[str] = Field(default_factory=list, max_length=3)


class PlannerAction(Strict):
    """One planner reply: delegate a task to a worker, or finish the investigation."""

    rationale: str = Field(max_length=RATIONALE_MAX)
    action: Literal["delegate", "finish"]
    worker_role: Literal["extractor", "correlator"] | None = None
    task: str | None = Field(default=None, max_length=TASK_MAX)
    focus_labels: list[str] | None = Field(default=None, max_length=5)
    notebook: NotebookUpdate | None = None
    finish_reason: str | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def _coherent(self) -> PlannerAction:
        if self.action == "delegate" and not (self.worker_role and (self.task or "").strip()):
            raise ValueError("delegate needs worker_role and task")
        return self


class FindingDraft(Strict):
    """A finding as the model writes it (flat); the system turns it into a stored Finding."""

    claim: str = Field(min_length=1, max_length=CLAIM_MAX)
    claim_type: ClaimType
    hosts: list[str] = Field(default_factory=list, max_length=8)
    users: list[str] = Field(default_factory=list, max_length=8)
    processes: list[str] = Field(default_factory=list, max_length=8)
    ips: list[str] = Field(default_factory=list, max_length=8)
    time_start: str | None = None
    time_end: str | None = None
    cited_event_uids: list[str] = Field(default_factory=list, max_length=MAX_CITED)
    cited_hit_ids: list[str] = Field(default_factory=list, max_length=MAX_CITED)
    confidence: Confidence = "low"
    needs: list[str] = Field(default_factory=list, max_length=NEEDS_MAX)
    revises: str | None = Field(default=None, max_length=ID_MAX)  # run-local id, e.g. F2

    def to_input(self) -> FindingInput:
        """The checkable content (entities nested)."""
        d = self.model_dump()
        ent = {
            k: d.pop(k) for k in ("hosts", "users", "processes", "ips", "time_start", "time_end")
        }
        d.pop("revises")
        return FindingInput(**d, entities=Entities(**ent))


class WorkerAction(Strict):
    """One worker reply: call a tool, record a finding, or finish with a handoff note."""

    rationale: str = Field(max_length=RATIONALE_MAX)
    action: Literal["call_tool", "record_finding", "finish"]
    tool: str | None = Field(default=None, max_length=40)
    args: dict[str, Any] | None = None
    finding: FindingDraft | None = None
    handoff: str | None = Field(default=None, max_length=HANDOFF_MAX)

    @model_validator(mode="after")
    def _coherent(self) -> WorkerAction:
        if self.action == "call_tool" and not self.tool:
            raise ValueError("call_tool needs tool")
        if self.action == "record_finding" and self.finding is None:
            raise ValueError("record_finding needs finding")
        return self
