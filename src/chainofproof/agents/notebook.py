"""The planner's notebook: hypotheses, open questions, verified findings, survey, known events.

It is serialized compactly into every prompt (about 1200 tokens) as ONE data block, because its
text comes from evidence and from models that read evidence (rule A4). Known events are capped
(oldest dropped from the notebook; an id that fell out can still be cited, citations are checked
against the database, not against the notebook). Saved to the run folder after every round.
"""

from __future__ import annotations

import json
from collections import OrderedDict
from pathlib import Path
from typing import Any

from chainofproof.agents.observe import event_summary, short, wrap
from chainofproof.custody.hashing import canonical_json
from chainofproof.llm.budget import estimate_tokens
from chainofproof.schemas.agent import NotebookUpdate

NOTEBOOK_TOKENS = 1200
TEXT_MAX = 160
SURVEY_CHARS = 1800


class Notebook:
    """State the planner keeps between rounds."""

    def __init__(self, known_events_cap: int = 60) -> None:
        self.cap = known_events_cap
        self.hypotheses: OrderedDict[str, dict[str, str]] = OrderedDict()
        self.questions: list[str] = []
        self.findings: list[tuple[str, str]] = []  # (run-local id, one-line claim)
        self.survey: list[str] = []
        self.known: OrderedDict[str, str] = OrderedDict()
        self.dropped_updates = 0
        self.counters: dict[str, int] = {}

    def apply(self, upd: NotebookUpdate | None) -> None:
        """Apply a planner update; updates naming an unknown hypothesis are counted and ignored."""
        if upd is None:
            return
        for text in upd.new_hypotheses:
            self.hypotheses[f"H{len(self.hypotheses) + 1}"] = {
                "text": short(text, TEXT_MAX), "status": "open", "note": ""}  # fmt: skip
        for u in upd.hypothesis_updates:
            if u.id in self.hypotheses:
                self.hypotheses[u.id].update(status=u.status, note=short(u.note, 120))
            else:
                self.dropped_updates += 1
        self.questions = [*self.questions, *(short(q, TEXT_MAX) for q in upd.new_questions)][-8:]

    def add_finding(self, local_id: str, claim: str) -> None:
        """A verified finding (fed back to the planner)."""
        self.findings.append((local_id, short(claim, TEXT_MAX)))

    def add_events(self, events: list[dict[str, Any]]) -> int:
        """Remember events (uid -> summary); returns how many uids were new."""
        new = 0
        for e in events:
            uid = e["event_uid"]
            new += uid not in self.known
            self.known[uid] = event_summary(e)
            self.known.move_to_end(uid)
        while len(self.known) > self.cap:
            self.known.popitem(last=False)
        return new

    def set_survey(self, lines: list[str]) -> None:
        """Compact survey lines (one per source plus graph counts), capped in total size."""
        out, used = [], 0
        for ln in lines:
            if used + len(ln) > SURVEY_CHARS:
                break
            out.append(ln)
            used += len(ln)
        self.survey = out

    def render_text(self, token_budget: int = NOTEBOOK_TOKENS) -> str:
        """Plain text of the notebook; known events fill whatever budget is left (newest first)."""
        parts = ["SURVEY:", *self.survey]
        parts += ["HYPOTHESES:", *(
            f"{k} [{v['status']}] {v['text']}" + (f" ({v['note']})" if v["note"] else "")
            for k, v in self.hypotheses.items()
        )]  # fmt: skip
        parts += ["OPEN QUESTIONS:", *(f"Q{i + 1} {q}" for i, q in enumerate(self.questions))]
        parts += ["VERIFIED FINDINGS:", *(f"{i}: {c}" for i, c in self.findings)]
        left = token_budget - estimate_tokens("\n".join(parts)) - 20
        kept: list[str] = []
        for uid, summ in reversed(self.known.items()):
            ln = f"{uid} {summ}"
            if estimate_tokens(ln) > left:
                break
            kept.append(ln)
            left -= estimate_tokens(ln)
        parts += ["KNOWN EVENTS (recent, citable):", *reversed(kept)]
        return "\n".join(parts)

    def render_block(self, block_id: str) -> tuple[str, int]:
        """The notebook as one DATA block, and the number of delimiter escapes it needed."""
        return wrap(self.render_text(), block_id, "notebook")

    def save(self, path: Path) -> None:
        """Write the notebook to the run folder (canonical JSON)."""
        d = {"hypotheses": self.hypotheses, "questions": self.questions, "findings": self.findings,
             "survey": self.survey, "known_events": dict(self.known), "counters": self.counters,
             "dropped_updates": self.dropped_updates}  # fmt: skip
        Path(path).write_text(json.dumps(json.loads(canonical_json(d)), indent=1), encoding="utf-8")
