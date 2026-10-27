"""Token estimate and the prompt builder that enforces the context budget.

The estimate is deliberately conservative (characters / 3). The builder never trims the system
prompt, the schema instructions or the notebook core; it trims, oldest first, tool observations
(replaced by a one-line elision that keeps their EVT/HIT ids) and then worker reports. If that is
not enough, ``PromptTooLarge`` is raised: the prompt is never silently cut.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from chainofproof.errors import UserError

ELIDE_IDS_MAX = 12


class PromptTooLarge(UserError):
    """Even with every block elided the prompt exceeds the budget."""


def estimate_tokens(text: str) -> int:
    """Conservative token estimate: characters / 3, rounded up."""
    return math.ceil(len(text) / 3)


def prompt_budget(num_ctx: int, num_predict: int, fraction: float) -> int:
    """Largest prompt (in estimated tokens) allowed: fraction of the room left for the prompt."""
    return int(fraction * (num_ctx - num_predict))


@dataclass
class Block:
    """A trimmable piece of the prompt: an observation (``obs``) or a worker report (``report``)."""

    kind: str
    block_id: str
    source: str
    text: str  # already wrapped in a DATA block
    ids: list[str] = field(default_factory=list)  # EVT/HIT ids it shows (kept when elided)

    def elision(self) -> str:
        """One line that replaces the block; only ids, never content."""
        shown = " ".join(self.ids[:ELIDE_IDS_MAX])
        more = f" (+{len(self.ids) - ELIDE_IDS_MAX} more)" if len(self.ids) > ELIDE_IDS_MAX else ""
        return f"[elided {self.block_id} source={self.source}; ids: {shown or 'none'}{more}]"


@dataclass
class BuildInfo:
    """What the builder did (goes to the trace)."""

    est_tokens: int
    budget: int
    elided: list[str]


class PromptBuilder:
    """Assemble ``[system, user]`` messages inside the budget."""

    def __init__(self, system: str, num_ctx: int, num_predict: int, fraction: float) -> None:
        self.system = system
        self.budget = prompt_budget(num_ctx, num_predict, fraction)

    def build(
        self, core: str, blocks: list[Block], tail: str, scale: float = 1.0
    ) -> tuple[list[dict[str, str]], BuildInfo]:
        """Messages for one call. ``scale`` < 1 tightens the budget (used after a truncation)."""
        budget = int(self.budget * scale)
        fixed = estimate_tokens(self.system) + estimate_tokens(core) + estimate_tokens(tail)
        texts = [b.text for b in blocks]
        total = fixed + sum(estimate_tokens(t) for t in texts)
        elided: list[str] = []
        for kind in ("obs", "report"):
            for i, b in enumerate(blocks):
                if total <= budget:
                    break
                if b.kind == kind and texts[i] is b.text:
                    short = b.elision()
                    total += estimate_tokens(short) - estimate_tokens(b.text)
                    texts[i] = short
                    elided.append(b.block_id)
        if total > budget:
            raise PromptTooLarge(f"prompt of about {total} tokens exceeds the budget of {budget}")
        user = "\n\n".join([core, *texts, tail])
        msgs = [{"role": "system", "content": self.system}, {"role": "user", "content": user}]
        return msgs, BuildInfo(total, budget, elided)
