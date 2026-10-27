"""Agent scope of a tool call: which agent run a call belongs to (rules A3 and A7).

``agent_scope(run_id)`` is entered by ``registry.call_tool`` for agent calls. Inside it every
database connection is restricted (no eval tables) and detector tools read and write only the hits
of that agent run.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from chainofproof.custody.db import restricted_reads

_RUN: ContextVar[str | None] = ContextVar("cop_agent_run", default=None)


def current_agent_run() -> str | None:
    """The agent run id of the enclosing ``agent_scope``, or None for harness/human calls."""
    return _RUN.get()


@contextmanager
def agent_scope(agent_run_id: str) -> Iterator[None]:
    """Mark the enclosed tool calls as belonging to ``agent_run_id`` with restricted DB reads."""
    token = _RUN.set(agent_run_id)
    try:
        with restricted_reads():
            yield
    finally:
        _RUN.reset(token)
