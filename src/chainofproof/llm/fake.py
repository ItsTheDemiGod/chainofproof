"""Scripted LLM client for tests and demos (``--llm fake:PATH``). No network, fully deterministic.

A script is a list of entries: a dict or list (sent as JSON), a string (sent as is, so it may be
invalid JSON), a ``FakeReply`` (explicit token counts, simulated slowness, errors) or a callable
``(messages, role) -> entry``. Running out of script is a fatal error.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from chainofproof.llm.base import BaseClient, LLMError, LLMFatal, Messages, RawReply
from chainofproof.llm.budget import estimate_tokens


class FakeClock:
    """A clock tests can advance (``FakeReply.advance_s`` simulates a slow call)."""

    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        """Move time forward."""
        self.t += seconds


@dataclass
class FakeReply:
    """One scripted reply with optional overrides."""

    text: str | dict | list
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    duration_ms: int = 1
    advance_s: float = 0.0
    error: str | None = None  # raise LLMError with this text
    fatal: bool = False


Entry = Any  # dict | list | str | FakeReply | Callable[[Messages, str], Entry]


class FakeLLMClient(BaseClient):
    """Plays back a script; remembers every request in ``requests``."""

    def __init__(
        self, script: list[Entry], model: str = "fake-model", num_ctx: int = 8192,
        json_retries: int = 2, clock: FakeClock | None = None,
    ) -> None:  # fmt: skip
        super().__init__(model, num_ctx, json_retries)
        self.script, self.clock = list(script), clock
        self.requests: list[dict[str, Any]] = []

    @classmethod
    def from_file(cls, path: Path, **kw: Any) -> FakeLLMClient:
        """Script from a JSON file holding a list of entries."""
        return cls(json.loads(Path(path).read_text(encoding="utf-8")), **kw)

    def _raw_call(self, messages: Messages, schema_json: dict, role: str, idx: int) -> RawReply:
        self.requests.append({"messages": messages, "role": role, "schema": schema_json})
        if not self.script:
            raise LLMFatal("fake script exhausted")
        entry = self.script.pop(0)
        if callable(entry):
            entry = entry(messages, role)
        r = entry if isinstance(entry, FakeReply) else FakeReply(entry)
        if r.advance_s and self.clock is not None:
            self.clock.advance(r.advance_s)
        if r.fatal:
            raise LLMFatal(r.error or "fake fatal error")
        if r.error:
            raise LLMError(r.error)
        text = r.text if isinstance(r.text, str) else json.dumps(r.text)
        pt = (
            r.prompt_tokens
            if r.prompt_tokens is not None
            else sum(estimate_tokens(m["content"]) for m in messages)
        )
        ct = r.completion_tokens if r.completion_tokens is not None else estimate_tokens(text)
        return RawReply(text, pt, ct, r.duration_ms)


FakeFactory = Callable[[], FakeLLMClient]
