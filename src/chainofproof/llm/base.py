"""LLM client interface and the shared structured-call logic (retry, truncation, recording).

Every client implements ``_raw_call`` (one request, one reply). ``BaseClient.chat`` wraps it with:
schema validation, a bounded retry with a templated message that names only error types and field
names (the model's text is never echoed back and never parsed by regex), truncation detection with
one shrink-and-retry, and a per-call record hook (the run's recorder writes the call file and the
ledger entry; no prompt or response text goes to the ledger or the console).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from pydantic import BaseModel, ValidationError

from chainofproof.custody.hashing import sha256_json, sha256_text
from chainofproof.errors import UserError

log = logging.getLogger(__name__)
TRUNCATION_FRACTION = 0.97
Messages = list[dict[str, str]]


class LLMError(UserError):
    """A failed request (connection, timeout, server error); counted by the run's failure rule."""


class LLMFatal(LLMError):
    """Not retryable: context mismatch, replay divergence, exhausted script."""


@dataclass
class RawReply:
    """What one request returned."""

    text: str
    prompt_tokens: int
    completion_tokens: int
    duration_ms: int


@dataclass
class LLMResult:
    """Outcome of ``chat``: a validated object, or a logged failure (``ok`` False + ``error``)."""

    parsed_json: dict[str, Any] | None
    raw_text: str
    prompt_tokens: int
    completion_tokens: int
    duration_ms: int
    model: str
    num_ctx: int
    truncated_flag: bool = False
    ok: bool = True
    error: str | None = None
    parsed: BaseModel | None = None
    attempts: int = 1
    invalid_count: int = 0
    shrunk: bool = False


@dataclass
class CallRecord:
    """One raw request as stored in ``llm/call_#####.json``."""

    idx: int
    role: str
    model: str
    num_ctx: int
    schema_name: str
    messages: Messages
    response_text: str
    prompt_sha256: str
    response_sha256: str
    prompt_tokens: int
    completion_tokens: int
    duration_ms: int
    status: str  # ok | invalid | truncated | error
    error: str | None = None


class CallRecorder(Protocol):
    """Receives every raw call (the agent run writes the file and the ledger entry)."""

    def record(self, rec: CallRecord) -> None:
        """Store one call."""


@dataclass
class CallCtx:
    """Per-call context: who calls, where to record, how to shrink a too-long prompt."""

    role: str = "system"
    recorder: CallRecorder | None = None
    shrink: Callable[[], Messages | None] | None = None
    events: list[str] = field(default_factory=list)  # truncation / retry flags for the trace


class LLMClient(Protocol):
    """What the agent code needs from a client."""

    model: str
    num_ctx: int

    def chat(
        self,
        messages: Messages,
        schema: type[BaseModel],
        role: str,
        call_ctx: CallCtx | None = None,
    ) -> LLMResult:
        """One structured call (JSON validated against ``schema``)."""


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.]", "", name)[:40] or "?"


def retry_note(err: ValidationError) -> str:
    """Templated retry message: error types and field names only, never the model's text."""
    parts = sorted(
        {f"{_safe('.'.join(str(x) for x in e['loc']) or 'reply')}: {_safe(e['type'])}"
         for e in err.errors()}
    )[:8]  # fmt: skip
    return (
        "Your previous reply was rejected by the schema check (" + "; ".join(parts) + "). "
        "Reply again with exactly one JSON object that matches the schema."
    )


class BaseClient:
    """Shared ``chat`` logic; subclasses implement ``_raw_call``."""

    model: str
    num_ctx: int

    def __init__(self, model: str, num_ctx: int, json_retries: int = 2) -> None:
        self.model, self.num_ctx, self.json_retries = model, num_ctx, json_retries
        self._n = 0  # index of the last raw call (1-based)

    def _raw_call(self, messages: Messages, schema_json: dict, role: str, idx: int) -> RawReply:
        raise NotImplementedError

    def _record(self, ctx: CallCtx | None, rec: CallRecord) -> None:
        if ctx is not None and ctx.recorder is not None:
            ctx.recorder.record(rec)

    def _one(
        self, msgs: Messages, schema: type[BaseModel], sj: dict, role: str, ctx: CallCtx | None
    ):
        """One raw call plus its record; returns (reply or None, status, error)."""
        self._n += 1
        idx, name = self._n, schema.__name__
        try:
            reply = self._raw_call(msgs, sj, role, idx)
        except LLMFatal:
            raise
        except LLMError as e:
            rec = CallRecord(
                idx,
                role,
                self.model,
                self.num_ctx,
                name,
                msgs,
                "",
                sha256_json(msgs),
                sha256_text(""),
                0,
                0,
                0,
                "error",
                str(e)[:200],
            )
            self._record(ctx, rec)
            return None, rec, str(e)
        rec = CallRecord(idx, role, self.model, self.num_ctx, name, msgs, reply.text,
                         sha256_json(msgs), sha256_text(reply.text), reply.prompt_tokens,
                         reply.completion_tokens, reply.duration_ms, "ok")  # fmt: skip
        return reply, rec, None

    def chat(
        self,
        messages: Messages,
        schema: type[BaseModel],
        role: str,
        call_ctx: CallCtx | None = None,
    ) -> LLMResult:
        """Structured call with bounded retry and truncation handling (see module doc)."""
        sj = schema.model_json_schema()
        base, msgs = list(messages), list(messages)
        attempts = invalid = 0
        shrunk = False
        ctx = call_ctx
        while True:
            attempts += 1
            reply, rec, err = self._one(msgs, schema, sj, role, ctx)
            if reply is None:
                return self._fail(err or "error", attempts, invalid, shrunk)
            if reply.prompt_tokens >= TRUNCATION_FRACTION * self.num_ctx:
                rec.status = "truncated"
                self._record(ctx, rec)
                log.warning(
                    "prompt of %d tokens reached num_ctx %d", reply.prompt_tokens, self.num_ctx
                )
                if ctx is not None:
                    ctx.events.append("truncated")
                smaller = ctx.shrink() if (ctx and ctx.shrink and not shrunk) else None
                if smaller is None:
                    return self._fail("context_truncated", attempts, invalid, shrunk, reply, True)
                base = msgs = smaller
                shrunk = True
                continue
            try:
                parsed = schema.model_validate_json(reply.text)
            except ValidationError as e:
                invalid += 1
                rec.status, rec.error = "invalid", retry_note(e)[:200]
                self._record(ctx, rec)
                if ctx is not None:
                    ctx.events.append("invalid_json")
                if invalid > self.json_retries:
                    return self._fail("invalid_output", attempts, invalid, shrunk, reply)
                msgs = [*base, {"role": "user", "content": retry_note(e)}]
                continue
            self._record(ctx, rec)
            return LLMResult(parsed.model_dump(mode="json"), reply.text, reply.prompt_tokens,
                             reply.completion_tokens, reply.duration_ms, self.model, self.num_ctx,
                             False, True, None, parsed, attempts, invalid, shrunk)  # fmt: skip

    def _fail(self, error: str, attempts: int, invalid: int, shrunk: bool,
              reply: RawReply | None = None, truncated: bool = False) -> LLMResult:  # fmt: skip
        r = reply or RawReply("", 0, 0, 0)
        log.warning("llm call failed: %s after %d attempt(s)", error[:80], attempts)
        return LLMResult(None, r.text, r.prompt_tokens, r.completion_tokens, r.duration_ms,
                         self.model, self.num_ctx, truncated, False, error, None, attempts,
                         invalid, shrunk)  # fmt: skip
