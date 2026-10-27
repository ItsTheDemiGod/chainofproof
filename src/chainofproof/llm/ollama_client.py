"""Ollama client (the ``ollama`` Python package; it is already a project dependency).

``num_ctx`` is ALWAYS sent (the server default is 4096). After the first successful reply the
client asks ``/api/ps`` for the loaded context length; when the server exposes it and it differs
from ``num_ctx`` the call fails loudly (``LLMFatal``); when it is not exposed, that is logged once.
The transport is injectable so tests need no server.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

import httpx
import ollama

from chainofproof.llm.base import BaseClient, LLMError, LLMFatal, Messages, RawReply

log = logging.getLogger(__name__)
Transport = Callable[[dict[str, Any]], dict[str, Any]]


def _dump(obj: Any) -> dict[str, Any]:
    return obj.model_dump() if hasattr(obj, "model_dump") else dict(obj)


class OllamaClient(BaseClient):
    """Chat with a local Ollama server using JSON-schema constrained output."""

    def __init__(
        self, host: str, model: str, num_ctx: int, seed: int, temperature: float = 0,
        num_predict: int = 700, keep_alive: str = "10m", json_retries: int = 2,
        timeout: float = 300, transport: Transport | None = None,
        ps: Callable[[], dict[str, Any]] | None = None,
    ) -> None:  # fmt: skip
        super().__init__(model, num_ctx, json_retries)
        self.host, self.seed, self.temperature = host, seed, temperature
        self.num_predict, self.keep_alive, self.timeout = num_predict, keep_alive, timeout
        self._client = ollama.Client(host=host, timeout=timeout)
        self._transport = transport or (lambda req: _dump(self._client.chat(**req)))
        self._ps = ps or (lambda: _dump(self._client.ps()))
        self.loaded_ctx: int | None = None
        self.loaded_ctx_checked = False

    def request(self, messages: Messages, schema_json: dict) -> dict[str, Any]:
        """The request sent to the server (``num_ctx`` always included)."""
        return {
            "model": self.model, "messages": messages, "format": schema_json, "stream": False,
            "keep_alive": self.keep_alive,
            "options": {"num_ctx": self.num_ctx, "temperature": self.temperature,
                        "seed": self.seed, "num_predict": self.num_predict},
        }  # fmt: skip

    def _raw_call(self, messages: Messages, schema_json: dict, role: str, idx: int) -> RawReply:
        t0 = time.perf_counter()
        try:
            resp = self._transport(self.request(messages, schema_json))
        except httpx.TimeoutException:
            raise LLMError(f"Ollama request timed out after {self.timeout:g}s") from None
        except (httpx.TransportError, ConnectionError):
            raise LLMError(f"cannot reach Ollama at {self.host}") from None
        except ollama.ResponseError as e:
            raise LLMError(f"Ollama returned an error (status {e.status_code})") from None
        ms = round((time.perf_counter() - t0) * 1000)
        reply = RawReply(
            (resp.get("message") or {}).get("content") or "",
            int(resp.get("prompt_eval_count") or 0), int(resp.get("eval_count") or 0), ms,
        )  # fmt: skip
        if not self.loaded_ctx_checked:
            self.check_loaded_context()
        return reply

    def check_loaded_context(self) -> int | None:
        """Compare the server's loaded context length with ``num_ctx`` (once per client)."""
        self.loaded_ctx_checked = True
        try:
            models = _dump(self._ps()).get("models") or []
        except Exception as e:  # noqa: BLE001 - /api/ps is advisory
            log.warning("could not query /api/ps: %s", type(e).__name__)
            return None
        for m in models:
            m = _dump(m)
            if m.get("model") == self.model or m.get("name") == self.model:
                self.loaded_ctx = m.get("context_length")
        if self.loaded_ctx is None:
            log.info("Ollama does not expose the loaded context length; num_ctx %d is sent "
                     "with every request", self.num_ctx)  # fmt: skip
        else:
            log.info("loaded context length %d (num_ctx %d)", self.loaded_ctx, self.num_ctx)
            if self.loaded_ctx != self.num_ctx:
                raise LLMFatal(
                    f"Ollama loaded context {self.loaded_ctx} differs from num_ctx {self.num_ctx}"
                )
        return self.loaded_ctx
