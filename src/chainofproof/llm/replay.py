"""Replay a recorded run: serves the stored replies in order and refuses to diverge.

Call ``i`` of the replay must have the same ``prompt_sha256`` as call ``i`` of the recording (the
retry messages and shrunk prompts are part of the prompt), otherwise ``LLMFatal('replay diverged
at call i')``. Only the LLM is non-deterministic; tools, verifier and orchestration are replayed
for real, so any change in them shows up as a divergence.
"""

from __future__ import annotations

import json
from pathlib import Path

from chainofproof.custody.hashing import sha256_json
from chainofproof.llm.base import BaseClient, LLMError, LLMFatal, Messages, RawReply


class ReplayLLMClient(BaseClient):
    """Reads ``call_#####.json`` files of a recorded run folder."""

    def __init__(self, run_dir: Path, model: str, num_ctx: int, json_retries: int = 2) -> None:
        super().__init__(model, num_ctx, json_retries)
        self.dir = Path(run_dir) / "llm"

    def _raw_call(self, messages: Messages, schema_json: dict, role: str, idx: int) -> RawReply:
        f = self.dir / f"call_{idx:05d}.json"
        if not f.is_file():
            raise LLMFatal(f"replay diverged at call {idx}: no recorded call")
        rec = json.loads(f.read_text(encoding="utf-8"))
        if rec["prompt_sha256"] != sha256_json(messages) or rec["role"] != role:
            raise LLMFatal(f"replay diverged at call {idx}: prompt differs from the recording")
        if rec["status"] == "error":
            raise LLMError(rec.get("error") or "recorded error")
        return RawReply(rec["response_text"], rec["prompt_tokens"], rec["completion_tokens"],
                        rec["duration_ms"])  # fmt: skip
