"""LLM client: options, retry, truncation, recording, errors, replay (fake transport only)."""

import json
import logging
import math

import httpx
import pytest
from pydantic import BaseModel

from chainofproof.custody.ledger import Ledger
from chainofproof.llm.base import CallCtx, CallRecord, LLMFatal
from chainofproof.llm.budget import Block, PromptBuilder, PromptTooLarge, estimate_tokens
from chainofproof.llm.fake import FakeLLMClient, FakeReply
from chainofproof.llm.ollama_client import OllamaClient
from chainofproof.llm.replay import ReplayLLMClient


class Out(BaseModel):
    """Tiny schema."""

    answer: str
    n: int = 0


MSGS = [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}]


class Rec:
    """Recorder that keeps the records in memory."""

    def __init__(self):
        self.calls: list[CallRecord] = []

    def record(self, rec):
        self.calls.append(rec)


def reply(text, pt=10, ct=5):
    return {"message": {"content": text}, "prompt_eval_count": pt, "eval_count": ct}


def ollama(transport, ps=None, **kw):
    return OllamaClient("http://x", "m", 8192, 42, transport=transport,
                        ps=ps or (lambda: {"models": []}), **kw)  # fmt: skip


def test_every_request_sends_num_ctx_and_the_json_schema():
    seen = []

    def transport(req):
        seen.append(req)
        return reply('{"answer":"a"}')

    c = ollama(transport, num_predict=123, keep_alive="5m")
    res = c.chat(MSGS, Out, "planner")
    o = seen[0]["options"]
    assert res.ok and res.parsed.answer == "a" and res.parsed_json == {"answer": "a", "n": 0}
    assert o == {"num_ctx": 8192, "temperature": 0, "seed": 42, "num_predict": 123}
    assert seen[0]["format"]["properties"]["answer"] and seen[0]["keep_alive"] == "5m"
    assert seen[0]["model"] == "m" and seen[0]["stream"] is False


def test_invalid_json_is_retried_with_a_templated_message_and_never_salvaged():
    texts = ['garbage {"answer": "x"} garbage', '{"answer": 5}', '{"answer":"ok"}']
    seen = []

    def transport(req):
        seen.append(req["messages"])
        return reply(texts.pop(0))

    res = ollama(transport, json_retries=2).chat(MSGS, Out, "worker")
    assert res.ok and res.attempts == 3 and res.invalid_count == 2
    note = seen[2][-1]["content"]
    assert "answer: string_type" in note and "garbage" not in note and "reply" in note
    assert "json_invalid" in seen[1][-1]["content"]  # first retry: invalid json, no text echoed


def test_retries_exhausted_returns_a_logged_failure_not_a_fallback(caplog):
    c = FakeLLMClient(["{bad", "{bad", "{bad", "{"], json_retries=2)
    rec = Rec()
    with caplog.at_level(logging.WARNING):
        res = c.chat(MSGS, Out, "p", CallCtx("p", rec))
    assert not res.ok and res.error == "invalid_output" and res.parsed is None
    assert res.attempts == 3 and [r.status for r in rec.calls] == ["invalid"] * 3
    assert "{bad" not in caplog.text


def test_truncation_is_detected_shrunk_and_retried_once():
    big = FakeReply({"answer": "a"}, prompt_tokens=math.ceil(0.97 * 8192))
    ok = FakeReply({"answer": "b"}, prompt_tokens=3000)
    c = FakeLLMClient([big, ok])
    shrunk = []

    def shrink():
        shrunk.append(1)
        return [{"role": "user", "content": "smaller"}]

    ctx, rec = CallCtx("w", Rec(), shrink), None
    ctx.recorder = rec = Rec()
    res = c.chat(MSGS, Out, "w", ctx)
    assert res.ok and res.shrunk and shrunk == [1] and ctx.events == ["truncated"]
    assert [r.status for r in rec.calls] == ["truncated", "ok"]
    assert c.requests[1]["messages"][0]["content"] == "smaller"


def test_truncation_without_a_way_to_shrink_fails_loudly_and_never_continues():
    c = FakeLLMClient([FakeReply({"answer": "a"}, prompt_tokens=8000)] * 2)
    res = c.chat(MSGS, Out, "w", CallCtx("w", Rec(), lambda: None))
    assert not res.ok and res.truncated_flag and res.error == "context_truncated"
    twice = FakeLLMClient([FakeReply({"answer": "a"}, prompt_tokens=8100)] * 3)
    res2 = twice.chat(MSGS, Out, "w", CallCtx("w", Rec(), lambda: MSGS))
    assert not res2.ok and res2.truncated_flag and res2.attempts == 2


def test_timeout_and_connection_errors_are_clear_failures():
    def timeout(req):
        raise httpx.ReadTimeout("slow")

    def refused(req):
        raise httpx.ConnectError("no")

    res = ollama(timeout, timeout=7).chat(MSGS, Out, "p")
    assert not res.ok and "timed out after 7s" in res.error
    res = ollama(refused).chat(MSGS, Out, "p")
    assert not res.ok and "cannot reach Ollama at http://x" in res.error


def test_loaded_context_is_checked_and_a_mismatch_is_fatal():
    ps = lambda: {"models": [{"model": "m", "context_length": 4096}]}  # noqa: E731
    with pytest.raises(LLMFatal, match="4096 differs from num_ctx 8192"):
        ollama(lambda r: reply('{"answer":"a"}'), ps=ps).chat(MSGS, Out, "p")
    good = ollama(lambda r: reply('{"answer":"a"}'),
                  ps=lambda: {"models": [{"model": "m", "context_length": 8192}]})  # fmt: skip
    assert good.chat(MSGS, Out, "p").ok and good.loaded_ctx == 8192
    unknown = ollama(lambda r: reply('{"answer":"a"}'))
    assert unknown.chat(MSGS, Out, "p").ok and unknown.loaded_ctx is None


def test_replay_serves_recorded_calls_and_detects_divergence(tmp_path):
    rec = Rec()
    src = FakeLLMClient([{"answer": "a"}, {"answer": "b"}])
    src.chat(MSGS, Out, "p", CallCtx("p", rec))
    src.chat(MSGS + [{"role": "user", "content": "more"}], Out, "p", CallCtx("p", rec))
    (tmp_path / "llm").mkdir()
    for r in rec.calls:
        d = {k: getattr(r, k) for k in r.__dataclass_fields__}
        (tmp_path / "llm" / f"call_{r.idx:05d}.json").write_text(json.dumps(d), encoding="utf-8")
    rp = ReplayLLMClient(tmp_path, "m", 8192)
    assert rp.chat(MSGS, Out, "p").parsed.answer == "a"
    assert rp.chat(MSGS + [{"role": "user", "content": "more"}], Out, "p").parsed.answer == "b"
    bad = ReplayLLMClient(tmp_path, "m", 8192)
    bad.chat(MSGS, Out, "p")
    with pytest.raises(LLMFatal, match="replay diverged at call 2"):
        bad.chat(MSGS, Out, "p")  # same call 2, different prompt
    with pytest.raises(LLMFatal, match="replay diverged at call 3"):
        rp.chat(MSGS, Out, "p")  # more calls than recorded


def test_fake_script_errors_and_exhaustion():
    c = FakeLLMClient([FakeReply({}, error="boom"), FakeReply({}, fatal=True)])
    assert c.chat(MSGS, Out, "p").error == "boom"
    with pytest.raises(LLMFatal):
        c.chat(MSGS, Out, "p")
    with pytest.raises(LLMFatal, match="exhausted"):
        c.chat(MSGS, Out, "p")


# ---- budget and prompt builder ------------------------------------------------------------
def blocks():
    return [
        Block("report", "rep-1", "worker_report", "R" * 600, []),
        Block("obs", "obs-1", "tool:search_events", "O" * 600, ["EVT-000000000001", "HIT-000002"]),
        Block("obs", "obs-2", "tool:search_events", "P" * 600, ["EVT-000000000003"]),
    ]


def test_trimming_order_oldest_observations_first_then_reports_and_ids_survive():
    b = PromptBuilder("S" * 90, 900, 100, 0.8)  # budget 640 tokens
    msgs, info = b.build("C" * 30, blocks(), "tail")
    assert info.elided == ["obs-1"] and "EVT-000000000001 HIT-000002" in msgs[1]["content"]
    assert "R" * 600 in msgs[1]["content"] and "P" * 600 in msgs[1]["content"]
    tight = PromptBuilder("S" * 90, 380, 100, 0.8)  # budget 224: observations, then the report
    _, info2 = tight.build("C" * 30, blocks(), "tail")
    assert info2.elided == ["obs-1", "obs-2", "rep-1"]


def test_hard_cap_and_the_fixed_parts_are_never_trimmed():
    b = PromptBuilder("S" * 3000, 1000, 100, 0.8)  # the system prompt alone exceeds the budget
    with pytest.raises(PromptTooLarge):
        b.build("core", [], "tail")
    ok = PromptBuilder("SYSTEM", 2000, 100, 0.8)
    msgs, info = ok.build("CORE-NOTEBOOK", blocks(), "TAIL")
    assert msgs[0]["content"] == "SYSTEM" and "CORE-NOTEBOOK" in msgs[1]["content"]
    assert msgs[1]["content"].endswith("TAIL") and info.est_tokens <= info.budget
    msgs2, info2 = PromptBuilder("SYSTEM", 2000, 100, 0.8).build("CORE", blocks(), "TAIL", 0.3)
    assert info2.budget < info.budget and len(info2.elided) >= 1 and msgs2[0]["content"] == "SYSTEM"


def test_token_estimate_is_conservative():
    assert estimate_tokens("a" * 9) == 3 and estimate_tokens("") == 0


def test_ledger_entries_hold_hashes_and_never_text(synth_norm):
    from agent_helpers import PERT, PLANNER_FINISH, settings
    from chainofproof.agents.runner import run_agent

    paths, _ = synth_norm
    secret = "UNIQUE-RESPONSE-MARKER"
    script = [
        {"rationale": secret, **{k: v for k, v in PLANNER_FINISH.items() if k != "rationale"}}
    ]
    res = run_agent(paths, PERT, FakeLLMClient(script), settings())
    mine = [e for e in Ledger(paths).read_all() if e.details.get("run_id") == res.run_id]
    llm = [e for e in mine if e.action == "llm_call"]
    assert len(llm) == 1 and llm[0].actor == "llm:planner" and llm[0].output_hash
    d = llm[0].details
    assert d["model"] == "fake-model" and d["num_ctx"] == 8192 and d["prompt_tokens"] > 0
    assert (
        d["prompt_sha256"] == llm[0].input_hashes[0] and d["response_sha256"] == llm[0].output_hash
    )
    assert secret not in json.dumps([e.model_dump(mode="json") for e in mine])
    call = json.loads((paths.runs_dir / res.run_id / "llm" / "call_00001.json").read_text("utf-8"))
    assert secret in call["response_text"] and call["messages"][0]["role"] == "system"
