import json

import ollama
import pytest

from chainofproof.config import load_settings

pytestmark = pytest.mark.llm


def test_json_roundtrip():
    o = load_settings().ollama
    resp = ollama.Client(host=o.host).chat(
        model=o.default_model,
        messages=[{"role": "user", "content": 'Reply with the JSON object {"status":"ok"} only.'}],
        format="json",
        options={"temperature": o.temperature, "num_ctx": o.num_ctx, "seed": o.seed},
    )
    assert json.loads(resp.message.content) == {"status": "ok"}
