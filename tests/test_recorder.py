import pytest

from chainofproof.custody.hashing import sha256_bytes, sha256_json, sha256_text
from chainofproof.custody.ledger import Ledger
from chainofproof.custody.recorder import ToolRun, record_tool_call

H = "a" * 64


@pytest.mark.parametrize(
    "out,expected",
    [
        (b"raw", sha256_bytes(b"raw")),
        ("txt", sha256_text("txt")),
        ({"k": [1]}, sha256_json({"k": [1]})),
    ],
)
def test_output_hashing(paths, out, expected):
    e = record_tool_call(Ledger(paths), "tool:x", "x --y", [H], out)
    assert e.output_hash == expected and e.command == "x --y" and e.input_hashes == [H]


def test_toolrun_success(paths):
    led = Ledger(paths)
    with ToolRun(led, "tool:x", "x", [H]) as run:
        run.output = {"rows": 3}
    e = run.entry
    assert e.action == "tool_call" and e.details["status"] == "ok"
    assert e.details["duration_s"] >= 0 and e.output_hash == sha256_json({"rows": 3})


def test_toolrun_failure_reraises(paths):
    led = Ledger(paths)
    with pytest.raises(ValueError, match="bad parse"):
        with ToolRun(led, "tool:x", "x", [H]):
            raise ValueError("bad parse")
    e = led.read_all()[-1]
    assert e.action == "tool_call_failed"
    assert e.details["error_type"] == "ValueError" and e.details["error_message"] == "bad parse"
    assert e.output_hash is None and led.verify().ok
