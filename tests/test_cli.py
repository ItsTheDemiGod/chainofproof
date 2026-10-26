import json

import pytest
from typer.testing import CliRunner

from chainofproof.cli import app

runner = CliRunner()


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINOFPROOF_BASE_DIR", str(tmp_path / "base"))

    def _run(*args):
        return runner.invoke(app, list(args))

    return _run


def test_full_flow(run, tmp_path):
    f = tmp_path / "evidence.log"
    f.write_text("synthetic")
    assert run("case-create", "C1", "--title", "T").exit_code == 0
    assert "C1" in run("case-list").output
    r = run("ingest", "C1", str(f), "--description", "d")
    assert r.exit_code == 0 and "EV-000001" in r.output
    assert "EV-000001" in run("evidence-list", "--case", "C1").output
    assert "log_text" in run("evidence-show", "EV-000001").output
    v = run("verify-evidence")
    assert v.exit_code == 0 and "OK" in v.output
    assert run("verify-evidence", "EV-000001").exit_code == 0
    w = run("working-copy", "EV-000001")
    assert w.exit_code == 0 and "evidence_working" in w.output
    assert "ingest" in run("ledger-show", "--tail", "10").output
    assert "ledger OK" in run("ledger-verify").output
    head = json.loads(run("ledger-head").output)
    assert head["ledger_id"].startswith("LED-") and head["count"] >= 4
    assert not (tmp_path / "base" / "ledger" / "ledger.jsonl.lock").is_dir()


def test_errors_are_clean(run, tmp_path):
    for args in (
        ("evidence-show", "EV-999999"),
        ("verify-evidence", "EV-999999"),
        ("working-copy", "EV-999999"),
        ("ingest", "NOPE", str(tmp_path / "missing")),
        ("case-create", "../bad"),
    ):
        r = run(*args)
        assert r.exit_code == 1, args
        assert "Traceback" not in r.output and "error:" in r.output


def test_ledger_verify_exit_code(run, tmp_path):
    run("case-create", "C1")
    run("case-create", "C2")
    lp = tmp_path / "base" / "ledger" / "ledger.jsonl"
    lines = lp.read_text(encoding="utf-8").splitlines()
    lp.write_text(lines[0] + "\n", encoding="utf-8")
    r = run("ledger-verify")
    assert r.exit_code == 1 and "LED-000002" in r.output


def test_verify_detects_tamper(run, tmp_path):
    f = tmp_path / "e.txt"
    f.write_text("abc")
    run("case-create", "C1")
    run("ingest", "C1", str(f))
    from chainofproof.ingest.vault import make_writable

    v = next((tmp_path / "base" / "evidence_raw" / "C1").iterdir())
    make_writable(v)
    v.write_text("abd")
    r = run("verify-evidence")
    assert r.exit_code == 1 and "sha256 mismatch" in r.output
