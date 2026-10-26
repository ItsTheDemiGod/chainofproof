import json

import pytest
from typer.testing import CliRunner

from chainofproof.cli import app
from chainofproof.custody.db import connect
from chainofproof.custody.ledger import Ledger
from chainofproof.ingest.store import EvidenceStore, StoreError


def _fill(paths, n):
    led = Ledger(paths)
    for i in range(n):
        led.append("t", f"a{i}")
    return led


def _crash_append(led, monkeypatch):
    """Write one ledger line but skip the anchor update (simulated crash)."""

    def boom(*a, **k):
        raise RuntimeError("crash")

    with monkeypatch.context() as m:
        m.setattr(led, "_set_head", boom)
        with pytest.raises(RuntimeError):
            led.append("t", "crashed")


def _set_anchor(paths, **cols):
    conn = connect(paths.db_path)
    for k, v in cols.items():
        conn.execute(f"UPDATE ledger_head SET {k} = ? WHERE id = 1", (v,))
    conn.close()


def test_recover_after_crash(paths, monkeypatch):
    led = _fill(paths, 3)
    _crash_append(led, monkeypatch)
    assert not led.verify().ok
    res, msg = led.recover()
    assert res.ok, msg
    assert led.verify().ok
    last = led.read_all()[-1]
    assert last.action == "ledger_recovered" and len(led.read_all()) == 5
    assert last.details == {
        "old_anchor_id": "LED-000003",
        "old_anchor_count": 3,
        "new_anchor_id": "LED-000004",
        "new_anchor_count": 4,
    }


def test_recover_healthy_is_noop(paths):
    led = _fill(paths, 2)
    res, msg = led.recover()
    assert res.ok and "nothing to recover" in msg
    assert len(led.read_all()) == 2


def _assert_refused(led, before):
    res, msg = led.recover()
    assert not res.ok and "truncation or tampering" in msg and "\n" not in msg
    assert len(led.read_all()) == before


def test_refuse_anchor_ahead(paths):
    led = _fill(paths, 3)
    _set_anchor(paths, entry_count=5)
    _assert_refused(led, 3)


def test_refuse_hash_mismatch(paths, monkeypatch):
    led = _fill(paths, 3)
    _crash_append(led, monkeypatch)
    _set_anchor(paths, entry_hash="f" * 64)
    _assert_refused(led, 4)


def test_refuse_two_ahead(paths, monkeypatch):
    led = _fill(paths, 2)
    _crash_append(led, monkeypatch)
    _crash_append_again(led, monkeypatch)
    _assert_refused(led, 4)


def _crash_append_again(led, monkeypatch):
    # the append guard refuses a lagging anchor, so write the next line by hand
    last = led._last_raw()
    raw = dict(last, ledger_id="LED-000004", prev_hash=last["entry_hash"], action="x")
    from chainofproof.custody.ledger import _compute_hash

    raw["entry_hash"] = _compute_hash(raw)
    led._write_line(json.dumps(raw))


def test_refuse_tampered_chain(paths, monkeypatch):
    led = _fill(paths, 3)
    _crash_append(led, monkeypatch)
    lines = paths.ledger_path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"a1"', '"zz"')
    paths.ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _assert_refused(led, 4)


def test_cli_ledger_recover(paths, monkeypatch):
    led = _fill(paths, 2)
    _crash_append(led, monkeypatch)
    r = CliRunner().invoke(app, ["--base-dir", str(paths.base_dir), "ledger-recover"])
    assert r.exit_code == 0, r.output
    assert led.verify().ok


# ---- 0b: case logging in the library -----------------------------------------------------
def test_create_case_logs_once(paths):
    EvidenceStore(paths).create_case("C1", "title")
    es = Ledger(paths).read_all()
    assert [e.action for e in es] == ["case_create"]
    assert es[0].actor == "ingest" and es[0].details == {"case_id": "C1", "title": "title"}


def test_cli_case_create_no_double_entry(paths):
    r = CliRunner().invoke(app, ["--base-dir", str(paths.base_dir), "case-create", "C1"])
    assert r.exit_code == 0, r.output
    assert [e.action for e in Ledger(paths).read_all()] == ["case_create"]


def test_duplicate_case_writes_nothing(paths):
    s = EvidenceStore(paths)
    s.create_case("C1")
    with pytest.raises(StoreError, match="already exists"):
        s.create_case("C1")
    assert len(Ledger(paths).read_all()) == 1


def test_ledger_failure_after_commit(paths, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(Ledger, "append", boom)
    s = EvidenceStore(paths)
    with pytest.raises(StoreError, match="created but the ledger entry failed"):
        s.create_case("C1")
    assert s.get_case("C1") is not None
