import json
import multiprocessing
import sqlite3
import threading

import pytest

from chainofproof.custody.ledger import Ledger, LedgerError
from chainofproof.schemas.custody import GENESIS_HASH


def _fill(paths, n=5):
    led = Ledger(paths)
    for i in range(n):
        led.append("t", f"act{i}", details={"i": i})
    return led


def _lines(paths):
    return paths.ledger_path.read_text(encoding="utf-8").splitlines()


def _write(paths, lines):
    paths.ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_chain_basics(paths):
    led = _fill(paths, 3)
    es = led.read_all()
    assert es[0].prev_hash == GENESIS_HASH
    assert [e.ledger_id for e in es] == ["LED-000001", "LED-000002", "LED-000003"]
    assert es[1].prev_hash == es[0].entry_hash
    assert led.verify().ok and led.verify().checked == 3
    assert led.get("LED-000002").action == "act1"
    assert [e.ledger_id for e in led.tail(2)] == ["LED-000002", "LED-000003"]
    assert led.export_head()["count"] == 3


def test_empty_ledger_ok(paths):
    assert Ledger(paths).verify().ok


def test_head_updated_each_append(paths):
    led = Ledger(paths)
    for i in range(1, 4):
        e = led.append("t", "a")
        con = sqlite3.connect(paths.db_path)
        row = con.execute("select ledger_id, entry_count, entry_hash from ledger_head").fetchone()
        con.close()
        assert row == (e.ledger_id, i, e.entry_hash)


def test_non_serializable_details(paths):
    with pytest.raises(TypeError):
        Ledger(paths).append("t", "a", details={"x": object()})


def test_edit_detected(paths):
    led = _fill(paths)
    ls = _lines(paths)
    d = json.loads(ls[1])
    d["action"] = "evil"
    ls[1] = json.dumps(d)
    _write(paths, ls)
    res = led.verify()
    assert not res.ok and res.problems[0].startswith("LED-000002") and "modified" in res.problems[0]


def test_delete_middle_detected(paths):
    led = _fill(paths)
    ls = _lines(paths)
    del ls[2]
    _write(paths, ls)
    res = led.verify()
    assert not res.ok and res.problems[0].startswith("LED-000004")


def test_reorder_detected(paths):
    led = _fill(paths)
    ls = _lines(paths)
    ls[1], ls[2] = ls[2], ls[1]
    _write(paths, ls)
    res = led.verify()
    assert not res.ok and res.problems[0].startswith("LED-000003")


def test_malformed_line_detected(paths):
    led = _fill(paths)
    ls = _lines(paths)
    ls[2] = "{not json"
    _write(paths, ls)
    res = led.verify()
    assert not res.ok and "line 3 (after LED-000002)" in res.problems[0]
    ls[2] = json.dumps({"ledger_id": "LED-000003"})
    _write(paths, ls)
    assert "line 3" in led.verify().problems[0]


def test_wrong_genesis_detected(paths):
    led = _fill(paths, 2)
    ls = _lines(paths)
    d = json.loads(ls[0])
    d["prev_hash"] = "1" * 64
    ls[0] = json.dumps(d)
    _write(paths, ls)
    assert "LED-000001: wrong genesis" in led.verify().problems[0]


def test_delete_last_detected_via_anchor(paths):
    led = _fill(paths)
    _write(paths, _lines(paths)[:-1])
    res = led.verify()
    assert not res.ok and "truncated or head anchor out of sync" in res.problems[0]
    assert "LED-000005" in res.problems[0]
    with pytest.raises(LedgerError, match="truncated"):
        led.append("t", "a")  # must not silently move the anchor


def test_threads(paths):
    led = Ledger(paths)

    def work():
        for _ in range(25):
            led.append("t", "a")

    ts = [threading.Thread(target=work) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    es = led.read_all()
    assert len(es) == 100 and len({e.ledger_id for e in es}) == 100
    assert led.verify().ok


def _proc(paths):
    led = Ledger(paths)
    for _ in range(20):
        led.append("p", "a")


def test_processes(paths):
    ps = [multiprocessing.Process(target=_proc, args=(paths,)) for _ in range(2)]
    [p.start() for p in ps]
    [p.join(60) for p in ps]
    assert all(p.exitcode == 0 for p in ps)
    led = Ledger(paths)
    assert len(led.read_all()) == 40 and led.verify().ok
