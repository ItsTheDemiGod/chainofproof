import pytest

from chainofproof.custody.hashing import sha256_file
from chainofproof.custody.ledger import Ledger
from chainofproof.ingest.ingest import ingest_evidence
from chainofproof.ingest.integrity import (
    IntegrityError,
    get_working_copy,
    verify_all,
    verify_evidence,
)
from chainofproof.ingest.store import EvidenceStore
from chainofproof.ingest.vault import is_read_only, make_writable


@pytest.fixture
def ev(paths, make_file):
    EvidenceStore(paths).create_case("C1")
    return ingest_evidence(paths, "C1", make_file("a.log", b"some log data"))


def _tamper(paths, ev):
    v = paths.base_dir / ev.vault_path
    make_writable(v)
    v.write_bytes(b"some log dXta")  # same size, one byte changed
    return v


def test_verify_ok(paths, ev):
    res = verify_evidence(paths, ev.evidence_id)
    assert res.ok and res.problems == []
    assert Ledger(paths).read_all()[-1].action == "verify_evidence"
    assert verify_all(paths).ok and verify_all(paths, "C1").checked == 1


def test_verify_all_writes_one_summary_entry(paths, ev, make_file):
    ingest_evidence(paths, "C1", make_file("b.log", b"second"))
    ledger = Ledger(paths)
    n = len(ledger.read_all())
    assert verify_all(paths, "C1").checked == 2
    new = ledger.read_all()[n:]
    assert [e.action for e in new] == ["verify_all"]
    d = new[0].details
    assert (d["case_id"], d["items_checked"], d["ok_count"], d["problem_count"]) == ("C1", 2, 2, 0)
    assert len(d["results_sha256"]) == 64
    verify_evidence(paths, ev.evidence_id)
    assert ledger.read_all()[-1].action == "verify_evidence"


def test_unknown_id(paths, ev):
    with pytest.raises(IntegrityError, match="unknown evidence id"):
        verify_evidence(paths, "EV-999999")


def test_modified_byte(paths, ev):
    _tamper(paths, ev)
    res = verify_evidence(paths, ev.evidence_id)
    assert not res.ok
    assert any("sha256 mismatch" in p for p in res.problems)
    assert any(p.startswith("WARN:") for p in res.problems)  # read-only was cleared
    assert not verify_all(paths).ok


def test_only_warning_is_ok(paths, ev):
    make_writable(paths.base_dir / ev.vault_path)
    res = verify_evidence(paths, ev.evidence_id)
    assert res.ok and res.problems[0].startswith("WARN:")


def test_deleted_vault_file(paths, ev):
    v = paths.base_dir / ev.vault_path
    make_writable(v)
    v.unlink()
    res = verify_evidence(paths, ev.evidence_id)
    assert not res.ok and "missing" in res.problems[0]


def test_working_copy_refuses_tampered(paths, ev):
    _tamper(paths, ev)
    with pytest.raises(IntegrityError, match="failed verification"):
        get_working_copy(paths, ev.evidence_id)
    assert not (paths.evidence_working / "C1").exists() or not any(
        (paths.evidence_working / "C1").iterdir()
    )


def test_working_copy_created_and_reused(paths, ev):
    w = get_working_copy(paths, ev.evidence_id)
    assert (
        w.parent == paths.evidence_working / "C1"
        and w.name == (paths.base_dir / ev.vault_path).name
    )
    assert sha256_file(w) == ev.sha256 and is_read_only(w)
    n = sum(1 for e in Ledger(paths).read_all() if e.action == "working_copy")
    assert get_working_copy(paths, ev.evidence_id) == w
    assert sum(1 for e in Ledger(paths).read_all() if e.action == "working_copy") == n == 1
