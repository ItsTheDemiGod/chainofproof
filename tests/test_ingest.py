import os
import tracemalloc

import pytest

from chainofproof.custody.hashing import sha256_file
from chainofproof.custody.ledger import Ledger
from chainofproof.ingest import ingest as ingest_mod
from chainofproof.ingest.detect import detect_source_type
from chainofproof.ingest.ingest import IngestError, ingest_evidence
from chainofproof.ingest.store import EvidenceStore
from chainofproof.ingest.vault import is_read_only, sanitize_filename
from chainofproof.schemas.custody import SourceType


@pytest.fixture
def case(paths):
    EvidenceStore(paths).create_case("C1")
    return "C1"


def test_happy_path(paths, case, make_file):
    src = make_file("log.txt", b"hello")
    r = ingest_evidence(paths, case, src, description="d")
    vault = paths.base_dir / r.vault_path
    assert r.evidence_id == "EV-000001" and r.source_type == SourceType.log_text
    assert r.sha256 == sha256_file(src) == sha256_file(vault) and r.size_bytes == 5
    assert r.vault_path.startswith("evidence_raw/C1/EV-000001__log.txt")
    assert is_read_only(vault)
    assert EvidenceStore(paths).get_evidence("EV-000001") == r
    last = Ledger(paths).read_all()[-1]
    assert last.action == "ingest" and last.input_hashes == [r.sha256]
    assert last.details["evidence_id"] == "EV-000001" and "original_path" not in last.details
    assert Ledger(paths).verify().ok
    assert src.read_bytes() == b"hello"  # original untouched


def test_duplicate(paths, case, make_file):
    src = make_file()
    a = ingest_evidence(paths, case, src)
    b = ingest_evidence(paths, case, src)
    assert a == b
    assert len(list((paths.evidence_raw / case).iterdir())) == 1
    assert len(EvidenceStore(paths).list_evidence()) == 1
    assert Ledger(paths).read_all()[-1].action == "ingest_duplicate"


def test_missing_case(paths, make_file):
    with pytest.raises(IngestError, match="create it first"):
        ingest_evidence(paths, "nope", make_file())


def test_rejects_missing_dir_symlink(paths, case, make_file, tmp_path):
    with pytest.raises(IngestError, match="not found"):
        ingest_evidence(paths, case, tmp_path / "missing")
    with pytest.raises(IngestError, match="not a regular file"):
        ingest_evidence(paths, case, tmp_path)
    link = tmp_path / "link"
    try:
        os.symlink(make_file(), link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted")
    with pytest.raises(IngestError, match="symlink"):
        ingest_evidence(paths, case, link)


def test_detect(tmp_path):
    def mk(name, head=b""):
        p = tmp_path / name
        p.write_bytes(head + b"x" * 16)
        return p

    assert detect_source_type(mk("noext", b"ElfFile\x00")) == SourceType.evtx
    assert detect_source_type(mk("a.evtx")) == SourceType.evtx
    for magic in ("a1b2c3d4", "d4c3b2a1", "a1b23c4d", "4d3cb2a1", "0a0d0d0a"):
        assert detect_source_type(mk("cap", bytes.fromhex(magic))) == SourceType.pcap
    assert detect_source_type(mk("x.PCAPNG")) == SourceType.pcap
    for ext in (".raw", ".mem", ".vmem", ".dmp", ".lime"):
        assert detect_source_type(mk("m" + ext)) == SourceType.memory_dump
    for ext in (".E01", ".dd", ".img", ".vhd", ".vhdx"):
        assert detect_source_type(mk("d" + ext)) == SourceType.disk_image
    for ext in (".txt", ".log", ".csv", ".json", ".jsonl", ".xml"):
        assert detect_source_type(mk("t" + ext)) == SourceType.log_text
    for ext in (".pdf", ".docx", ".doc", ".xlsx"):
        assert detect_source_type(mk("p" + ext)) == SourceType.document
    assert detect_source_type(mk("weird.bin")) == SourceType.other


def test_type_override(paths, case, make_file):
    r = ingest_evidence(paths, case, make_file("a.txt"), source_type=SourceType.document)
    assert r.source_type == SourceType.document


def test_sanitize():
    assert sanitize_filename("my file (1).txt") == "my_file__1_.txt"
    assert sanitize_filename("héllo.txt") == "h_llo.txt"
    assert not sanitize_filename("..").startswith(".")
    assert not sanitize_filename(".hidden").startswith(".")
    assert "/" not in sanitize_filename("../../etc/passwd") and "\\" not in sanitize_filename(
        "a\\b"
    )
    long = sanitize_filename("a" * 500 + ".evtx")
    assert len(long) <= 100 and long.endswith(".evtx")
    assert sanitize_filename("") == "file"


def test_weird_name_ingests(paths, case, make_file):
    r = ingest_evidence(paths, case, make_file("..weird name é.txt"))
    assert (paths.base_dir / r.vault_path).is_file()
    assert ".." not in r.vault_path.split("__", 1)[1][:2]


def test_failure_injection(paths, case, make_file, monkeypatch):
    src = make_file()
    real = ingest_mod.sha256_file
    calls = []

    def fake(p):
        calls.append(p)
        return real(p) if len(calls) == 1 else "f" * 64

    monkeypatch.setattr(ingest_mod, "sha256_file", fake)
    with pytest.raises(IngestError, match="hash differs"):
        ingest_evidence(paths, case, src)
    assert list((paths.evidence_raw / case).glob("*")) == []
    assert EvidenceStore(paths).list_evidence() == []
    last = Ledger(paths).read_all()[-1]
    assert last.action == "ingest_failed" and "hash differs" in last.details["reason"]
    assert Ledger(paths).verify().ok


def test_ledger_failure_rolls_back_row(paths, case, make_file, monkeypatch):
    real = Ledger.append

    def boom(self, actor, action, *a, **k):
        if action == "ingest":
            raise RuntimeError("disk full")
        return real(self, actor, action, *a, **k)

    monkeypatch.setattr(Ledger, "append", boom)
    with pytest.raises(IngestError, match="disk full"):
        ingest_evidence(paths, case, make_file())
    assert EvidenceStore(paths).list_evidence() == []
    assert list((paths.evidence_raw / case).glob("*")) == []


def test_large_file_low_memory(paths, case, tmp_path):
    big = tmp_path / "big.mem"
    with big.open("wb") as f:
        for _ in range(50):
            f.write(os.urandom(1024 * 1024))
    tracemalloc.start()
    r = ingest_evidence(paths, case, big)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert r.size_bytes == 50 * 1024 * 1024 and r.sha256 == sha256_file(big)
    assert peak < 10 * 1024 * 1024
