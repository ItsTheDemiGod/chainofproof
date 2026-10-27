import sqlite3

import pytest

from chainofproof.custody.hashing import utc_now
from chainofproof.ingest.store import EvidenceStore, StoreError
from chainofproof.schemas.custody import EvidenceRecord, SourceType


def rec(i, sha="a" * 64, case="C1"):
    return EvidenceRecord(
        evidence_id=f"EV-{i:06d}",
        case_id=case,
        original_name="x",
        original_path="/x",
        vault_path="evidence_raw/x",
        size_bytes=1,
        sha256=sha,
        source_type=SourceType.other,
        ingested_at=utc_now(),
    )


@pytest.mark.parametrize("bad", ["../x", "a/b", "a\\b", "", "a b", "x" * 65, "..", "a;b"])
def test_bad_case_ids(paths, bad):
    with pytest.raises(StoreError):
        EvidenceStore(paths).create_case(bad)


def test_cases_and_ids(paths):
    s = EvidenceStore(paths)
    s.create_case("C1", "t", "d")
    s.create_case("C2")
    with pytest.raises(StoreError, match="already exists"):
        s.create_case("C1")
    assert [c.case_id for c in s.list_cases()] == ["C1", "C2"]
    assert s.next_evidence_id() == "EV-000001"
    s.add_evidence(rec(1, "a" * 64, "C1"))
    s.add_evidence(rec(2, "b" * 64, "C2"))
    assert s.next_evidence_id() == "EV-000003"
    assert [e.evidence_id for e in s.list_evidence("C2")] == ["EV-000002"]
    assert len(s.list_evidence()) == 2
    assert s.get_evidence("EV-000009") is None


def test_unique_case_sha(paths):
    s = EvidenceStore(paths)
    s.create_case("C1")
    s.add_evidence(rec(1))
    with pytest.raises(StoreError):
        s.add_evidence(rec(2))


def test_unknown_case_fk(paths):
    with pytest.raises(StoreError):
        EvidenceStore(paths).add_evidence(rec(1, case="nope"))


def test_sql_injection_text_is_data(paths):
    s = EvidenceStore(paths)
    title = "O'Brien'; DROP TABLE cases;--"
    s.create_case("C1", title, "x' OR '1'='1")
    assert s.get_case("C1").title == title
    assert len(s.list_cases()) == 1
    assert s.get_case("C1' OR '1'='1") is None


def test_schema_version(paths):
    EvidenceStore(paths)
    con = sqlite3.connect(paths.db_path)
    assert con.execute("select version from schema_version").fetchall() == [
        (2,)
    ]  # fresh databases start at v2
    con.close()
