import sqlite3
from contextlib import closing

from chainofproof.custody.hashing import sha256_file
from chainofproof.custody.ledger import Ledger
from chainofproof.custody.migrations import (
    migrate_to_v2,
    migrate_to_v3,
    migrate_to_v4,
    schema_version,
)
from chainofproof.ingest.store import SCHEMA, EvidenceStore


def make_v1(paths):
    """A version-1 database with a case, an evidence row and some ledger entries."""
    with closing(sqlite3.connect(paths.db_path)) as con:
        for ddl in SCHEMA:
            con.execute(ddl)
        con.execute("INSERT INTO schema_version VALUES (1)")
        con.execute("INSERT INTO cases VALUES ('C1','t','d','2024-01-01')")
        con.execute(
            "INSERT INTO evidence VALUES ('EV-000001','C1','n.log','p','v/n.log',3,'ab','log_text',"
            "'x','2024-01-01','me')"
        )
        con.commit()
    ledger = Ledger(paths)
    ledger.append("t", "one")
    ledger.append("t", "two")


def tables(paths):
    with closing(sqlite3.connect(paths.db_path)) as con:
        return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def test_migrates_v1_without_losing_anything(paths):
    make_v1(paths)
    m = migrate_to_v2(paths)
    assert m.migrated and (m.from_version, m.to_version) == (1, 2)
    with closing(sqlite3.connect(paths.db_path)) as con:
        assert con.execute("SELECT version FROM schema_version").fetchall() == [(2,)]
        assert con.execute("SELECT case_id FROM cases").fetchall() == [("C1",)]
        assert con.execute("SELECT evidence_id, sha256 FROM evidence").fetchall() == [
            ("EV-000001", "ab")
        ]
    assert {"norm_runs", "events", "detections", "event_eval_meta"} <= tables(paths)
    backup = paths.db_dir / "backups" / "chainofproof.db.pre-v2"
    assert backup.is_file() and sha256_file(backup) == m.backup_sha256
    with closing(sqlite3.connect(backup)) as con:  # the backup is a v1 database with the data
        assert con.execute("SELECT version FROM schema_version").fetchall() == [(1,)]
        assert con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 1
    last = Ledger(paths).read_all()[-1]
    assert last.action == "db_migrate" and Ledger(paths).verify().ok
    assert last.details == {
        "from_version": 1, "to_version": 2,
        "backup_file": "chainofproof.db.pre-v2", "backup_sha256": m.backup_sha256,
    }  # fmt: skip


def test_migration_is_idempotent_and_v2_is_left_alone(paths):
    make_v1(paths)
    migrate_to_v2(paths)
    n = len(Ledger(paths).read_all())
    again = migrate_to_v2(paths)
    assert not again.migrated and len(Ledger(paths).read_all()) == n
    assert len(list((paths.db_dir / "backups").iterdir())) == 1


V3_TABLES = {"detector_runs", "detector_hits", "graph_runs"}


def test_v2_to_v3_keeps_data_is_idempotent_and_v3_left_alone(paths):
    make_v1(paths)
    migrate_to_v2(paths)
    n = len(Ledger(paths).read_all())
    m = migrate_to_v3(paths)
    assert m.migrated and (m.from_version, m.to_version) == (2, 3)
    assert m.backup_name == "chainofproof.db.pre-v3"
    backup = paths.db_dir / "backups" / m.backup_name
    assert sha256_file(backup) == m.backup_sha256
    assert V3_TABLES <= tables(paths)
    with closing(sqlite3.connect(paths.db_path)) as con:
        assert schema_version(con) == 3
        assert con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 1
    last = Ledger(paths).read_all()[-1]
    assert last.action == "db_migrate" and last.details["to_version"] == 3
    assert len(Ledger(paths).read_all()) == n + 1
    assert not migrate_to_v3(paths).migrated and len(Ledger(paths).read_all()) == n + 1
    assert Ledger(paths).verify().ok


def test_v1_passes_through_v2_to_v3(paths):
    make_v1(paths)
    m = migrate_to_v3(paths)
    assert (m.from_version, m.to_version) == (2, 3)
    names = sorted(p.name for p in (paths.db_dir / "backups").iterdir())
    assert names == ["chainofproof.db.pre-v2", "chainofproof.db.pre-v3"]


def test_fresh_database_is_created_at_latest_version_and_not_migrated(paths):
    EvidenceStore(paths)
    with closing(sqlite3.connect(paths.db_path)) as con:
        assert schema_version(con) == 4
    assert (V3_TABLES | V4_TABLES) <= tables(paths)
    m = migrate_to_v4(paths)
    assert not migrate_to_v2(paths).migrated and not migrate_to_v3(paths).migrated
    assert not m.migrated and not (paths.db_dir / "backups").exists()


V4_TABLES = {"agent_runs", "agent_calls", "findings"}


def test_v3_to_v4_keeps_data_marks_old_rows_as_harness_and_is_idempotent(paths):
    make_v1(paths)
    migrate_to_v3(paths)
    with closing(sqlite3.connect(paths.db_path)) as con:  # a v3 detector run with a hit
        con.execute(
            "INSERT INTO detector_runs VALUES ('RUN-000001','C1','log_gap','{}','p','i',1,'o','L',"
            "'2024-01-01')"
        )
        con.execute(
            "INSERT INTO detector_hits VALUES ('HIT-000001','RUN-000001','C1','k','log_gap','k',"
            "'low','[]','[]','[]','{}','e','[]','2024-01-01')"
        )
        con.commit()
    n = len(Ledger(paths).read_all())
    m = migrate_to_v4(paths)
    assert m.migrated and (m.from_version, m.to_version) == (3, 4)
    assert m.backup_name == "chainofproof.db.pre-v4"
    assert sha256_file(paths.db_dir / "backups" / m.backup_name) == m.backup_sha256
    assert V4_TABLES <= tables(paths)
    with closing(sqlite3.connect(paths.db_path)) as con:
        assert schema_version(con) == 4
        assert con.execute("SELECT origin, agent_run_id FROM detector_hits").fetchall() == [
            ("harness", None)
        ]
        assert con.execute("SELECT origin FROM detector_runs").fetchall() == [("harness",)]
        assert con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 1
    last = Ledger(paths).read_all()[-1]
    assert last.action == "db_migrate" and last.details["to_version"] == 4
    assert len(Ledger(paths).read_all()) == n + 1
    assert not migrate_to_v4(paths).migrated and len(Ledger(paths).read_all()) == n + 1
    assert Ledger(paths).verify().ok


def test_v1_passes_through_every_step_to_v4(paths):
    make_v1(paths)
    assert migrate_to_v4(paths).to_version == 4
    names = sorted(p.name for p in (paths.db_dir / "backups").iterdir())
    assert names == [f"chainofproof.db.pre-v{i}" for i in (2, 3, 4)]


def test_existing_backup_is_never_overwritten(paths):
    make_v1(paths)
    first = migrate_to_v2(paths)
    with closing(sqlite3.connect(paths.db_path)) as con:  # simulate an old v1 again
        con.execute("UPDATE schema_version SET version = 1")
        con.commit()
    second = migrate_to_v2(paths)
    assert (first.backup_name, second.backup_name) == (
        "chainofproof.db.pre-v2",
        "chainofproof.db.pre-v2.2",
    )
    assert sha256_file(paths.db_dir / "backups" / first.backup_name) == first.backup_sha256
