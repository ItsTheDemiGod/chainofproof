"""Normalizer on the SYNTHETIC v3 sources: labels, uids, determinism, versioning, perturbations."""

import re
import sqlite3
from contextlib import closing
from datetime import datetime

import pytest

from chainofproof.eval.gt_link import build_index
from chainofproof.ingest.ingest import ingest_evidence
from chainofproof.ingest.store import EvidenceStore
from chainofproof.scenarios.source_map import resolve_source_keys, split_case_id
from chainofproof.schemas.events import SourceKindName
from chainofproof.schemas.scenario import ScenarioError, Variant
from chainofproof.tools import normalize as norm
from chainofproof.tools import query
from chainofproof.tools.normalize import NormalizationError, normalize_evidence
from conftest import synthetic_env

CLEAN, PERT = "credtheft_lateral_v3_clean", "credtheft_lateral_v3_perturbed"
FMT = "%Y-%m-%dT%H:%M:%S.%fZ"
SYNTH_KEYS = [
    "fs_ws_fin_07", "fs_srv_file_02", "fs_dc_01",
    "auth_ws_fin_07", "auth_srv_file_02", "auth_dc_01",
]  # fmt: skip


def ts(idx, sk, rid):
    return datetime.strptime(idx.row(idx.uids(sk, rid)[0])["timestamp"], FMT)


def day_gap(fields):
    fn, si = (
        datetime.fromisoformat(fields["fn_created"]),
        datetime.fromisoformat(fields["si_created"]),
    )
    return (fn - si).days


def one_file_env(v3, tmp_path):
    paths, _ = synthetic_env(tmp_path / "b", v3, files=("auth_ws_fin_07.log",))
    (rec,) = EvidenceStore(paths).list_evidence(CLEAN)
    return paths, rec


def test_labels_hosts_and_uids_are_opaque(synth_norm):
    paths, rows = synth_norm
    store = EvidenceStore(paths)
    for case, report in rows.items():
        assert len(report) == 6
        by_ev = {r.evidence_id: r for r in store.list_evidence(case)}
        for r in report:
            sha = by_ev[r.evidence_id].sha256
            prefix = {"fs_timeline": "FSTL", "auth_log": "AUTH"}[r.source_kind]
            assert r.label == f"{prefix}-{sha[:6]}" and r.events > 0 and r.corrupt == 0
            assert set(r.hosts) <= {"WS-FIN-07", "SRV-FILE-02", "DC-01"}


def test_event_uids_unique_and_shared_for_identical_files(synth_norm):
    paths, _ = synth_norm
    clean, pert = build_index(paths, CLEAN), build_index(paths, PERT)
    for idx in (clean, pert):
        assert sum(len(v) for v in idx.by_ref.values()) == len(idx.rows)  # no uid collisions
        assert all(re.fullmatch(r"EVT-[0-9a-f]{12}", u) for u in idx.rows)
    # these three files are byte-identical in both variants, so their events share uids
    for sk in ("fs_dc_01", "fs_ws_fin_07", "auth_ws_fin_07"):
        assert sorted(clean.by_source(sk)) == sorted(pert.by_source(sk)) != []


def test_perturbations_are_not_corrected(synth_norm):
    paths, _ = synth_norm
    clean, pert = build_index(paths, CLEAN), build_index(paths, PERT)
    # clock skew: every SRV-FILE-02 auth line is 420 s later in the perturbed variant
    seqs = sorted(r for (sk, r) in pert.by_ref if sk == "auth_srv_file_02")
    assert len(seqs) == 272
    deltas = {
        int((ts(pert, "auth_srv_file_02", s) - ts(clean, "auth_srv_file_02", s)).total_seconds())
        for s in seqs
    }
    assert deltas == {420}
    # timestomp: si_created days earlier than fn_created (perturbed), equal (clean)
    for rid in (272, 339):
        p = pert.row(pert.uids("fs_srv_file_02", rid)[0])["fields"]
        c = clean.row(clean.uids("fs_srv_file_02", rid)[0])["fields"]
        assert day_gap(p) >= 1000 and day_gap(c) == 0
    # removed DC-01 lines stay missing
    assert not any(pert.uids("auth_dc_01", s) for s in range(144, 157))
    assert all(clean.uids("auth_dc_01", s) for s in range(144, 157))


def test_determinism_and_versioning_without_deletions(v3, tmp_path):
    paths, rec = one_file_env(v3, tmp_path)
    with closing(sqlite3.connect(paths.db_path)) as con:
        run_id, n = con.execute(
            "SELECT run_id, event_count FROM norm_runs WHERE evidence_id = ?", [rec.evidence_id]
        ).fetchone()
    old = paths.runs_dir / run_id / f"normalized_{rec.evidence_id}.jsonl"
    again = normalize_evidence(paths, rec.evidence_id)
    assert again.run_id != run_id
    assert again.jsonl_path.read_bytes() == old.read_bytes()  # byte-identical twice
    with closing(sqlite3.connect(paths.db_path)) as con:
        sql = (
            "SELECT COUNT(*) FROM events WHERE norm_run_id IN "
            "(SELECT run_id FROM norm_runs WHERE evidence_id = ?)"
        )
        total = con.execute(sql, [rec.evidence_id]).fetchone()[0]
    assert total == 2 * n and old.exists()  # old rows and files are kept
    assert query.search_events(paths, CLEAN, limit=1).total_matches == n  # only the latest run


def test_uid_collision_is_a_hard_error(v3, tmp_path, monkeypatch):
    paths, rec = one_file_env(v3, tmp_path)
    real = norm.PARSERS[SourceKindName.auth_log]

    def doubled(path, ctx):
        for pair in real(path, ctx):
            yield pair
            yield pair

    monkeypatch.setitem(norm.PARSERS, SourceKindName.auth_log, doubled)
    with pytest.raises(NormalizationError, match="collision"):
        normalize_evidence(paths, rec.evidence_id)


def test_resolve_source_keys(synth_norm):
    paths, _ = synth_norm
    assert sorted(resolve_source_keys(paths, CLEAN).values()) == sorted(SYNTH_KEYS)
    assert split_case_id(PERT) == ("credtheft_lateral_v3", Variant.perturbed)


@pytest.mark.parametrize(
    "bad", ["credtheft_lateral_v3", "credtheft_lateral_v3_other", "nope_clean"]
)
def test_case_id_must_match_a_scenario_and_variant(bad):
    with pytest.raises(ScenarioError, match="not <scenario_id>_<variant>"):
        split_case_id(bad)


def test_resolve_refuses_unknown_and_wrong_variant_files(v3, tmp_path, paths):
    store = EvidenceStore(paths)
    store.create_case(CLEAN)
    with pytest.raises(ScenarioError, match="has no evidence"):
        resolve_source_keys(paths, CLEAN)
    stray = tmp_path / "stray.log"
    stray.write_text("hello\n", encoding="utf-8")
    rec = ingest_evidence(paths, CLEAN, stray)
    with pytest.raises(ScenarioError, match=f"not part of.*{rec.evidence_id}"):
        resolve_source_keys(paths, CLEAN)
    store.create_case("other_case")
    with pytest.raises(ScenarioError, match="not <scenario_id>_<variant>"):
        resolve_source_keys(paths, "other_case")


def test_perturbed_file_is_not_a_clean_variant_file(v3, paths):
    EvidenceStore(paths).create_case(CLEAN)
    ingest_evidence(paths, CLEAN, v3.dirs[Variant.perturbed] / "auth_dc_01.log")
    with pytest.raises(ScenarioError, match="not part of"):
        resolve_source_keys(paths, CLEAN)
