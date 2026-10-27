"""CLI + build workflow on the fixture scenario, and dataset-marked tests on the real files."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from chainofproof.cli import app
from chainofproof.config import get_paths
from chainofproof.custody.ledger import Ledger
from chainofproof.ingest.store import EvidenceStore
from chainofproof.scenarios import build
from chainofproof.scenarios.dataset import dataset_root, verify_dataset
from chainofproof.scenarios.inventory import inventory_file, load_inventory
from chainofproof.schemas.scenario import load_scenario
from scenario_fixture import SID, build_fixture

runner = CliRunner()


@pytest.fixture
def env(tmp_path, monkeypatch):
    scn, inv, sroot, ddir = build_fixture(tmp_path)
    monkeypatch.setenv("CHAINOFPROOF_SCENARIOS_DIR", str(sroot))
    monkeypatch.setenv("CHAINOFPROOF_DATASET_DIR", str(ddir))
    monkeypatch.setenv("COLUMNS", "200")
    build.write_keys(SID)
    return tmp_path / "base", ddir


def cli(base, *args):
    return runner.invoke(app, ["--base-dir", str(base), *args])


def test_scenario_list(env):
    r = cli(env[0], "scenario-list")
    assert r.exit_code == 0 and SID in r.output and "clean, perturbed" in r.output


def test_key_show(env):
    r = cli(env[0], "scenario-key-show", SID, "perturbed")
    assert r.exit_code == 0, r.output
    assert "GT-ACT-001" in r.output and "GT-CON-003" in r.output and "GT-MIS-001" in r.output


def test_verify_ok_and_detects_drift(env):
    base, ddir = env
    assert cli(base, "scenario-verify", SID).exit_code == 0
    (ddir / "s1.evtx").write_bytes(b"tampered")
    r = cli(base, "scenario-verify", SID)
    assert r.exit_code == 1 and "dataset drift" in r.output.lower()


def test_verify_detects_stale_key(env, tmp_path):
    key = tmp_path / "scenarios" / SID / "key_clean.yaml"
    key.write_text(
        key.read_text(encoding="utf-8").replace("GT-ACT-001", "GT-ACT-009", 1), encoding="utf-8"
    )
    r = cli(env[0], "scenario-verify", SID)
    assert r.exit_code == 1


def test_inventory_refuses_overwrite(env):
    r = cli(env[0], "scenario-inventory", SID)
    assert r.exit_code == 1 and "--force" in r.output


def test_build_is_idempotent_and_ledgered_once(env):
    base, _ = env
    paths = get_paths(base_dir=base)
    for variant in ("clean", "perturbed"):
        assert cli(base, "scenario-build", SID, variant).exit_code == 0
    first = EvidenceStore(paths).list_evidence(f"{SID}_clean")
    assert len(first) == 12  # 6 real + 6 synthetic
    n_ledger = len(Ledger(paths).read_all())
    r = cli(base, "scenario-build", SID, "clean")
    assert r.exit_code == 0
    assert len(EvidenceStore(paths).list_evidence(f"{SID}_clean")) == 12
    assert len(Ledger(paths).read_all()) == n_ledger  # nothing re-logged on a rerun
    actions = [e.action for e in Ledger(paths).read_all()]
    assert actions.count("case_create") == 2
    assert Ledger(paths).verify().ok
    assert cli(base, "verify-evidence").exit_code == 0


def test_build_refuses_drifted_dataset(env):
    base, ddir = env
    (ddir / "s2.evtx").write_bytes(b"changed")
    r = cli(base, "scenario-build", SID, "clean")
    assert r.exit_code == 1 and "drift" in r.output.lower()
    assert EvidenceStore(get_paths(base_dir=base)).get_case(f"{SID}_clean") is None


# ---- real dataset ------------------------------------------------------------------------
REAL_SCN = Path(__file__).resolve().parents[1] / "scenarios" / "credtheft_lateral_v4"


def _root():
    root = dataset_root(get_paths())
    if not root.is_dir():
        pytest.skip("data/downloads/EVTX-ATTACK-SAMPLES not present")
    return root


@pytest.mark.dataset
def test_real_dataset_hashes_match():
    scn = load_scenario(REAL_SCN / "scenario.yaml")
    assert verify_dataset(scn, _root()) == []


@pytest.mark.dataset
def test_real_inventory_matches_fresh_run():
    root = _root()
    scn = load_scenario(REAL_SCN / "scenario.yaml")
    inv = load_inventory(REAL_SCN / "inventory.json")
    assert len(inv.sources) == 7 and not any(s.corrupt_records for s in inv.sources)
    for key in ("s1_lsass_mimikatz", "s5_dcsync", "s4_renamed_psexec"):
        spec = scn.source(key)
        fresh, _ = inventory_file(key, spec.relative_path, spec.sha256, root / spec.relative_path)
        assert json.loads(fresh.model_dump_json()) == json.loads(inv.source(key).model_dump_json())


@pytest.mark.dataset
def test_real_scenario_verify_passes():
    assert build.verify_scenario(get_paths(), "credtheft_lateral_v4") == []
