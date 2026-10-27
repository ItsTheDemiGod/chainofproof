"""Seed-scoped scenario build (Phase 5.1): paths, case ids, base seed untouched, invariants."""

import shutil

import pytest
from typer.testing import CliRunner

from chainofproof.cli import app
from chainofproof.config import get_paths
from chainofproof.custody.hashing import sha256_file, sha256_json
from chainofproof.ingest.store import EvidenceStore
from chainofproof.scenarios import build
from chainofproof.scenarios.dataset import generated_dir, key_file, scenario_dir
from chainofproof.scenarios.invariants import check_generated
from chainofproof.scenarios.source_map import (
    case_key_path,
    load_case_scenario,
    parse_case_id,
    resolve_source_keys,
)
from chainofproof.schemas.scenario import ScenarioError, Variant, load_key
from scenario_fixture import SID, build_fixture

runner = CliRunner()
BASE_SEED = 20240312
BASE_KEY_HASHES = {  # sha256 of generated_file_hashes in the committed base keys (Phase 4.1)
    "clean": "f9976ca5534af403ac21d86ae115136aee231020db26aebddef105928a4892f3",
    "perturbed": "572bf83ab0985eb0f84a4d3a4231c083f9cdc68ef81db269ac1444252e65ae5f",
}


@pytest.fixture
def env(tmp_path, monkeypatch):
    scn, inv, sroot, ddir = build_fixture(tmp_path)
    monkeypatch.setenv("CHAINOFPROOF_SCENARIOS_DIR", str(sroot))
    monkeypatch.setenv("CHAINOFPROOF_DATASET_DIR", str(ddir))
    monkeypatch.setenv("COLUMNS", "200")
    build.write_keys(SID)
    return get_paths(base_dir=tmp_path / "base")


def cli(paths, *args):
    return runner.invoke(app, ["--base-dir", str(paths.base_dir), *args])


def test_committed_base_v4_key_hashes_are_unchanged(v4):
    for v in Variant:
        assert v4.keys[v].seed == BASE_SEED
        assert sha256_json(v4.keys[v].generated_file_hashes) == BASE_KEY_HASHES[v.value]
        assert sha256_file(key_file("credtheft_lateral_v4", v.value)) == sha256_file(
            scenario_dir("credtheft_lateral_v4") / f"key_{v.value}.yaml"
        )


def test_generator_invariants_hold_on_the_committed_base_data(v4):
    assert check_generated(v4.dirs, v4.keys) == []


def test_an_invariant_violation_is_reported(v4, tmp_path):
    dirs = {v: tmp_path / v.value for v in Variant}
    for v in Variant:
        shutil.copytree(v4.dirs[v], dirs[v])
    f = dirs[Variant.clean] / "auth_dc_01.log"
    lines = f.read_text(encoding="utf-8").splitlines(keepends=True)
    drop = next(i for i, x in enumerate(lines) if "CONN_ACCEPTED" in x)
    f.write_text("".join(lines[:drop] + lines[drop + 1 :]), encoding="utf-8")
    problems = check_generated(dirs, v4.keys)
    assert any("clean G2" in p and "two ends" in p for p in problems)


def test_locations_and_case_ids_of_seed_cases():
    assert key_file("s", "clean").parts[-2:] == ("s", "key_clean.yaml")
    assert key_file("s", "clean", 301).parts[-4:] == ("s", "seeds", "301", "key_clean.yaml")
    from pathlib import Path

    g = generated_dir(get_paths(base_dir=Path("x")), "s", "clean", 301)
    assert g.parts[-3:] == ("s", "seed_301", "clean")
    assert generated_dir(get_paths(base_dir=Path("x")), "s", "clean").parts[-2:] == ("s", "clean")
    assert build.case_id_of("s", Variant.clean) == "s_clean"
    assert build.case_id_of("s", Variant.perturbed, 301) == "s_s301_perturbed"


def test_seed_keys_are_written_to_the_seed_folder_and_the_base_keys_are_untouched(env):
    before = {v: sha256_file(key_file(SID, v.value)) for v in Variant}
    paths = build.write_keys(SID, 9)
    assert [p.parent.name for p in paths] == ["9", "9"]
    assert {v: sha256_file(key_file(SID, v.value)) for v in Variant} == before
    scn, _ = load_case_scenario(f"{SID}_s9_clean")
    k = load_key(key_file(SID, "clean", 9), scn)
    base = load_key(key_file(SID, "clean"), load_case_scenario(f"{SID}_clean")[0])
    assert k.seed == 9 and base.seed != 9
    assert k.generated_file_hashes != base.generated_file_hashes  # another background


def test_generate_and_build_a_seed_case_end_to_end(env):
    paths = env
    build.write_keys(SID, 9)
    folder, _ = build.generate(paths, SID, Variant.clean, seed=9)
    assert folder == generated_dir(paths, SID, "clean", 9) and folder.is_dir()
    case_id, items = build.build_case(paths, SID, Variant.clean, seed=9)
    assert case_id == f"{SID}_s9_clean" and len(items) == 12
    base_id, _ = build.build_case(paths, SID, Variant.clean)
    assert base_id == f"{SID}_clean"
    assert parse_case_id(case_id) == (SID, 9, Variant.clean)
    assert case_key_path(case_id) == key_file(SID, "clean", 9)
    keys = resolve_source_keys(paths, case_id)  # seed hashes resolve through the seed key
    assert len(keys) == 12
    assert build.build_case(paths, SID, Variant.clean, seed=9)[0] == case_id  # idempotent


def test_building_a_seed_case_into_another_seeds_case_id_is_refused(env):
    paths = env
    build.write_keys(SID, 9)
    EvidenceStore(paths).create_case(f"{SID}_s9_clean", "t", f"{SID} (clean) seed 8")
    with pytest.raises(ScenarioError, match="another scenario or seed"):
        build.build_case(paths, SID, Variant.clean, seed=9)
    # and a base case cannot be filled with a seed's evidence either
    EvidenceStore(paths).create_case(f"{SID}_perturbed", "t", f"{SID} (perturbed) seed 9")
    with pytest.raises(ScenarioError, match="another scenario or seed"):
        build.build_case(paths, SID, Variant.perturbed)


def test_cli_seed_options_and_verify(env):
    paths = env
    r = cli(paths, "scenario-keys", SID, "--seed", "9")
    assert r.exit_code == 0 and "wrote 9/key_clean.yaml" in r.output
    r = cli(paths, "scenario-generate", SID, "clean", "--seed", "9")
    assert r.exit_code == 0 and (generated_dir(paths, SID, "clean", 9) / "auth_dc_01.log").is_file()
    r = cli(paths, "scenario-build", SID, "perturbed", "--seed", "9")
    assert r.exit_code == 0 and f"case {SID}_s9_perturbed" in r.output
    assert cli(paths, "scenario-verify", SID).exit_code == 0  # base seed: unchanged behaviour
    r = cli(paths, "scenario-verify", SID, "--seed", "77")  # no keys for this seed
    assert r.exit_code == 1 and "seed 77: FAILED" in r.output and "missing" in r.output
    r = cli(paths, "scenario-verify", SID, "--seed", "9")
    assert "seed 9" in r.output
    problems = build.verify_scenario(paths, SID, 9)
    other = [p for p in problems if not any(f" G{n}:" in p or f"G{n}:" in p for n in range(1, 6))]
    assert (
        other == []
    )  # determinism, keys, collateral and adjudication hold; only invariants may differ
