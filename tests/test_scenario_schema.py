import pytest
import yaml

from chainofproof.scenarios import build
from chainofproof.schemas.scenario import (
    AnswerKey,
    ScenarioError,
    load_key,
    load_scenario,
    save_key,
)
from scenario_fixture import SID, build_fixture


@pytest.fixture
def fx(tmp_path, monkeypatch):
    scn, inv, sroot, ddir = build_fixture(tmp_path)
    monkeypatch.setenv("CHAINOFPROOF_SCENARIOS_DIR", str(sroot))
    monkeypatch.setenv("CHAINOFPROOF_DATASET_DIR", str(ddir))
    build.write_keys(SID)
    return scn, inv, sroot / SID


def test_valid_key_loads(fx):
    scn, _, d = fx
    key = load_key(d / "key_perturbed.yaml", scn)
    assert key.variant == "perturbed" and key.actions and len(key.contradictions) == 3
    assert load_key(d / "key_clean.yaml", scn).contradictions == []
    assert load_scenario(d / "scenario.yaml").scenario_id == SID


def _mutated(fx, tmp_path, fn):
    _, _, d = fx
    data = yaml.safe_load((d / "key_clean.yaml").read_text(encoding="utf-8"))
    fn(data)
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return p


def test_duplicate_ids_rejected(fx, tmp_path):
    p = _mutated(fx, tmp_path, lambda k: k["actions"].append(dict(k["actions"][0])))
    with pytest.raises(ScenarioError, match="duplicate"):
        load_key(p)


def test_undeclared_source_rejected(fx, tmp_path):
    scn = fx[0]
    p = _mutated(
        fx, tmp_path, lambda k: k["actions"][0]["supporting_refs"][0].update(source_key="nope")
    )
    load_key(p)  # structurally valid on its own
    with pytest.raises(ScenarioError, match="undeclared source"):
        load_key(p, scn)


@pytest.mark.parametrize(
    "path,value",
    [
        ("id", "GT-ACT-1"),
        ("stage_id", "X9"),
        ("attack_technique_id", "1003"),
        ("virtual_time", "2024-03-12 09:00:00"),
    ],
)
def test_bad_patterns_rejected(fx, tmp_path, path, value):
    p = _mutated(fx, tmp_path, lambda k: k["actions"][0].update({path: value}))
    with pytest.raises(ScenarioError):
        load_key(p)


def test_bad_decoy_and_missing_ids_rejected(fx, tmp_path):
    p = _mutated(fx, tmp_path, lambda k: k["missing_evidence"][0].update(id="GT-MIS-X"))
    with pytest.raises(ScenarioError):
        load_key(p)


def test_scenario_validators(fx, tmp_path):
    _, _, d = fx
    data = yaml.safe_load((d / "scenario.yaml").read_text(encoding="utf-8"))
    data["sources"][1]["source_key"] = data["sources"][0]["source_key"]
    p = tmp_path / "s.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(ScenarioError):
        load_scenario(p)
    data = yaml.safe_load((d / "scenario.yaml").read_text(encoding="utf-8"))
    data["alignment"] = data["alignment"][:-1]
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(ScenarioError, match="alignment"):
        load_scenario(p)


def test_key_round_trip_is_deterministic(fx, tmp_path):
    scn, _, d = fx
    key = load_key(d / "key_perturbed.yaml", scn)
    save_key(tmp_path / "again.yaml", key)
    assert (tmp_path / "again.yaml").read_bytes() == (d / "key_perturbed.yaml").read_bytes()
    assert isinstance(key, AnswerKey)
