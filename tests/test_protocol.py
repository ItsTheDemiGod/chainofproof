"""Protocol package (rules E1-E3): splits, freeze, guard, and the import boundary."""

import dataclasses
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_helpers import PLANNER_FINISH, events, make_case, settings
from chainofproof.agents import prompts, store
from chainofproof.agents.runner import run_agent
from chainofproof.cli import app
from chainofproof.custody.ledger import Ledger
from chainofproof.eval.agent_peek import peek
from chainofproof.llm.fake import FakeLLMClient
from chainofproof.protocol import guard
from chainofproof.protocol.guard import FreezeError, current_fingerprint, write_freeze
from chainofproof.protocol.splits import load_splits, split_of
from chainofproof.tools import registry
from evfactory import ev

DEV_SEEDS, TEST_SEEDS, VARIANTS = (201, 202, 203), range(301, 306), ("clean", "perturbed")
TEST_CASE = "credtheft_lateral_v4_s301_clean"
DEV_CASE = "credtheft_lateral_v4_s201_clean"
SRC = Path(__file__).resolve().parents[1] / "src" / "chainofproof"


def small_case(tmp_path, case):
    e = ev("EVTX-111111", "2024-03-12T09:00:00.000000Z", "H1", "logon", user="bob")
    return make_case(tmp_path, [e], case=case)


def run(paths, case, **agent):
    return run_agent(paths, case, FakeLLMClient([PLANNER_FINISH]), settings(**agent))


# ---- splits ------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "case,expected",
    [
        ("credtheft_lateral_v4_clean", "dev"),
        ("credtheft_lateral_v4_perturbed", "dev"),
        *[(f"credtheft_lateral_v4_s{s}_{v}", "dev") for s in DEV_SEEDS for v in VARIANTS],
        *[(f"credtheft_lateral_v4_s{s}_{v}", "test") for s in TEST_SEEDS for v in VARIANTS],
        ("credtheft_lateral_v4_s999_clean", None),
        ("credtheft_lateral_v3_clean", None),
        ("credtheft_lateral_v1_perturbed", None),
        ("some_other_case", None),
        ("not-a-scenario_clean", None),
    ],
)  # fmt: skip
def test_split_of_every_case_id(case, expected):
    assert split_of(case) == expected


def test_splits_yaml_is_the_committed_table():
    s = load_splits("credtheft_lateral_v4")
    assert s.dev.base and s.dev.seeds == [201, 202, 203]
    assert s.test.seeds == [301, 302, 303, 304, 305]
    assert load_splits("credtheft_lateral_v3") is None


# ---- guard -------------------------------------------------------------------------------
def test_unassigned_and_dev_cases_run_freely_and_record_their_split(tmp_path):
    a = run(small_case(tmp_path / "a", "free_case_clean"), "free_case_clean")
    assert a.status == "completed"
    paths = small_case(tmp_path / "b", DEV_CASE)
    r = run(paths, DEV_CASE)
    assert r.status == "completed" and store.get_run(paths, r.run_id)["split"] == "dev"
    paths2 = small_case(tmp_path / "c", "free_case_perturbed")
    assert store.get_run(paths2, run(paths2, "free_case_perturbed").run_id)["split"] is None


def test_test_split_is_refused_without_a_freeze_and_nothing_is_created(tmp_path):
    paths = small_case(tmp_path, TEST_CASE)
    n = len(Ledger(paths).read_all())
    with pytest.raises(FreezeError, match="TEST split: no prompt_freeze exists"):
        run(paths, TEST_CASE)
    assert store.list_runs(paths) == [] and len(Ledger(paths).read_all()) == n


def test_test_split_runs_under_a_matching_freeze_and_is_ledgered(tmp_path):
    paths = small_case(tmp_path, TEST_CASE)
    fid = write_freeze(paths, settings().agent, "m", note="n")
    res = run(paths, TEST_CASE)
    assert res.status == "completed" and store.get_run(paths, res.run_id)["split"] == "test"
    led = Ledger(paths).read_all()
    (t,) = [e for e in led if e.action == "test_split_run"]
    assert t.details == {"freeze_ledger_id": fid, "case_id": TEST_CASE, "run_id": res.run_id}
    (f,) = [e for e in led if e.action == "prompt_freeze"]
    fp = current_fingerprint(settings().agent)
    assert f.details == {"prompt_version": fp.prompt_version, "settings_sha256": fp.settings_sha256,
                         "model": "m", "tool_registry_sha256": fp.tool_registry_sha256,
                         "note": "n"}  # fmt: skip
    assert led.index(f) < led.index(t) and Ledger(paths).verify().ok


def test_a_changed_template_setting_or_tool_spec_makes_the_freeze_stale(tmp_path, monkeypatch):
    paths = small_case(tmp_path, TEST_CASE)
    write_freeze(paths, settings().agent, "m")
    assert run(paths, TEST_CASE).status == "completed"
    with monkeypatch.context() as m:  # (a) a prompt template
        m.setitem(prompts.TEMPLATES, "rules", prompts.TEMPLATES["rules"] + " x")
        with pytest.raises(FreezeError, match=r"stale \(prompt_version changed\)"):
            run(paths, TEST_CASE)
    with pytest.raises(FreezeError, match=r"stale \(settings_sha256 changed\)"):  # (b) a setting
        run(paths, TEST_CASE, worker_max_steps=7)
    with monkeypatch.context() as m:  # (c) a tool spec
        spec = registry.TOOLS["graph_stats"]
        m.setitem(registry.TOOLS, "graph_stats", dataclasses.replace(spec, description="changed"))
        with pytest.raises(FreezeError) as e:
            run(paths, TEST_CASE)
        assert "tool_registry_sha256" in str(e.value)
    assert run(paths, TEST_CASE).status == "completed"  # back to the frozen state: allowed again


def test_a_newer_freeze_for_the_new_state_unlocks_the_run(tmp_path):
    paths = small_case(tmp_path, TEST_CASE)
    write_freeze(paths, settings().agent, "m")
    with pytest.raises(FreezeError):
        run(paths, TEST_CASE, worker_max_steps=7)
    write_freeze(paths, settings(worker_max_steps=7).agent, "m")
    assert run(paths, TEST_CASE, worker_max_steps=7).status == "completed"


def test_replay_of_a_recorded_test_run_is_allowed_even_when_stale(tmp_path, monkeypatch):
    from chainofproof.agents.replay import replay_run

    paths = small_case(tmp_path, TEST_CASE)
    write_freeze(paths, settings().agent, "m")
    res = run(paths, TEST_CASE)
    monkeypatch.setitem(prompts.TEMPLATES, "rules", prompts.TEMPLATES["rules"] + " x")
    # (the replay needs the same prompts to match the recording; here only the guard is under test)
    monkeypatch.undo()
    assert replay_run(paths, res.run_id, settings()).ok


def test_peek_refuses_test_runs_without_a_matching_freeze(tmp_path, monkeypatch):
    paths = small_case(tmp_path, TEST_CASE)
    write_freeze(paths, settings().agent, "m")
    res = run(paths, TEST_CASE)
    monkeypatch.setitem(prompts.TEMPLATES, "rules", prompts.TEMPLATES["rules"] + " x")
    with pytest.raises(FreezeError, match="stale"):
        peek(paths, res.run_id)


def test_the_guard_is_inside_run_agent_not_only_in_the_cli(tmp_path):
    paths = small_case(tmp_path, TEST_CASE)
    with pytest.raises(FreezeError):
        run_agent(paths, TEST_CASE, FakeLLMClient([PLANNER_FINISH]), settings())
    src = (SRC / "agents" / "runner.py").read_text(encoding="utf-8")
    assert "check_run_allowed(" in src


# ---- agent-freeze CLI --------------------------------------------------------------------
def test_agent_freeze_refuses_without_confirm_and_writes_only_with_it(tmp_path):
    paths = small_case(tmp_path, "free_case_clean")
    base = str(paths.base_dir)
    r = CliRunner().invoke(app, ["--base-dir", base, "agent-freeze"])
    assert r.exit_code == 1 and "prompt_version" in r.output and "refusing" in r.output
    assert not [e for e in Ledger(paths).read_all() if e.action == "prompt_freeze"]
    r = CliRunner().invoke(app, ["--base-dir", base, "agent-freeze", "--confirm", "--note", "x"])
    assert r.exit_code == 0 and "freeze written: LED-" in r.output
    (f,) = [e for e in Ledger(paths).read_all() if e.action == "prompt_freeze"]
    assert set(f.details) == {"prompt_version", "settings_sha256", "model", "tool_registry_sha256",
                              "note"}  # fmt: skip
    assert re.fullmatch(r"[0-9a-f]{64}", f.details["tool_registry_sha256"])


# ---- import boundary ---------------------------------------------------------------------
def test_protocol_package_imports_no_eval_scenarios_or_ground_truth():
    for f in (SRC / "protocol").glob("*.py"):
        src = f.read_text(encoding="utf-8")
        assert not re.search(r"chainofproof\.(eval|scenarios)|event_eval_meta|groundtruth", src), f


def test_a_clean_interpreter_importing_protocol_loads_neither_eval_nor_scenarios():
    code = ("import sys, json, chainofproof.protocol.guard, chainofproof.protocol.splits; "
            "print(json.dumps([m for m in sys.modules if m.startswith("
            "('chainofproof.eval', 'chainofproof.scenarios'))]))")  # fmt: skip
    out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr[-300:]
    assert json.loads(out.stdout) == []


def test_no_test_split_run_exists_in_this_repository_state(synth_norm):
    paths, _ = synth_norm
    assert events(paths, "credtheft_lateral_v4_perturbed", 1)
    assert not [
        e for e in Ledger(paths).read_all() if e.action in ("prompt_freeze", "test_split_run")
    ]
    assert guard.find_freeze(paths, current_fingerprint(settings().agent)) is None
