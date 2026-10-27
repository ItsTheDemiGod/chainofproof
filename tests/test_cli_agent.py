"""Phase 5 CLI: agent-run, agent-runs, findings-show, agent-trace, agent-replay, llm-check, peek."""

import json
import shutil

import pytest
from typer.testing import CliRunner

from agent_helpers import PERT, events, happy_script
from chainofproof import cli_agent
from chainofproof.cli import app
from chainofproof.llm.ollama_client import OllamaClient

runner = CliRunner()


@pytest.fixture
def base(synth_norm, tmp_path):
    """A private copy of the normalized synthetic database (the CLI mutates it)."""
    paths, _ = synth_norm
    dest = tmp_path / "base"
    shutil.copytree(paths.base_dir, dest)
    return dest


def invoke(base, *args, env=None):
    env = {"COLUMNS": "260", **(env or {})}  # wide terminal: rich tables do not truncate cells
    return runner.invoke(app, ["--base-dir", str(base), *args], env=env)


def script_file(tmp_path, script):
    f = tmp_path / "script.json"
    f.write_text(json.dumps(script), encoding="utf-8")
    return f


def run_id_of(result):
    return result.output.split(":")[0].strip()


def test_agent_run_runs_list_findings_trace_and_replay_end_to_end(base, synth_norm, tmp_path):
    paths, _ = synth_norm
    e = events(paths, PERT, 1)[0]
    f = script_file(tmp_path, happy_script(e))
    r = invoke(base, "agent-run", PERT, "--llm", f"fake:{f}")
    assert r.exit_code == 0, r.output
    run_id = run_id_of(r)
    assert run_id.startswith("RUN-") and "completed (planner_finish)" in r.output
    assert "'verified': 1" in r.output and "llm calls 5" in r.output
    r = invoke(base, "agent-runs", "--case", PERT)
    assert r.exit_code == 0 and run_id in r.output and "completed" in r.output
    r = invoke(base, "findings-show", run_id)
    assert r.exit_code == 0 and "FND-" in r.output and "verified" in r.output
    assert "MODEL TEXT" in r.output
    assert invoke(base, "findings-show", run_id, "--status", "rejected").output.count("FND-") == 0
    r = invoke(base, "agent-trace", run_id, "--limit", "100")
    assert r.exit_code == 0 and "search_events" in r.output and "finding" in r.output
    assert "look at the first source" not in r.output  # no model text in the trace summary
    r = invoke(base, "agent-replay", run_id)
    assert r.exit_code == 0 and "replay OK" in r.output
    assert invoke(base, "ledger-verify").exit_code == 0


def test_findings_show_prints_claims_only_in_a_capped_labeled_column(base, tmp_path, synth_norm):
    paths, _ = synth_norm
    e = events(paths, PERT, 1)[0]
    d = {"claim": ("word " * 70).strip(), "claim_type": "observation", "hosts": [e["host"]],
         "cited_event_uids": [e["event_uid"]]}  # fmt: skip
    script = [{"rationale": "r", "action": "delegate", "worker_role": "extractor", "task": "t"},
              {"rationale": "r", "action": "record_finding", "finding": d},
              {"rationale": "r", "action": "finish", "handoff": "h"},
              {"rationale": "r", "action": "finish"}]  # fmt: skip
    r = invoke(base, "agent-run", PERT, "--llm", f"fake:{script_file(tmp_path, script)}")
    out = invoke(base, "findings-show", run_id_of(r)).output
    assert "MODEL TEXT" in out
    assert " ".join(out.split()).count("word") <= 24  # at most 120 characters of the claim


def test_agent_run_exit_codes_and_clean_errors(base, tmp_path):
    bad = script_file(tmp_path, ["bad"] * 12)
    r = invoke(base, "agent-run", PERT, "--llm", f"fake:{bad}")
    assert r.exit_code == 1 and "failed (consecutive_failures)" in r.output
    r = invoke(base, "agent-run", "no_such_case", "--llm", f"fake:{script_file(tmp_path, [])}")
    assert r.exit_code == 1 and "error:" in r.output and "Traceback" not in r.output
    r = invoke(base, "agent-run", PERT, "--llm", "bogus")
    assert r.exit_code == 1 and "--llm must be" in r.output
    assert invoke(base, "agent-trace", "RUN-999999").exit_code != 0
    r = invoke(base, "agent-replay", "RUN-999999")
    assert r.exit_code == 1 and "unknown agent run" in r.output


def test_agent_run_honours_max_rounds_and_budget_exhaustion_exits_zero(base, tmp_path):
    loop = [{"rationale": "r", "action": "delegate", "worker_role": "extractor", "task": "t"},
            {"rationale": "r", "action": "finish", "handoff": "h"}] * 3  # fmt: skip
    f = script_file(tmp_path, loop)
    r = invoke(base, "agent-run", PERT, "--max-rounds", "2", "--llm", f"fake:{f}")
    assert r.exit_code == 0 and "budget_exhausted (planner_max_rounds)" in r.output


def test_llm_check_with_a_fake_transport(monkeypatch, base):
    monkeypatch.setattr(cli_agent, "installed_models", lambda host: {"qwen2.5:7b-instruct"})
    seen = []

    def transport(req):
        seen.append(req)
        return {"message": {"content": '{"status":"ok"}'}, "prompt_eval_count": 12,
                "eval_count": 6}  # fmt: skip

    def factory(spec, s, model=None):
        return OllamaClient(
            "http://x", "qwen2.5:7b-instruct", s.ollama.num_ctx, 42, transport=transport,
            ps=lambda: {"models": [{"model": "qwen2.5:7b-instruct", "context_length": 8192}]},
        )  # fmt: skip

    monkeypatch.setattr(cli_agent, "make_client", factory)
    r = invoke(base, "llm-check")
    assert r.exit_code == 0, r.output
    assert "present" in r.output and "structured call OK" in r.output
    assert "loaded context reported by server: 8192" in r.output and seen[0]["options"]["num_ctx"]


def test_llm_check_reports_a_missing_model_and_an_unreachable_server(monkeypatch, base):
    monkeypatch.setattr(cli_agent, "installed_models", lambda host: {"other:1b"})
    r = invoke(base, "llm-check")
    assert r.exit_code == 1 and "MISSING" in r.output and "never pulls" in r.output
    monkeypatch.undo()
    r = invoke(base, "llm-check", env={"OLLAMA_HOST": "http://127.0.0.1:9"})
    assert r.exit_code == 1 and "cannot reach Ollama" in r.output


def test_agent_peek_is_labeled_preliminary_and_lists_key_items(base, synth_norm, tmp_path):
    paths, _ = synth_norm
    e = events(paths, PERT, 1)[0]
    f = script_file(tmp_path, happy_script(e))
    run_id = run_id_of(invoke(base, "agent-run", PERT, "--llm", f"fake:{f}"))
    r = invoke(base, "agent-peek", run_id)
    assert r.exit_code == 0, r.output
    assert "PRELIMINARY" in r.output and "GT-ACT-001" in r.output and "GT-CON-001" in r.output
    assert "detector tools the agent chose to run: none" in r.output
