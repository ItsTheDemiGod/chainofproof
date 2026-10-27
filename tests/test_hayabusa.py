"""Hayabusa wrapper against a FAKE executable (a .cmd shim that runs a tiny Python script)."""

import sys
from pathlib import Path

import pytest

from chainofproof.config import ToolsSettings
from chainofproof.custody.hashing import sha256_file
from chainofproof.custody.ledger import Ledger
from chainofproof.ingest.ingest import ingest_evidence
from chainofproof.ingest.store import EvidenceStore
from chainofproof.tools.hayabusa import build_args, parse_detection, run_hayabusa
from chainofproof.tools.hayabusa_fp import HayabusaError, hayabusa_fingerprint, locate_exe

FAKE = r"""
import json, os, sys, time
a = sys.argv[1:]
if a and a[0] == "help":
    print("Hayabusa v9.9.9 - Fake")
    sys.exit(0)
mode = os.environ.get("FAKE_MODE", "ok")
out = a[a.index("-o") + 1]
if mode == "fail":
    sys.exit(3)
if mode == "slow":
    time.sleep(3)
if mode == "empty":
    sys.exit(0)  # no output file at all: no rule matched
good = {"Timestamp": "2019-03-17T19:37:11.661930Z", "RuleTitle": "Proc \x1b[31mAccess\x1b[0m",
        "Level": "low", "Computer": "PC04.example.corp", "Channel": "Sysmon", "EventID": 10,
        "MitreTags": "T1003.001 ¦ T1059", "RecordID": 4807, "RuleID": "abc"}
with open(out, "w", encoding="utf-8") as f:
    f.write(json.dumps(good) + "\n")
    f.write("this is not json\n")
    f.write(json.dumps({"Level": "high"}) + "\n")
    f.write(json.dumps({**good, "RuleTitle": "Second", "MitreTags": ["T1", "T2"],
                        "RecordID": "7"}) + "\n")
"""


@pytest.fixture
def fake(paths, tmp_path, monkeypatch):
    hb = tmp_path / "hb"
    hb.mkdir()
    script = hb / "fake_hayabusa.py"
    script.write_text(FAKE, encoding="utf-8")
    (hb / "hayabusa-fake.cmd").write_text(f'@"{sys.executable}" "{script}" %*\r\n')
    cfg = ToolsSettings(hayabusa_dir=hb, timeout_seconds=1, exe_glob="hayabusa*.cmd")
    store = EvidenceStore(paths)
    store.create_case("C1")
    src = tmp_path / "in" / "log.evtx"
    src.parent.mkdir()
    src.write_bytes(b"not a real evtx; the fake exe never reads it")
    rec = ingest_evidence(paths, "C1", src)
    return cfg, rec


def entries(paths, action="tool_call"):
    return [e for e in Ledger(paths).read_all() if e.action == action and e.actor == "hayabusa"]


def test_success_parses_sanitizes_and_ledgers(paths, fake, monkeypatch):
    cfg, rec = fake
    monkeypatch.setenv("FAKE_MODE", "ok")
    res = run_hayabusa(paths, rec.evidence_id, cfg)
    assert (res.lines, res.unparseable, len(res.detections)) == (4, 2, 2)
    d = res.detections[0]
    assert d.rule_title == "Proc Access" and d.mitre_tags == ["T1003.001", "T1059"]
    assert (d.record_id, d.channel, d.level) == (4807, "Sysmon", "low")
    assert res.detections[1].record_id == 7 and res.detections[1].mitre_tags == ["T1", "T2"]
    assert res.output_path.parent == paths.runs_dir / res.run_id
    assert res.fingerprint.version == "9.9.9"
    (e,) = entries(paths)
    work = next((paths.evidence_working / "C1").iterdir())
    assert e.input_hashes == [sha256_file(work)]
    assert e.output_hash == sha256_file(res.output_path)
    assert e.details["lines"] == 4 and e.details["unparseable"] == 2 and "duration_s" in e.details
    assert entries(paths, "tool_fingerprint")  # fingerprint recorded the first time it is used
    assert Ledger(paths).verify().ok


def test_command_is_project_relative_and_reads_only_working_copy(paths, fake, monkeypatch):
    cfg, rec = fake
    monkeypatch.setenv("FAKE_MODE", "ok")
    run_hayabusa(paths, rec.evidence_id, cfg)
    cmd = entries(paths)[0].command
    assert Path.home().name.lower() not in cmd.lower() and ":\\" not in cmd and ":/" not in cmd
    assert "evidence_working" in cmd and "evidence_raw" not in cmd
    assert "dfir-timeline" in cmd and "-t jsonl" in cmd and "-p verbose" in cmd


def test_empty_output_is_not_an_error(paths, fake, monkeypatch):
    cfg, rec = fake
    monkeypatch.setenv("FAKE_MODE", "empty")
    res = run_hayabusa(paths, rec.evidence_id, cfg)
    assert res.detections == [] and res.lines == 0 and res.output_path.read_bytes() == b""


def test_nonzero_exit_is_an_error_and_ledgered(paths, fake, monkeypatch):
    cfg, rec = fake
    monkeypatch.setenv("FAKE_MODE", "fail")
    with pytest.raises(HayabusaError, match="code 3"):
        run_hayabusa(paths, rec.evidence_id, cfg)
    assert entries(paths, "tool_call_failed")[0].details["error_type"] == "HayabusaError"


def test_timeout(paths, fake, monkeypatch):
    cfg, rec = fake
    monkeypatch.setenv("FAKE_MODE", "slow")
    with pytest.raises(HayabusaError, match="timed out"):
        run_hayabusa(paths, rec.evidence_id, cfg)


def test_missing_or_ambiguous_exe(paths, fake, tmp_path):
    cfg, rec = fake
    empty = tmp_path / "none"
    empty.mkdir()
    with pytest.raises(HayabusaError, match="not found"):
        run_hayabusa(paths, rec.evidence_id, cfg.model_copy(update={"hayabusa_dir": empty}))
    (Path(cfg.hayabusa_dir) / "hayabusa-other.cmd").write_text("@echo off\r\n")
    with pytest.raises(HayabusaError, match="expected exactly one"):
        locate_exe(cfg)


def test_unknown_evidence(paths, fake):
    with pytest.raises(HayabusaError, match="unknown evidence"):
        run_hayabusa(paths, "EV-999999", fake[0])


def test_runs_get_sequential_ids_and_are_never_overwritten(paths, fake, monkeypatch):
    cfg, rec = fake
    monkeypatch.setenv("FAKE_MODE", "ok")
    a, b = (run_hayabusa(paths, rec.evidence_id, cfg) for _ in range(2))
    assert (a.run_id, b.run_id) == ("RUN-000001", "RUN-000002")
    assert a.output_path.exists() and b.output_path.exists()


def test_fingerprint_with_rules_tree(fake):
    cfg, _ = fake
    rules = Path(cfg.hayabusa_dir) / "rules"
    (rules / "sub").mkdir(parents=True)
    (rules / "sub" / "a.yml").write_text("x")
    (rules / ".git").mkdir()
    (rules / ".git" / "HEAD").write_text("ignored")
    from chainofproof.tools import hayabusa_fp

    hayabusa_fp._CACHE.clear()
    h1 = hayabusa_fingerprint(cfg).rules_tree_sha256
    hayabusa_fp._CACHE.clear()
    (rules / ".git" / "HEAD").write_text("changed")
    assert hayabusa_fingerprint(cfg).rules_tree_sha256 == h1  # .git is not part of the tree hash
    hayabusa_fp._CACHE.clear()
    (rules / "sub" / "a.yml").write_text("y")
    assert hayabusa_fingerprint(cfg).rules_tree_sha256 != h1


def test_parse_detection_requires_title_and_level():
    assert parse_detection({"RuleTitle": "t"}) is None and parse_detection([]) is None
    assert parse_detection({"RuleTitle": "t", "Level": "high"}).record_id is None


def test_build_args_is_fixed_list_without_network_or_shell_flags():
    args = build_args(Path("x.exe"), Path("w.evtx"), Path("o.jsonl"))
    assert args[:2] == ["x.exe", "dfir-timeline"] and "update-rules" not in args
    assert args[args.index("-r") + 1] == "rules" and args[args.index("-t") + 1] == "jsonl"
