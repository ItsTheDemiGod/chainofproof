"""Integration on the REAL dataset and the real Hayabusa (skips cleanly when either is missing)."""

import pytest

from chainofproof.config import ToolsSettings, get_paths, load_settings
from chainofproof.custody.ledger import Ledger
from chainofproof.eval.baseline import compute_baseline
from chainofproof.eval.coverage import run_coverage
from chainofproof.ingest.store import EvidenceStore
from chainofproof.scenarios import build
from chainofproof.scenarios.dataset import dataset_root
from chainofproof.schemas.scenario import Variant
from chainofproof.tools.case_run import normalize_case
from chainofproof.tools.hayabusa import run_hayabusa
from chainofproof.tools.hayabusa_fp import locate_exe
from leakage import scan

SID = "credtheft_lateral_v4"
pytestmark = pytest.mark.dataset


@pytest.fixture(scope="module")
def real(tmp_path_factory):
    root = dataset_root(get_paths())
    cfg: ToolsSettings = load_settings().tools
    if not root.is_dir():
        pytest.skip("data/downloads/EVTX-ATTACK-SAMPLES not present")
    try:
        locate_exe(cfg)
    except Exception:
        pytest.skip("Hayabusa binary not present")
    mp = pytest.MonkeyPatch()
    mp.setenv("CHAINOFPROOF_DATASET_DIR", str(root))
    paths = get_paths(base_dir=tmp_path_factory.mktemp("real") / "base")
    paths.ensure_dirs()
    reports = {}
    for v in Variant:
        case, _ = build.build_case(paths, SID, v)
        reports[case] = normalize_case(paths, case, cfg)
    yield paths, reports
    mp.undo()


def test_hayabusa_on_s1_and_a_decoy_is_ledgered_and_parses(real):
    paths, _ = real
    cfg = load_settings().tools
    items = {i.original_name: i for i in EvidenceStore(paths).list_evidence(f"{SID}_clean")}
    s1 = items["sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx"]
    res = run_hayabusa(paths, s1.evidence_id, cfg)
    assert res.unparseable == 0 and res.lines == len(res.detections) >= 1
    assert all(d.level and d.rule_title and d.record_id for d in res.detections)
    decoy = items["sysmon_13_1_persistence_via_winlogon_shell.evtx"]
    assert run_hayabusa(paths, decoy.evidence_id, cfg).unparseable == 0
    runs = [
        e for e in Ledger(paths).read_all() if e.actor == "hayabusa" and e.action == "tool_call"
    ]
    assert len(runs) >= 2 and all(e.output_hash and e.input_hashes for e in runs)
    assert Ledger(paths).verify().ok


def test_corrupt_records_zero_and_all_evidence_normalized(real):
    _, reports = real
    for rows in reports.values():
        assert len(rows) == 13 and sum(r.corrupt for r in rows) == 0
        assert all(r.events > 0 for r in rows)
        assert sum(r.unlinked for r in rows) == 0


@pytest.mark.parametrize("variant", list(Variant))
def test_key_coverage_counts_alignment_and_perturbations(real, variant):
    paths, _ = real
    rep, idx, key, adj, scn = run_coverage(paths, f"{SID}_{variant.value}")
    assert rep.unresolved == [] and rep.count_mismatches == []
    assert rep.alignment_problems == [] and rep.alignment_checked >= 7
    assert all(v == "ok" for v in rep.perturbations.values())
    assert len(rep.perturbations) == (3 if variant == Variant.perturbed else 0)
    rows = compute_baseline(paths, f"{SID}_{variant.value}", idx, key, adj, scn)
    assert {r.kind for r in rows} == {"GT-ACT", "GT-ADJ"}


@pytest.mark.parametrize("variant", list(Variant))
def test_no_leakage_in_real_agent_view_dump(real, variant):
    paths, _ = real
    from chainofproof.scenarios.source_map import load_case_scenario

    scn, _ = load_case_scenario(f"{SID}_{variant.value}")
    rep = scan(paths, f"{SID}_{variant.value}", [s.source_key for s in scn.sources])
    assert rep.strict == [], rep.strict[:5]
    print(f"\n{variant.value}: free-text real-computer-name hits={rep.free_text_computer_names} "
          f"old-date hits={rep.free_text_old_dates} samples={rep.samples}")  # fmt: skip


@pytest.mark.parametrize("variant", list(Variant))
def test_every_registered_tool_is_leak_free_on_the_real_cases(real, variant):
    import json

    from chainofproof.scenarios.source_map import load_case_scenario
    from chainofproof.tools.detectors import DETECTORS
    from chainofproof.tools.registry import call_tool
    from leakage import scan_tool_output

    paths, _ = real
    case = f"{SID}_{variant.value}"
    scn, _ = load_case_scenario(case)
    names = []
    for rec in EvidenceStore(paths).list_evidence(case):
        names += [rec.original_name, rec.vault_path.replace("\\", "/").rsplit("/", 1)[-1]]
    keys = [s.source_key for s in scn.sources]
    labels = call_tool("planner", "list_evidence_labels", {}, paths, case)["labels"]
    page = call_tool("extractor", "search_events", {"limit": 50}, paths, case)
    uid = page["events"][0]["event_uid"]
    calls = [
        ("planner", "list_evidence_labels", {}),
        ("planner", "source_summary", {"evidence_label": labels[0]["label"]}),
        ("planner", "graph_stats", {}),
        ("extractor", "search_events", {"limit": 50}),
        ("extractor", "get_event", {"event_uid": uid}),
        ("extractor", "timeline_window", {"host": "DC-01", "start": "2024-03-12T00:00:00Z",
                                          "end": "2024-03-12T23:59:59Z"}),
        ("extractor", "get_detections", {"limit": 50}),
        ("correlator", "entity_summary", {"node_id": "host:SRV-FILE-02"}),
        ("correlator", "neighbors", {"node_id": "host:SRV-FILE-02", "limit": 50}),
        ("correlator", "find_paths", {"from_node": "host:WS-FIN-07", "to_node": "host:DC-01"}),
        ("correlator", "host_links", {}),
        *[("correlator", f"detect_{n}", {}) for n in DETECTORS],
        ("reporter", "get_hits", {"limit": 50}),
    ]  # fmt: skip
    for role, tool, args in calls:
        result = call_tool(role, tool, args, paths, case)
        assert json.dumps(result)
        assert scan_tool_output(result, names, keys) == [], tool
