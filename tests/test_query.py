"""Agent-facing query API: bounds, filters, no eval fields; leakage and import boundary."""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from chainofproof.eval.gt_link import build_index, key_action_refs, resolve_ref
from chainofproof.tools import query
from leakage import scan

SRC = Path(__file__).resolve().parents[1] / "src" / "chainofproof"
CLEAN, PERT = "credtheft_lateral_v3_clean", "credtheft_lateral_v3_perturbed"


def test_limit_defaults_and_hard_maximum(synth_norm):
    paths, _ = synth_norm
    page = query.search_events(paths, CLEAN)
    assert page.returned == 25 and page.total_matches > 25 and page.truncated
    big = query.search_events(paths, CLEAN, limit=10_000)
    assert big.returned == 50 and big.truncated
    assert query.search_events(paths, CLEAN, limit=0).returned == 1
    host = query.search_events(paths, CLEAN, host="DC-01", limit=50)
    assert host.total_matches > 50 and all(e.host == "DC-01" for e in host.events)
    last = query.search_events(paths, CLEAN, host="DC-01", limit=50, offset=host.total_matches - 3)
    assert last.returned == 3 and not last.truncated


def test_filters_and_ordering(synth_norm):
    paths, _ = synth_norm
    page = query.search_events(paths, CLEAN, event_type="auth_conn", limit=50)
    assert page.total_matches == 3 and {e.conn_id for e in page.events} == {"CONN-001", "CONN-002"}
    stamps = [e.timestamp for e in page.events]
    assert stamps == sorted(stamps)
    one = query.search_events(paths, CLEAN, conn_id="CONN-001", event_type="auth_logon")
    assert one.total_matches == 1 and one.events[0].user == "user01"
    assert query.get_event(paths, CLEAN, one.events[0].event_uid) == one.events[0]
    assert query.get_event(paths, CLEAN, "EVT-000000000000") is None
    t = one.events[0].timestamp
    win = query.timeline_window(paths, CLEAN, "SRV-FILE-02", t, t)
    assert win.total_matches >= 1 and all(e.timestamp == t for e in win.events)
    txt = query.search_events(paths, CLEAN, text="CONN-002", limit=50)
    assert txt.total_matches >= 2
    assert query.search_events(paths, CLEAN, text="100%_[x]").total_matches == 0  # wildcards inert


def test_bad_arguments(synth_norm):
    paths, _ = synth_norm
    with pytest.raises(query.QueryError):
        query.search_events(paths, CLEAN, time_from="yesterday")
    with pytest.raises(query.QueryError):
        query.search_events(paths, CLEAN, text="x" * 101)
    with pytest.raises(query.QueryError):
        query.source_summary(paths, CLEAN, "AUTH-000000")


def test_labels_summary_detections(synth_norm):
    paths, _ = synth_norm
    labels = query.list_evidence_labels(paths, CLEAN)
    assert len(labels) == 6 and sum(li.event_count for li in labels) > 1500
    for li in labels:
        assert (
            re.fullmatch(r"(FSTL|AUTH)-[0-9a-f]{6}", li.label) and li.hosts and li.first_timestamp
        )
        s = query.source_summary(paths, CLEAN, li.label)
        assert s.event_count == li.event_count and sum(s.by_event_type.values()) == li.event_count
    d = query.get_detections(paths, CLEAN)
    assert (d.total_matches, d.returned, d.truncated) == (0, 0, False)
    assert query.list_evidence_labels(paths, "no_such_case") == []


def test_query_results_never_carry_eval_fields(synth_norm):
    paths, _ = synth_norm
    blob = " ".join(
        query.search_events(paths, c, limit=50).model_dump_json() for c in (CLEAN, PERT)
    ) + " ".join(li.model_dump_json() for li in query.list_evidence_labels(paths, CLEAN))
    for bad in ("source_key", "synth_only", "pair_field", "pair=", "is_synthetic", "raw_note",
                "real_timestamp", "real_computer", "locator", "evidence_id",
                "original_name"):  # fmt: skip
        assert bad not in blob


@pytest.mark.parametrize("case", [CLEAN, PERT])
def test_no_leakage_in_full_agent_view_dump(synth_norm, v3, case):
    paths, _ = synth_norm
    rep = scan(paths, case, [s.source_key for s in v3.scn.sources])
    assert rep.rows > 1000 and rep.strict == []


# ---- import boundary ------------------------------------------------------------------------
FORBIDDEN = re.compile(
    r"chainofproof\.eval|chainofproof\.scenarios|schemas\.groundtruth|schemas\.adjudication"
    r"|event_eval_meta|meta_store|from chainofproof import .*\b(eval|scenarios)\b"
)


def agent_side_files():
    files = [SRC / "tools" / "query.py"]
    for pkg in ("agents", "report", "ui", "llm", "security"):
        files += sorted((SRC / pkg).rglob("*.py")) if (SRC / pkg).is_dir() else []
    return files


@pytest.mark.parametrize("path", agent_side_files(), ids=lambda p: p.relative_to(SRC).as_posix())
def test_agent_side_source_has_no_forbidden_imports(path):
    assert FORBIDDEN.findall(path.read_text(encoding="utf-8")) == []


def test_query_module_does_not_load_eval_or_scenarios_at_import_time():
    code = (
        "import sys, chainofproof.tools.query; "
        "pre = ('chainofproof.eval', 'chainofproof.scenarios'); "
        "bad = [m for m in sys.modules if m.startswith(pre)]; "
        "print(json.dumps(bad))"
    )
    out = subprocess.run(
        [sys.executable, "-c", "import json; " + code], capture_output=True, text=True
    )
    assert out.returncode == 0 and json.loads(out.stdout) == []


# ---- gt_link on the synthetic sources ----------------------------------------------------------
def test_gt_link_resolves_synthetic_key_refs(synth_norm, v3):
    paths, _ = synth_norm
    from chainofproof.schemas.scenario import Variant

    for variant, case in ((Variant.clean, CLEAN), (Variant.perturbed, PERT)):
        idx, key = build_index(paths, case), v3.keys[variant]
        synthetic = {s.source_key for s in v3.scn.sources if s.is_synthetic}
        refs = [(o, r) for o, r in key_action_refs(key) if r.source_key in synthetic]
        assert refs and all(resolve_ref(idx, r) for _, r in refs)
        for ln in key.links:
            for r in ln.evidence_refs:
                if r.source_key in synthetic:
                    assert resolve_ref(idx, r, r.conn_id), ln.id
        wrong = [u for _, r in refs[:1] for u in resolve_ref(idx, r, "CONN-999")]
        assert wrong == []
