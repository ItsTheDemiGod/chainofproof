"""Style audit logic on small fixtures, plus the audit on the synthetic v3 sources."""

from chainofproof.eval.style_audit import (
    Audit,
    audit_case,
    audit_features,
    render,
    verdict,
)

CLEAN, PERT = "credtheft_lateral_v3_clean", "credtheft_lateral_v3_perturbed"


def rows(values, key="v"):
    return [{key: v} for v in values]


FEATS = {"tell": lambda r: r["v"], "shared": lambda r: r["w"]}


def test_verdict_rule():
    assert verdict(1.0) == "separates cleanly" and verdict(0.5) == "separates cleanly"
    assert verdict(0.49) == "weak" and verdict(0.01) == "weak" and verdict(0.0) == "none"


def test_a_feature_that_separates_and_one_that_does_not():
    ref = [{"v": "mimikatz", "w": "a"}, {"v": "psexec", "w": "b"}, {"v": "svchost", "w": "a"}]
    ben = [{"v": f"report{i}", "w": "a" if i % 2 else "b"} for i in range(20)] + [
        {"v": "svchost", "w": "c"}]  # fmt: skip
    got = {f.name: f for f in audit_features("k", FEATS, ref, ben)}
    assert got["tell"].verdict == "separates cleanly" and abs(got["tell"].coverage - 2 / 3) < 1e-9
    assert [v for v, _, _ in got["tell"].ref_only] == [
        "mimikatz",
        "psexec",
    ]  # svchost is not unique
    assert got["shared"].verdict == "none" and got["shared"].ref_only == []
    assert got["shared"].benign_only_values == 1


def test_weak_when_few_referenced_lines_are_unique():
    ref = [{"v": "x", "w": "a"}] + [{"v": "common", "w": "a"}] * 4
    ben = [{"v": "common", "w": "a"}] * 10
    f = audit_features("k", {"tell": lambda r: r["v"]}, ref, ben)[0]
    assert f.verdict == "weak" and f.coverage == 0.2


def test_audit_runs_on_the_synthetic_sources_and_renders(synth_norm):
    paths, _ = synth_norm
    audits = [audit_case(paths, c) for c in (CLEAN, PERT)]
    for a in audits:
        assert (
            isinstance(a, Audit) and a.counts["auth_log"][0] > 0 and a.counts["fs_timeline"][0] > 0
        )
        names = {(f.kind, f.name) for f in a.features}
        assert ("auth_log", "event") in names and ("fs_timeline", "name_stem") in names
        assert all(f.verdict in ("separates cleanly", "weak", "none") for f in a.features)
        # timestamps are not a tell: every second/minute value also occurs among benign lines
        by = {(f.kind, f.name): f.verdict for f in a.features}
        assert by[("auth_log", "zero_microseconds")] == "none"
    text = render(audits)
    assert "Recommended generator changes (NOT applied" in text and "| auth_log | event |" in text
    assert "synth_only" not in text and "pair=" not in text
