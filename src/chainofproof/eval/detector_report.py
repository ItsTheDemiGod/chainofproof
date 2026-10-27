"""EVALUATION ONLY: write docs/detector_baseline.md (the no-LLM deterministic baseline)."""

from __future__ import annotations

from pathlib import Path

from chainofproof.config import Paths
from chainofproof.eval.detector_eval import CaseEval, _brief
from chainofproof.eval.robustness import SeedRow, run_robustness

HEAD = """# Detector baseline (deterministic, no LLM)

All five detectors were run with their default parameters (`config/settings.yaml`, section
`detectors`, fixed before the first run) on the real v4 cases. A hit counts as *found* only under
the matching rules in `eval/detector_eval.py` (exact file set for timestomp, exact missing seq range
for the log gap, offset within 1 s of the key for clock skew). Unmatched-connection hits on benign
connections whose DC-01 end the gap removed are *explained collateral* (listed separately, not
counted as unexpected hits or in the precision denominator). Nothing was tuned.

"""


def _case_section(r: CaseEval) -> list[str]:
    n = sum(c.found for c in r.cons)
    lines = [f"## {r.case_id}", ""]
    if r.cons:
        lines += [f"Recall: **{n} of {len(r.cons)}** planted contradictions found.", "",
                  "| contradiction | kind | found | matching hits | measured | key |",
                  "|---|---|---|---|---|---|"]  # fmt: skip
        for c in r.cons:
            found = "yes" if c.found else "no"
            hits = ", ".join(c.hit_ids) or "-"
            lines.append(
                f"| {c.con_id} | {c.kind} | {found} | {hits} | {c.measured} | {c.key_value} |"
            )
    else:
        lines.append("This variant has no planted contradictions.")
    lines += ["", "Action indicators (not contradictions): "
              + (", ".join(f"{a} <- {h}" for a, h in r.indicators) or "none"), "",
              "| detector | matched / total hits |", "|---|---|"]  # fmt: skip
    lines += [f"| {d} | {m} / {t} |" for d, (m, t) in r.precision().items()]
    if r.collateral_ids:
        lines += ["", f"Explained collateral (unmatched_connection on benign connections broken by "
                  f"the gap): **{len(r.explained)} of {len(r.collateral_ids)}** expected conn_ids "
                  f"flagged ({', '.join(sorted(r.collateral_ids))}); missed: "
                  f"{', '.join(r.collateral_missed()) or 'none'}."]  # fmt: skip
    lines += ["", f"Unexpected hits: **{len(r.unexpected)}**", ""]
    if r.unexpected:
        lines += [
            "| hit | detector | kind | severity | hosts | measures |",
            "|---|---|---|---|---|---|",
        ]
        lines += [f"| {h.hit_id} | {h.detector} | {h.kind} | {h.severity} | {','.join(h.hosts)} "
                  f"| {_brief(h)} |" for h in r.unexpected]  # fmt: skip
    lines += ["", "Link check (unmatched_connection per conn_id of each GT-LNK):", ""]
    lines += [f"* {lid} {cid}: flagged = {fl}" for lid, cid, fl in r.link_flags] or ["* none"]
    return [*lines, ""]


def _robust_section(rows: list[SeedRow]) -> list[str]:
    lines = ["## Robustness across seeds", "",
             "Synthetic files regenerated into a temp folder per seed (nothing ingested), combined "
             "with the real EVTX events of the existing case, all detectors in memory.", "",
             "| variant | seed | found | explained collateral | unexpected hits |",
             "|---|---|---|---|---|"]  # fmt: skip
    for r in rows:
        if r.error:
            lines.append(f"| {r.variant} | {r.seed} | generator error {r.error} | - | - |")
            continue
        found = ", ".join(f"{k}={'yes' if v else 'no'}" for k, v in sorted(r.found.items())) or "-"
        col = f"{r.collateral[0]} of {r.collateral[1]}"
        lines.append(
            f"| {r.variant} | {r.seed} | {found} | {col} | {', '.join(r.unexpected) or 'none'} |"
        )
    return [*lines, ""]


def write_baseline(
    paths: Paths, path: Path, results: list[CaseEval], robustness: bool = True
) -> None:
    """Write the baseline document (overwrites the generated file only)."""
    lines = HEAD.splitlines()
    for r in results:
        lines += _case_section(r)
    if robustness and results:
        prefix = results[0].case_id.rsplit("_", 1)[0]
        lines += _robust_section(run_robustness(paths, prefix))
    lines += ["## Hayabusa-only comparison (trivial)", "",
              "| system | contradictions found |", "|---|---|",
              "| Hayabusa-only (`docs/hayabusa_baseline.md`) | 0 of 3, by construction |",
              "", "Hayabusa reads EVTX files one at a time. The three contradictions live in the "
              "synthetic file-system and auth sources and in disagreement BETWEEN sources, which "
              "a single-source rule engine cannot see; the comparison is trivial and is listed "
              "only for completeness.", ""]  # fmt: skip
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
