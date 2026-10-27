"""Write scenarios/<id>/field_inspection.json (metadata only) from the real EVTX sources.

Usage: .venv\\Scripts\\python.exe scripts\\field_inspect.py <scenario_id> [--rows s2,s3,s4 ...]
Prints only file names and counts, never event content.
"""

from __future__ import annotations

import sys

from chainofproof.config import get_paths
from chainofproof.scenarios.dataset import dataset_root, scenario_dir
from chainofproof.scenarios.fieldscan import save_inspection, scan_file
from chainofproof.schemas.scenario import SourceKind, load_scenario

ROW_STAGES = {"S1", "S2", "S3", "S4", "S5"}


def main(scenario_id: str) -> None:
    """Scan every real source of the scenario and write field_inspection.json."""
    d = scenario_dir(scenario_id)
    scn = load_scenario(d / "scenario.yaml")
    root = dataset_root(get_paths())
    sources = {}
    for s in scn.sources:
        if s.kind != SourceKind.real_evtx:
            continue
        res = scan_file(root / s.relative_path, with_rows=s.stage_id in ROW_STAGES)
        res.update(stage_id=s.stage_id, sha256=s.sha256)
        sources[s.source_key] = res
        print(f"{s.source_key}: {res['record_count']} records")
    save_inspection(
        d / "field_inspection.json",
        {
            "scenario_id": scenario_id,
            "note": "metadata only; see docs/scenarios.md",
            "sources": sources,
        },
    )


if __name__ == "__main__":
    main(sys.argv[1])
