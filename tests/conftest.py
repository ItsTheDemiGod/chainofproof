import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from chainofproof.config import get_paths
from chainofproof.scenarios.gen_context import parse_real
from chainofproof.scenarios.generator import generate_variant
from chainofproof.scenarios.inventory import Inventory, load_inventory
from chainofproof.schemas.scenario import AnswerKey, Scenario, Variant, load_key, load_scenario


@pytest.fixture
def paths(tmp_path):
    p = get_paths(base_dir=tmp_path / "base")
    p.ensure_dirs()
    return p


@pytest.fixture
def make_file(tmp_path):
    def _make(name="a.txt", data=b"hello evidence"):
        f = tmp_path / "src" / name
        f.parent.mkdir(exist_ok=True)
        f.write_bytes(data)
        return f

    return _make


# ---- the committed credtheft_lateral_v4 scenario, generated once per session ----------------
V4_DIR = Path(__file__).resolve().parents[1] / "scenarios" / "credtheft_lateral_v4"


@dataclass
class V4Data:
    """Committed v4 files plus both generated variants (no dataset needed)."""

    scn: Scenario
    inv: Inventory
    insp: dict
    keys: dict[Variant, AnswerKey]
    dirs: dict[Variant, Path]

    def rows(self, source_key: str) -> list[dict]:
        """Field-inspection rows of a real source."""
        return self.insp["sources"][source_key]["events"]

    def aligned(self, source_key: str, row: dict) -> datetime:
        """Real event time after the alignment layer, whole seconds."""
        off = timedelta(seconds=self.scn.aligned(source_key).time_offset_seconds)
        return (parse_real(row["time"]) + off).replace(microsecond=0)


@pytest.fixture(scope="session")
def v4(tmp_path_factory) -> V4Data:
    scn = load_scenario(V4_DIR / "scenario.yaml")
    inv = load_inventory(V4_DIR / "inventory.json")
    insp = json.loads((V4_DIR / "field_inspection.json").read_text(encoding="utf-8"))
    keys = {v: load_key(V4_DIR / f"key_{v.value}.yaml", scn) for v in Variant}
    dirs = {}
    for v in Variant:
        dirs[v] = tmp_path_factory.mktemp(f"v4_{v.value}")
        generate_variant(scn, inv, v, dirs[v])
    return V4Data(scn, inv, insp, keys, dirs)


def synthetic_env(base: Path, v4: V4Data, files: tuple[str, ...] | None = None):
    """Paths with both v4 cases holding the SYNTHETIC companion files, normalized (no Hayabusa)."""
    from chainofproof.ingest.ingest import ingest_evidence
    from chainofproof.ingest.store import EvidenceStore
    from chainofproof.tools.case_run import normalize_case

    paths = get_paths(base_dir=base)
    paths.ensure_dirs()
    store = EvidenceStore(paths)
    rows = {}
    for v in Variant:
        case = f"{v4.scn.scenario_id}_{v.value}"
        store.create_case(case, "t", f"{v4.scn.scenario_id} ({v.value})")
        for f in sorted(v4.dirs[v].iterdir()):
            if f.suffix in (".csv", ".log") and (files is None or f.name in files):
                ingest_evidence(paths, case, f)
        rows[case] = normalize_case(paths, case, hayabusa=False)
    return paths, rows


@pytest.fixture(scope="session")
def synth_norm(v4, tmp_path_factory):
    """Both v4 variants, synthetic sources only, normalized once per session."""
    return synthetic_env(tmp_path_factory.mktemp("norm") / "base", v4)
