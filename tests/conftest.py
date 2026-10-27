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


# ---- the committed credtheft_lateral_v2 scenario, generated once per session ----------------
V2_DIR = Path(__file__).resolve().parents[1] / "scenarios" / "credtheft_lateral_v2"


@dataclass
class V2Data:
    """Committed v2 files plus both generated variants (no dataset needed)."""

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
def v2(tmp_path_factory) -> V2Data:
    scn = load_scenario(V2_DIR / "scenario.yaml")
    inv = load_inventory(V2_DIR / "inventory.json")
    insp = json.loads((V2_DIR / "field_inspection.json").read_text(encoding="utf-8"))
    keys = {v: load_key(V2_DIR / f"key_{v.value}.yaml", scn) for v in Variant}
    dirs = {}
    for v in Variant:
        dirs[v] = tmp_path_factory.mktemp(f"v2_{v.value}")
        generate_variant(scn, inv, v, dirs[v])
    return V2Data(scn, inv, insp, keys, dirs)
