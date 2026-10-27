"""DEV / TEST split of the cases (rules E1 to E3). Neutral: no ground truth, no scenario imports.

``splits.yaml`` sits in the scenario folder. A case id is ``<scenario>_<variant>`` (base seed) or
``<scenario>_s<seed>_<variant>``. Any case that is not listed (v1 to v3, other cases) is
"unassigned" and unrestricted.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

from chainofproof.config import PROJECT_ROOT

Split = Literal["dev", "test"]
_CASE = re.compile(r"^(?P<sid>.+?)_(?:s(?P<seed>\d+)_)?(?P<variant>clean|perturbed)$")


class DevSplit(BaseModel):
    """The development cases: the base seed (optional) and extra seeds."""

    base: bool = False
    seeds: list[int] = Field(default_factory=list)


class HeldOutSplit(BaseModel):
    """The held-out (TEST) cases."""

    seeds: list[int] = Field(default_factory=list)


class Splits(BaseModel):
    """Contents of splits.yaml."""

    scenario_id: str
    dev: DevSplit
    test: HeldOutSplit


def scenarios_root() -> Path:
    """Folder with the committed scenario definitions (env override for tests)."""
    env = os.environ.get("CHAINOFPROOF_SCENARIOS_DIR")
    return Path(env) if env else PROJECT_ROOT / "scenarios"


@lru_cache(maxsize=16)
def _load(path: str, mtime: float) -> Splits:
    return Splits.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))


def load_splits(scenario_id: str) -> Splits | None:
    """The splits of a scenario, or None when it has no splits.yaml."""
    f = scenarios_root() / scenario_id / "splits.yaml"
    return _load(str(f), f.stat().st_mtime) if f.is_file() else None


def split_of(case_id: str) -> Split | None:
    """``dev``, ``test`` or None (unassigned) for a case id."""
    m = _CASE.match(case_id)
    if m is None:
        return None
    splits = load_splits(m["sid"])
    if splits is None or splits.scenario_id != m["sid"]:
        return None
    if m["seed"] is None:
        return "dev" if splits.dev.base else None
    seed = int(m["seed"])
    if seed in splits.test.seeds:
        return "test"
    return "dev" if seed in splits.dev.seeds else None
