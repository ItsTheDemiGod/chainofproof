"""Locations and drift protection for the real dataset and the scenario folders."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from chainofproof.config import PROJECT_ROOT, Paths
from chainofproof.custody.hashing import sha256_file
from chainofproof.schemas.scenario import Scenario, ScenarioError, SourceKind

DATASET_NAME = "EVTX-ATTACK-SAMPLES"


def dataset_root(paths: Paths) -> Path:
    """Where the real dataset lives (data/downloads/EVTX-ATTACK-SAMPLES); env override for tests."""
    env = os.environ.get("CHAINOFPROOF_DATASET_DIR")
    return Path(env) if env else paths.base_dir / "downloads" / DATASET_NAME


def scenarios_root() -> Path:
    """Folder holding committed scenario definitions; env override for tests."""
    env = os.environ.get("CHAINOFPROOF_SCENARIOS_DIR")
    return Path(env) if env else PROJECT_ROOT / "scenarios"


def scenario_dir(scenario_id: str) -> Path:
    """Folder of one scenario (scenario.yaml, inventory.json, key_*.yaml)."""
    return scenarios_root() / scenario_id


def generated_dir(paths: Paths, scenario_id: str, variant: str) -> Path:
    """Where generated (SYNTHETIC) companion files of a variant are written (gitignored)."""
    return paths.base_dir / "scenarios_generated" / scenario_id / variant


def git_commit(repo: Path) -> str | None:
    """HEAD commit of a git checkout, or None if unavailable."""
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() or None


def verify_dataset(scenario: Scenario, root: Path) -> list[str]:
    """Check the real files against scenario.yaml; returns problems (empty = OK). Never writes."""
    if not root.is_dir():
        return [f"dataset folder not found: {root}"]
    problems: list[str] = []
    commit = git_commit(root)
    if commit is not None and commit != scenario.dataset_provenance.clone_commit:
        problems.append(
            f"dataset commit {commit[:12]} != scenario commit "
            f"{scenario.dataset_provenance.clone_commit[:12]}"
        )
    for s in scenario.sources:
        if s.kind != SourceKind.real_evtx:
            continue
        f = root / s.relative_path
        if not f.is_file():
            problems.append(f"{s.source_key}: missing file {s.relative_path}")
        elif sha256_file(f) != s.sha256:
            problems.append(f"{s.source_key}: SHA-256 differs from scenario.yaml (dataset drift)")
    return problems


def require_dataset(scenario: Scenario, root: Path) -> None:
    """Fail loudly (ScenarioError) if the dataset drifted or is missing."""
    problems = verify_dataset(scenario, root)
    if problems:
        raise ScenarioError("DATASET DRIFT / MISSING: " + "; ".join(problems))
