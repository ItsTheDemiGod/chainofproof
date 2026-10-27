"""Run folders: sequential RUN-###### ids under data/runs. Earlier runs are never touched."""

from __future__ import annotations

import re
from pathlib import Path

from chainofproof.config import PROJECT_ROOT, Paths

_RUN = re.compile(r"^RUN-(\d{6})$")


def new_run_dir(paths: Paths) -> tuple[str, Path]:
    """Create the next free ``RUN-######`` folder (exist_ok is False: never reuse a run)."""
    paths.runs_dir.mkdir(parents=True, exist_ok=True)
    nums = [int(m.group(1)) for p in paths.runs_dir.iterdir() if (m := _RUN.match(p.name))]
    n = max(nums, default=0) + 1
    while True:
        run_id = f"RUN-{n:06d}"
        d = paths.runs_dir / run_id
        try:
            d.mkdir()
        except FileExistsError:
            n += 1
            continue
        return run_id, d


def display_path(paths: Paths, p: Path) -> str:
    """Project-relative (or data-root-relative) path for ledger commands; never a user name.

    Falls back to the bare file name when the path is outside both roots.
    """
    resolved = Path(p).resolve()
    for root in (PROJECT_ROOT, paths.base_dir.parent):
        try:
            return resolved.relative_to(root.resolve()).as_posix()
        except ValueError:
            continue
    return resolved.name
