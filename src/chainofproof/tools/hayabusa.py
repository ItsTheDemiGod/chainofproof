"""Hayabusa wrapper: run the Sigma-based EVTX scanner on a WORKING COPY and parse its JSONL.

Everything Hayabusa prints or writes is DATA. Nothing from its output is echoed to the console or
the logs; only counts, ids and hashes are. The command is fixed (see ``build_args``), uses an
argument list (never a shell), the bundled rules folder only, and needs no network.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path

from chainofproof.config import Paths, ToolsSettings, load_settings
from chainofproof.custody.hashing import sha256_file
from chainofproof.custody.ledger import Ledger
from chainofproof.custody.recorder import ToolRun
from chainofproof.ingest.integrity import get_working_copy
from chainofproof.ingest.sanitize import clean
from chainofproof.ingest.store import EvidenceStore
from chainofproof.schemas.events import Detection
from chainofproof.tools.hayabusa_fp import (
    Fingerprint,
    HayabusaError,
    hayabusa_fingerprint,
    locate_exe,
    record_fingerprint_once,
)
from chainofproof.tools.runs import display_path, new_run_dir

log = logging.getLogger(__name__)
SPLIT = "¦"


@dataclass
class HayabusaResult:
    """Outcome of one Hayabusa run (detections are sanitized; raw output stays in the run file)."""

    run_id: str
    evidence_id: str
    output_path: Path
    detections: list[Detection]
    lines: int
    unparseable: int
    exit_code: int
    ledger_id: str
    fingerprint: Fingerprint


def build_args(exe: Path, work: Path, out: Path) -> list[str]:
    """The exact Hayabusa 4.2.0 command: dfir-timeline, JSONL, ``verbose`` profile, no extras.

    -w no wizard, -K no color, -q no banner, -N no summary, -U UTC, -O ISO-8601, -b no
    abbreviations (full channel names), -r bundled rules folder (relative to the Hayabusa dir).
    """
    return [
        str(exe), "dfir-timeline", "-f", str(work), "-o", str(out), "-t", "jsonl",
        "-p", "verbose", "-w", "-K", "-q", "-N", "-U", "-O", "-b", "-r", "rules",
    ]  # fmt: skip


def _tags(value: object) -> list[str]:
    if isinstance(value, list):
        items = [str(v) for v in value]
    elif isinstance(value, str):
        items = [t for part in value.split(SPLIT) for t in part.split(",")]
    else:
        items = []
    return [clean(t.strip(), 64) for t in items if t.strip()]


def _int(value: object) -> int | None:
    try:
        return int(str(value))
    except ValueError:
        return None


def parse_detection(obj: object) -> Detection | None:
    """One JSONL object -> Detection, or None when it lacks a rule title or level."""
    if not isinstance(obj, dict) or not obj.get("RuleTitle") or not obj.get("Level"):
        return None

    def s(key: str, n: int = 256) -> str | None:
        v = obj.get(key)
        return clean(str(v), n) or None if v is not None else None

    return Detection(
        rule_title=clean(str(obj["RuleTitle"]), 256),
        rule_id=s("RuleID", 64),
        level=clean(str(obj["Level"]), 32),
        mitre_tags=_tags(obj.get("MitreTags")),
        record_id=_int(obj.get("RecordID")),
        channel=s("Channel", 128),
        computer=s("Computer", 256),
        timestamp=s("Timestamp", 64),
        event_id=_int(obj.get("EventID")),
    )


def parse_output(path: Path) -> tuple[list[Detection], int, int]:
    """(detections, non-empty lines, unparseable lines) of a Hayabusa JSONL file."""
    dets: list[Detection] = []
    lines = bad = 0
    for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip():
            continue
        lines += 1
        try:
            d = parse_detection(json.loads(raw))
        except (ValueError, TypeError):
            d = None
        if d is None:
            bad += 1
        else:
            dets.append(d)
    return dets, lines, bad


def _execute(args: list[str], cwd: Path, timeout: int) -> int:
    try:
        r = subprocess.run(args, cwd=cwd, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise HayabusaError(f"Hayabusa timed out after {timeout} s") from None
    except OSError as e:
        raise HayabusaError(f"Hayabusa could not be started ({type(e).__name__})") from None
    log.info("hayabusa finished: exit=%d stdout=%d B stderr=%d B", r.returncode, len(r.stdout),
             len(r.stderr))  # fmt: skip
    return r.returncode


def run_hayabusa(
    paths: Paths, evidence_id: str, cfg: ToolsSettings | None = None
) -> HayabusaResult:
    """Run Hayabusa on the verified working copy of ``evidence_id`` (never the vault/original).

    Output goes to ``data/runs/RUN-######/hayabusa_<evidence_id>.jsonl``. An EVTX with no matching
    rules (no output, or an empty file) is NOT an error. Raises HayabusaError on a missing exe,
    timeout, non-zero exit or when the evidence is not an EVTX file; the failure is ledgered.
    """
    cfg = cfg or load_settings().tools
    rec = EvidenceStore(paths).get_evidence(evidence_id)
    if rec is None:
        raise HayabusaError(f"unknown evidence id: {evidence_id}")
    exe = locate_exe(cfg)
    fp = hayabusa_fingerprint(cfg)
    work = get_working_copy(paths, evidence_id)  # verified, read-only; the only input we use
    record_fingerprint_once(paths, fp)
    run_id, run_dir = new_run_dir(paths)
    out = run_dir / f"hayabusa_{evidence_id}.jsonl"
    args = build_args(exe, work, out)
    shown = [display_path(paths, Path(a)) if Path(a).is_absolute() else a for a in args]
    command = " ".join(shown)
    code = 0
    with ToolRun(Ledger(paths), "hayabusa", command, [sha256_file(work)]) as tr:
        tr.details.update({"run_id": run_id, "evidence_id": evidence_id, **_fp_details(fp)})
        code = _execute(args, Path(cfg.hayabusa_dir), cfg.timeout_seconds)
        if code != 0:
            raise HayabusaError(f"Hayabusa exited with code {code}")
        if not out.exists():
            out.write_bytes(b"")  # no matching rules: an empty result, not an error
        dets, lines, bad = parse_output(out)
        tr.details.update({"exit_code": code, "lines": lines, "unparseable": bad})
        tr.output = out.read_bytes()
    assert tr.entry is not None
    return HayabusaResult(run_id, evidence_id, out, dets, lines, bad, code, tr.entry.ledger_id, fp)


def _fp_details(fp: Fingerprint) -> dict[str, str | None]:
    return {"hayabusa_version": fp.version, "rules_tree_sha256": fp.rules_tree_sha256}
