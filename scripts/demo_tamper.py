"""Tamper-detection demo. Runs ONLY inside a temporary directory; never touches data/.

Usage: .venv\\Scripts\\python.exe scripts\\demo_tamper.py (exit 1 if tampering goes undetected)
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

from rich.console import Console
from rich.table import Table

from chainofproof.config import Paths, get_paths
from chainofproof.custody.ledger import Ledger
from chainofproof.ingest.ingest import ingest_evidence
from chainofproof.ingest.integrity import verify_all, verify_evidence
from chainofproof.ingest.store import EvidenceStore
from chainofproof.ingest.vault import make_writable

console = Console(width=140)


def build(base: Path) -> Paths:
    """Create a case with three synthetic evidence files and ingest them."""
    paths = get_paths(base_dir=base)
    paths.ensure_dirs()
    EvidenceStore(paths).create_case("DEMO", "Synthetic tamper demo")
    src = base / "_src"
    src.mkdir()
    (src / "notes.txt").write_text("SYNTHETIC evidence file 1\n")
    (src / "events.log").write_text("SYNTHETIC log line A\nSYNTHETIC log line B\n")
    (src / "fake.evtx").write_bytes(b"ElfFile\x00" + b"SYNTHETIC-FILLER" * 4)
    for f in sorted(src.iterdir()):
        ingest_evidence(paths, "DEMO", f, description="synthetic demo file")
    verify_all(paths)  # more ledger entries, so "middle" is really in the middle
    return paths


def fresh_copy(base: Path, name: str) -> Paths:
    """Copy the whole data root so each experiment starts from a clean state."""
    dest = base.parent / name
    shutil.copytree(base, dest)
    return get_paths(base_dir=dest)


def rewrite(paths: Paths, fn) -> None:
    lines = paths.ledger_path.read_text(encoding="utf-8").splitlines()
    lines = fn(lines)
    paths.ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def edit_old(lines):
    d = json.loads(lines[1])
    d["details"]["original_name"] = "innocent.txt"
    lines[1] = json.dumps(d)
    return lines


def swap(lines):
    lines[1], lines[2] = lines[2], lines[1]
    return lines


def main() -> int:
    """Run all experiments and print the result table."""
    root = Path(tempfile.mkdtemp(prefix="cop_demo_"))
    try:
        base = root / "base"
        paths = build(base)
        led = Ledger(paths)
        res = led.verify()
        console.print(f"baseline ledger verify: ok={res.ok} ({res.checked} entries)")
        console.print(json.dumps(led.export_head(), indent=2), highlight=False)
        rows = []
        experiments = [
            ("a) edit a field in an old entry", edit_old),
            ("b) delete a middle entry", lambda ls: ls[:2] + ls[3:]),
            ("c) swap two entries", swap),
            ("d) delete the last entry", lambda ls: ls[:-1]),
        ]
        for i, (label, fn) in enumerate(experiments):
            p = fresh_copy(base, f"exp{i}")
            rewrite(p, fn)
            r = Ledger(p).verify()
            rows.append((label, not r.ok, r.problems[0] if r.problems else "-"))
        p = fresh_copy(base, "expv")
        eid = EvidenceStore(p).list_evidence()[0].evidence_id
        vault = p.base_dir / EvidenceStore(p).get_evidence(eid).vault_path
        make_writable(vault)
        data = bytearray(vault.read_bytes())
        data[-1] ^= 0x01
        vault.write_bytes(bytes(data))
        r = verify_evidence(p, eid)
        msg = next((x for x in r.problems if not x.startswith("WARN:")), "-")
        rows.append((f"e) flip one byte in vault file {eid}", not r.ok, msg))

        table = Table("experiment", "detected", "message", show_lines=True)
        for label, detected, msg in rows:
            table.add_row(label, "yes" if detected else "NO", msg)
        console.print(table)
        return 0 if all(d for _, d, _ in rows) else 1
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
