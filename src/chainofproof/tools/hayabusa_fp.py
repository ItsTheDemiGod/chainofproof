"""Hayabusa location and fingerprint (version, exe hash, rules tree hash)."""

from __future__ import annotations

import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from chainofproof.config import Paths, ToolsSettings
from chainofproof.custody.hashing import sha256_bytes, sha256_file
from chainofproof.custody.ledger import Ledger
from chainofproof.errors import UserError

_VERSION = re.compile(r"Hayabusa v(\d+\.\d+\.\d+)")
_FILE_VERSION = re.compile(r"(\d+\.\d+\.\d+)")
_CACHE: dict[str, Fingerprint] = {}
_RECORDED: set[tuple[str, str]] = set()


class HayabusaError(UserError):
    """Hayabusa is missing, failed, timed out, or its output is unusable."""


@dataclass(frozen=True)
class Fingerprint:
    """Identity of the tool that produced detections."""

    version: str
    exe_sha256: str
    rules_tree_sha256: str | None  # None only when there is no rules folder (fake exe in tests)


def locate_exe(cfg: ToolsSettings) -> Path:
    """The single executable matching ``cfg.exe_glob`` in ``cfg.hayabusa_dir``."""
    folder = Path(cfg.hayabusa_dir)
    matches = sorted(folder.glob(cfg.exe_glob)) if folder.is_dir() else []
    if not matches:
        raise HayabusaError(f"Hayabusa executable not found ({cfg.exe_glob} in {folder.name})")
    if len(matches) > 1:
        raise HayabusaError(f"{len(matches)} files match {cfg.exe_glob}; expected exactly one")
    return matches[0]


def _rules_tree_hash(rules: Path) -> str:
    """sha256 over sorted (relative path, file sha256) of every rules file; ``.git`` is skipped."""
    lines = []
    for f in rules.rglob("*"):
        rel = f.relative_to(rules)
        if f.is_file() and ".git" not in rel.parts:
            lines.append(f"{rel.as_posix()}\0{sha256_file(f)}")
    return sha256_bytes("\n".join(sorted(lines)).encode("utf-8"))


def run_help(exe: Path, cfg: ToolsSettings, timeout: int = 60) -> tuple[bool, str]:
    """Run ``exe help``; returns (ran_ok, version or 'unknown'). Output is parsed, never shown."""
    try:
        r = subprocess.run(
            [str(exe), "help"], cwd=exe.parent, capture_output=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return False, "unknown"
    m = _VERSION.search(r.stdout.decode("utf-8", errors="replace"))
    return r.returncode == 0, m.group(1) if m else "unknown"


def hayabusa_fingerprint(cfg: ToolsSettings) -> Fingerprint:
    """Version, exe sha256 and rules tree sha256 (computed once per process and exe path)."""
    exe = locate_exe(cfg)
    key = str(exe.resolve())
    if key not in _CACHE:
        _, version = run_help(exe, cfg)
        if version == "unknown" and (m := _FILE_VERSION.search(exe.name)):
            version = m.group(1)
        rules = exe.parent / "rules"
        _CACHE[key] = Fingerprint(
            version, sha256_file(exe), _rules_tree_hash(rules) if rules.is_dir() else None
        )
    return _CACHE[key]


def record_fingerprint_once(paths: Paths, fp: Fingerprint) -> None:
    """Append the fingerprint to the ledger the first time this process uses it for a ledger."""
    key = (str(paths.ledger_path), fp.exe_sha256 + str(fp.rules_tree_sha256))
    if key in _RECORDED:
        return
    Ledger(paths).append("hayabusa", "tool_fingerprint", details=asdict(fp))
    _RECORDED.add(key)
