"""Source-type detection from magic bytes, then file extension."""

from __future__ import annotations

from pathlib import Path

from chainofproof.schemas.custody import SourceType

_PCAP_MAGICS = {
    bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b23c4d"),
    bytes.fromhex("4d3cb2a1"),
    bytes.fromhex("0a0d0d0a"),  # pcapng
}
_EXT = {
    SourceType.evtx: {".evtx"},
    SourceType.pcap: {".pcap", ".pcapng"},
    SourceType.memory_dump: {".raw", ".mem", ".vmem", ".dmp", ".lime"},
    SourceType.disk_image: {".e01", ".dd", ".img", ".vhd", ".vhdx"},
    SourceType.log_text: {".txt", ".log", ".csv", ".json", ".jsonl", ".xml"},
    SourceType.document: {".pdf", ".docx", ".doc", ".xlsx"},
}


def detect_source_type(path: Path) -> SourceType:
    """Guess the evidence type: magic bytes first, extension second, else ``other``."""
    path = Path(path)
    with path.open("rb") as f:
        head = f.read(8)
    if head.startswith(b"ElfFile\x00"):
        return SourceType.evtx
    if head[:4] in _PCAP_MAGICS:
        return SourceType.pcap
    ext = path.suffix.lower()
    for stype, exts in _EXT.items():
        if ext in exts:
            return stype
    return SourceType.other
