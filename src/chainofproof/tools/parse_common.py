"""Shared pieces of the three parsers: context, opaque IDs, entity helpers, summaries."""

from __future__ import annotations

import hashlib
import ntpath
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from chainofproof.errors import UserError
from chainofproof.ingest.sanitize import FIELD_MAX, clean, sanitize
from chainofproof.schemas.events import LABEL_PREFIX, MAX_FIELDS, NormalizedEvent, SourceKindName

TS_OUT = "%Y-%m-%dT%H:%M:%S.%fZ"
_FIELD_TS = re.compile(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(\.\d+)?Z?$")
_IP = re.compile(r"^[0-9a-fA-F:.]{2,45}$")


class ParseError(UserError):
    """A source file could not be parsed (message names a line or record number only)."""


@dataclass
class ParseStats:
    """Filled while a parser runs."""

    records: int = 0
    corrupt: int = 0


@dataclass
class ParseContext:
    """What a parser needs to know about its source (supplied by the normalizer)."""

    evidence_id: str
    evidence_sha256: str
    source_key: str
    source_kind: SourceKindName
    is_synthetic: bool
    offset: timedelta = timedelta(0)  # real -> virtual; zero for synthetic sources
    aliases: dict[str, str] = field(default_factory=dict)  # real computer (lower) -> virtual host
    virtual_hosts: frozenset[str] = frozenset()
    stats: ParseStats = field(default_factory=ParseStats)

    @property
    def label(self) -> str:
        """Opaque evidence label: KIND-<first 6 hex of the file's sha256>."""
        return make_label(self.source_kind, self.evidence_sha256)

    def virtual_host(self, real_name: str) -> str:
        """Alias of a real computer name for THIS source (never global); strict."""
        host = self.aliases.get(real_name.lower())
        if host is None:
            raise ParseError("a computer name has no alias in this source's alignment entry")
        return host

    def scrub(self, value: str) -> str:
        """Replace a value that is exactly a real computer name, its short name, or the machine
        account (``PC01$``) of either; the ``$`` suffix is kept on the virtual name."""
        low = value.lower()
        dollar = "$" if low.endswith("$") else ""
        low = low.removesuffix("$")
        for real, virt in self.aliases.items():
            if low == real or low == real.split(".")[0]:
                return virt + dollar
        return value


def make_label(kind: SourceKindName, sha256: str) -> str:
    """``EVTX-3fa91c`` style label; never derived from names or EV ids."""
    return f"{LABEL_PREFIX[kind]}-{sha256[:6]}"


def make_event_uid(evidence_sha256: str, locator: str) -> str:
    """EVT-<12 hex of sha256(evidence_sha256 + ':' + stable record locator)>."""
    return "EVT-" + hashlib.sha256(f"{evidence_sha256}:{locator}".encode()).hexdigest()[:12]


def fmt_virtual(dt: datetime) -> str:
    """UTC timestamp with microseconds."""
    return dt.astimezone(UTC).strftime(TS_OUT)


def shift_text_time(value: str, offset: timedelta) -> str | None:
    """If ``value`` is a bare timestamp, return it shifted into virtual time; else None."""
    m = _FIELD_TS.match(value.strip())
    if not m:
        return None
    frac = (m.group(3) or ".0")[1:7].ljust(6, "0")
    dt = datetime.strptime(f"{m.group(1)} {m.group(2)}.{frac}", "%Y-%m-%d %H:%M:%S.%f")
    return fmt_virtual(dt.replace(tzinfo=UTC) + offset)


def basename(path: str | None) -> str | None:
    """Last path component (Windows or POSIX separators), sanitized; None when empty."""
    if not path:
        return None
    base = ntpath.basename(path.replace("/", "\\").rstrip("\\"))
    return clean(base, 260) or None


def to_int(value: str | None) -> int | None:
    """Decimal or 0x-hex string to int, None when not numeric."""
    if value is None:
        return None
    v = value.strip()
    try:
        return int(v, 16) if v.lower().startswith("0x") else int(v)
    except ValueError:
        return None


def clean_ip(value: str | None) -> str | None:
    """IP-looking value or None (placeholders like '-' or 'unknown' become None)."""
    return value if value and _IP.match(value) and ("." in value or ":" in value) else None


def add_fields(ctx: ParseContext, data: dict[str, str], consumed: set[str]) -> tuple[dict, bool]:
    """Remaining fields, sanitized and capped (<= MAX_FIELDS, 512 chars each); (dict, truncated)."""
    out: dict[str, str] = {}
    trunc = False
    for k in sorted(data):
        if k in consumed or data[k] == "":
            continue
        if len(out) >= MAX_FIELDS:
            trunc = True
            break
        key = clean(k, 64)
        val = ctx.scrub(data[k])
        shifted = shift_text_time(val, ctx.offset) if ctx.source_kind == "evtx" else None
        text, t, _ = sanitize(shifted or val, FIELD_MAX)
        out[key] = text
        trunc = trunc or t
    return out, trunc


def build_summary(ev: NormalizedEvent) -> str:
    """Short deterministic text from structured fields only (never copies free text)."""
    parts = [ev.event_type.value]
    if ev.process_image or ev.target_image:
        arrow = f" -> {ev.target_image}" if ev.target_image else ""
        parts.append(f"{ev.process_image or '?'}{arrow}")
    if ev.file_path:
        parts.append(f"file={basename(ev.file_path)}")
    if ev.user:
        parts.append(f"user={ev.user}")
    if ev.logon_type:
        parts.append(f"logon_type={ev.logon_type}")
    if ev.service_name:
        parts.append(f"service={ev.service_name}")
    if ev.pipe_name:
        parts.append(f"pipe={ev.pipe_name}")
    if ev.dst_ip or ev.dst_port:
        parts.append(f"dst={ev.dst_ip or '?'}:{ev.dst_port or '?'}")
    if ev.src_ip:
        parts.append(f"src={ev.src_ip}")
    if ev.conn_id:
        parts.append(f"conn={ev.conn_id}")
    if ev.dst_host:
        parts.append(f"to={ev.dst_host}")
    if ev.event_id is not None:
        parts.append(f"eid={ev.event_id}")
    return " ".join(parts)[:300]
