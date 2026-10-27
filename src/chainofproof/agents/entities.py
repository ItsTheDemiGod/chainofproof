"""Pure helpers of the citation verifier: normalisation, token extraction and matching.

Plain code, no LLM, no database. Everything here works on agent-view objects only.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from chainofproof.schemas.events import NormalizedEvent
from chainofproof.tools.detectors.base import Hit, parse_ts

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ISO_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?(?![\w])")
HMS_RE = re.compile(r"(?<![\d:])\d{2}:\d{2}:\d{2}(?![\d:])")
EXE_RE = re.compile(r"\b[\w$-]+\.exe\b", re.I)
EVT_TOKEN_RE = re.compile(r"\bEVT-[0-9a-f]{12}\b")
HIT_TOKEN_RE = re.compile(r"\bHIT-\d{6}\b")
UNIT_RE = re.compile(r"(?<![\w.])(\d+(?:\.\d+)?)\s*(seconds?|secs?|minutes?|mins?|s)\b", re.I)
MAX_TOKENS = 50
TIME_TOLERANCE_S = 2.0
WINDOW_S = 60.0
_SAFE = re.compile(r"[^\w.\-\\$@:]")


def safe_name(value: str, cap: int = 60) -> str:
    """A model-provided name made safe to put in a templated problem string."""
    return _SAFE.sub("", value)[:cap] or "?"


def norm_user(value: str) -> str:
    """Lower case, domain prefix (``DOM\\user``) ignored."""
    return value.strip().rsplit("\\", 1)[-1].lower()


def norm_proc(value: str) -> str:
    """Lower-case basename of a process name or path."""
    return re.split(r"[\\/]", value.strip())[-1].lower()


def has_token(blob: str, needle: str) -> bool:
    """``needle`` occurs in ``blob`` as a whole token (both lower case)."""
    if not needle:
        return False
    pat = rf"(?<![\w-])(?<!\w\.){re.escape(needle)}(?![\w-]|\.\w)"
    return re.search(pat, blob) is not None


def parse_time(value: str) -> datetime | None:
    """Parse a virtual ISO time (``Z`` optional); None when malformed."""
    v = value.strip()
    return parse_ts(v if v.endswith("Z") else v + "Z")


def fields_blob(ev: NormalizedEvent) -> str:
    """Lower-case text of the free ``fields`` of an event."""
    return " ".join(str(v) for v in ev.fields.values()).lower()


def event_blob(ev: NormalizedEvent) -> str:
    """Lower-case text of every attribute of an event (token support in claim texts)."""
    d = ev.model_dump(mode="json")
    parts = [str(v) for k, v in d.items() if k != "fields" and v is not None]
    return " ".join([*parts, fields_blob(ev)]).lower()


def _walk(obj: Any):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _walk(v)
    elif isinstance(obj, list | tuple):
        for v in obj:
            yield from _walk(v)
    else:
        yield obj


def hit_times(hit: Hit) -> list[datetime]:
    """Every ISO time that appears in the measures of a hit."""
    out = []
    for v in _walk(hit.measures):
        if isinstance(v, str) and ISO_RE.match(v) and (t := parse_time(v)):
            out.append(t)
    return out


def hit_numbers(hit: Hit) -> list[float]:
    """Every numeric measure of a hit (booleans excluded)."""
    return [float(v) for v in _walk(hit.measures)
            if isinstance(v, int | float) and not isinstance(v, bool)]  # fmt: skip


def hit_blob(hit: Hit) -> str:
    """Lower-case text of a hit (hosts, measures, explanation)."""
    vals = [*hit.hosts, *hit.evidence_labels, hit.explanation, hit.kind, hit.detector]
    return " ".join([*vals, *(str(v) for v in _walk(hit.measures))]).lower()


def window(times: list[datetime]) -> tuple[datetime, datetime] | None:
    """[min - 60 s, max + 60 s] of the reference times, or None when there are none."""
    if not times:
        return None
    return min(times) - timedelta(seconds=WINDOW_S), max(times) + timedelta(seconds=WINDOW_S)


def _tod(t: datetime) -> float:
    t = t.astimezone(UTC)
    return t.hour * 3600 + t.minute * 60 + t.second + t.microsecond / 1e6


def claim_tokens(claim: str, known_hosts: list[str], numbers: bool) -> dict[str, list[Any]]:
    """Tokens the V5 scan can extract from a claim text (fixed regexes, deterministic order)."""
    iso = [m.group(0) for m in ISO_RE.finditer(claim)][:MAX_TOKENS]
    rest = ISO_RE.sub(" ", claim)  # HH:MM:SS inside an ISO time is not a second token
    hosts = [h for h in sorted(known_hosts)
             if re.search(rf"(?<![\w-]){re.escape(h)}(?![\w-])", claim, re.I)]  # fmt: skip
    nums: list[tuple[float, str]] = []
    if numbers:
        for m in UNIT_RE.finditer(claim):
            n = float(m.group(1)) * (60.0 if m.group(2).lower().startswith("m") else 1.0)
            nums.append((n, m.group(0).strip()))
    return {
        "ip": sorted(set(IP_RE.findall(claim)))[:MAX_TOKENS],
        "host": hosts[:MAX_TOKENS],
        "evt": sorted(set(EVT_TOKEN_RE.findall(claim)))[:MAX_TOKENS],
        "hit": sorted(set(HIT_TOKEN_RE.findall(claim)))[:MAX_TOKENS],
        "iso": iso,
        "hms": sorted(set(HMS_RE.findall(rest)))[:MAX_TOKENS],
        "exe": sorted({m.lower() for m in EXE_RE.findall(claim)})[:MAX_TOKENS],
        "num": nums[:MAX_TOKENS],
    }


def time_supported(token: str, refs: list[datetime]) -> bool:
    """An ISO or HH:MM:SS token lies within 2 s of a reference time."""
    if ":" in token and "T" not in token:
        h, m, s = (int(x) for x in token.split(":"))
        sec = h * 3600 + m * 60 + s
        return any(abs(_tod(r) - sec) <= TIME_TOLERANCE_S for r in refs)
    t = parse_time(token)
    return t is not None and any(abs((t - r).total_seconds()) <= TIME_TOLERANCE_S for r in refs)


def number_supported(seconds: float, measures: list[float]) -> bool:
    """Within max(1 s, 1 percent) of a numeric measure."""
    return any(abs(seconds - m) <= max(1.0, 0.01 * abs(m)) for m in measures)
