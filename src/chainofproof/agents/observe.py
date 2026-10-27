"""Delimiting and compaction (rule A4).

Everything that came from evidence, or from a model that read evidence, reaches a prompt ONLY as
``<<<DATA id=... source=...>>> ... <<<END-DATA id=...>>>``. Before wrapping, the text is sanitized
(ANSI/control characters removed) and any ``<<<`` / ``>>>`` in it is replaced by a neutral escape,
so content can never close its own block or open another. Tool results are compacted to one line
per record and capped at ``max_tool_output_chars``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from chainofproof.ingest.sanitize import clean

OPEN_ESC, CLOSE_ESC = "‹‹‹", "›››"  # single guillemets, tripled
LINE_MAX = 600
_ID = re.compile(r"[^A-Za-z0-9_.:-]")
_EVENT_KEYS = (("user", "user"), ("process_image", "proc"), ("target_image", "target"),
               ("pipe_name", "pipe"), ("conn_id", "conn"), ("src_ip", "src"), ("dst_ip", "dst"),
               ("dst_host", "dst_host"), ("logon_type", "logon"), ("record_id", "rec"))  # fmt: skip


def escape(text: str) -> tuple[str, int]:
    """Replace ``<<<`` and ``>>>`` with a neutral escape; returns (text, number of escapes)."""
    n = text.count("<<<") + text.count(">>>")
    return text.replace("<<<", OPEN_ESC).replace(">>>", CLOSE_ESC), n


def wrap(content: str, block_id: str, source: str, line_max: int = LINE_MAX) -> tuple[str, int]:
    """Sanitize each line, escape delimiters and wrap in a DATA block; returns (block, escapes)."""
    lines = [clean(x, line_max) for x in content.splitlines()] or [""]
    body, n = escape("\n".join(lines))
    bid, src = _ID.sub("", block_id)[:30], _ID.sub("", source)[:50]
    return f"<<<DATA id={bid} source={src}>>>\n{body}\n<<<END-DATA id={bid}>>>", n


def short(text: str, cap: int) -> str:
    """One sanitized line of at most ``cap`` characters."""
    return clean(text, cap)


def base_name(path: str | None) -> str | None:
    """File basename of a Windows or POSIX path."""
    return re.split(r"[\\/]", path)[-1] if path else None


def _t(ts: str) -> str:
    return ts[:19] + "Z"


def event_line(e: dict[str, Any]) -> str:
    """One compact line per event: id, virtual time, host, type and key structured fields."""
    parts = [e["event_uid"], _t(e["timestamp"]), e["host"], e["event_type"]]
    parts += [f"{short_k}={e[k]}" for k, short_k in _EVENT_KEYS if e.get(k) is not None]
    if f := base_name(e.get("file_path")):
        parts.append(f"file={f}")
    return " ".join(str(p) for p in parts)


def event_summary(e: dict[str, Any]) -> str:
    """Deterministic one-line summary of an event for the notebook (no id, no record number)."""
    parts = [_t(e["timestamp"]), e["host"], e["event_type"]]
    keys = [("user", "user"), ("process_image", "proc"), ("target_image", "target"),
            ("pipe_name", "pipe"), ("dst_host", "dst_host"), ("conn_id", "conn")]  # fmt: skip
    parts += [f"{s}={e[k]}" for k, s in keys if e.get(k) is not None][:3]
    return " ".join(parts)


def hit_line(h: dict[str, Any]) -> str:
    """One compact line per detector hit: id, kind, severity, hosts, measures, explanation."""
    m = " ".join(
        f"{k}={v}" for k, v in sorted(h["measures"].items())
        if isinstance(v, int | float | str) and not isinstance(v, bool) and len(str(v)) <= 60
    )  # fmt: skip
    first = h["limitations"][0] if h["limitations"] else ""
    uids = ",".join(h["event_uids"][:4])
    return (f"{h['hit_id']} {h['detector']}/{h['kind']} sev={h['severity']} "
            f"hosts={','.join(h['hosts'])} {m} events={uids} | {h['explanation']} "
            f"| limit: {first}")  # fmt: skip


@dataclass
class Compact:
    """A compacted tool result: text for the model plus the ids it shows."""

    text: str
    event_uids: list[str] = field(default_factory=list)
    hit_ids: list[str] = field(default_factory=list)
    shown: int = 0
    total: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)


def _page(lines: list[str], total: int, cap: int, head: str = "") -> tuple[str, int]:
    """Join lines up to ``cap`` characters with a visible 'showing N of M' header."""
    used, out = len(head) + 40, []
    for raw in lines:
        ln = raw[:LINE_MAX]  # one record never exceeds a line (a long field cannot hide the rest)
        if used + len(ln) + 1 > cap:
            break
        out.append(ln)
        used += len(ln) + 1
    header = f"{head}showing {len(out)} of {total}"
    return "\n".join([header, *out]), len(out)


def _kv(d: dict[str, Any], keys: tuple[str, ...]) -> str:
    return " ".join(f"{k}={d[k]}" for k in keys if k in d and d[k] is not None)


def _list_lines(tool: str, r: dict[str, Any]) -> tuple[list[str], int, str] | None:
    """(lines, total, header) for list-like results; None when the result is not list-like."""
    if "events" in r:
        return [event_line(e) for e in r["events"]], r["total_matches"], ""
    if "hits" in r:
        head = f"detector={r['detector']} hit_count={r['hit_count']} " if "detector" in r else ""
        return [hit_line(h) for h in r["hits"]], r.get("total_matches", r.get("hit_count", 0)), head
    if "detections" in r:
        keys = ("detection_id", "event_uid", "evidence_label", "level", "rule_title")
        return [_kv(d, keys) for d in r["detections"]], r["total_matches"], ""
    if "labels" in r:
        return [f"{x['label']} {x['source_kind']} hosts={','.join(x['hosts'])} "
                f"events={x['event_count']} {x['first_timestamp']} .. {x['last_timestamp']}"
                for x in r["labels"]], len(r["labels"]), ""  # fmt: skip
    if "items" in r:
        return (
            [
                f"{i['direction']} {i['relation']} {i['node_id']} n={i['event_count']} "
                f"events={','.join(i['event_uids'][:3])}"
                for i in r["items"]
            ],
            r["total_matches"],
            "",
        )
    if "paths" in r:
        return (
            [
                " -> ".join(p["nodes"])
                + " | events="
                + ",".join(u for h in p["hops"] for u in h["event_uids"][:1])
                for p in r["paths"]
            ],
            r["total_matches"],
            "",
        )
    if "links" in r:
        return [f"{x['from_host']} -> {x['to_host']} conns={','.join(x['conn_ids'][:6])} "
                f"n={x['event_count']} events={','.join(x['event_uids'][:3])}"
                for x in r["links"]], r["total_matches"], ""  # fmt: skip
    return None


def _scalar_lines(r: dict[str, Any]) -> list[str]:
    out = []
    for k, v in r.items():
        if isinstance(v, dict):
            out.append(f"{k}: " + " ".join(f"{a}={b}" for a, b in v.items()))
        elif isinstance(v, list):
            out.append(f"{k}: " + ", ".join(str(x) for x in v[:12]))
        else:
            out.append(f"{k}={v}")
    return out


def compact(tool: str, result: dict[str, Any], cap: int) -> Compact:
    """Compact a registry result for the model; at most ``cap`` characters."""
    listed = _list_lines(tool, result)
    if listed is None:  # summaries: scalars and small dicts, still capped
        text, shown = _page(_scalar_lines(result), len(result), cap, "")
        c = Compact(text, shown=shown, total=len(result))
        c.event_uids = list(dict.fromkeys(result.get("event_uids", [])))[:12]  # as shown
        return c
    lines, total, head = listed
    text, shown = _page(lines, total, cap, head)
    c = Compact(text, shown=shown, total=total)
    if "events" in result:
        c.events = result["events"][:shown]
        c.event_uids = [e["event_uid"] for e in c.events]
    if "hits" in result:
        hits = result["hits"][:shown]
        c.hit_ids = [h["hit_id"] for h in hits if h.get("hit_id")]
        c.event_uids = list(dict.fromkeys(u for h in hits for u in h["event_uids"][:4]))
    if "items" in result or "paths" in result or "links" in result:
        c.event_uids = sorted(set(re.findall(r"EVT-[0-9a-f]{12}", text)))
    return c
