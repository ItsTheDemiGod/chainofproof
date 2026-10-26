"""Metadata inventory and key-event discovery for the real EVTX sources of a scenario.

Output (inventory.json) holds metadata only: counts, times, names, EventIDs and the key events'
IDs/times/rationales. No raw event content is stored or printed.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from chainofproof.scenarios.evtx_meta import EvtxEvent, ReadStats, iter_events
from chainofproof.scenarios.keyevents import RULES, StageResult
from chainofproof.schemas.scenario import Scenario, ScenarioError, SourceKind

ACCOUNT_FIELDS = ("SubjectUserName", "TargetUserName", "User")
INSTRUCTION_LIKE = re.compile(
    r"ignore (all |any |the )?(previous|prior|above)|disregard (the |all |any )?(previous|prior)"
    r"|system prompt|you are (now )?(an? |the )?(ai|assistant|llm)|as an ai\b|\bclaude\b",
    re.I,
)
TOP_N, MAX_ACCOUNTS = 15, 20


class EventCount(BaseModel):
    """EventID and how often it occurs."""

    event_id: int
    count: int


class SourceInventory(BaseModel):
    """Metadata of one real EVTX file."""

    model_config = ConfigDict(extra="forbid")
    source_key: str
    relative_path: str
    sha256: str | None
    record_count: int
    corrupt_records: int
    first_event_time: str | None
    last_event_time: str | None
    span_seconds: float
    computers: list[str]
    channels: list[str]
    top_event_ids: list[EventCount]
    accounts: list[str]
    instruction_like_fields: list[str]  # "EventID<n>.<FieldName>" only, never the text


class StageKeys(BaseModel):
    """Key events found for one storyline stage."""

    stage_id: str
    source_key: str
    result: StageResult


class Inventory(BaseModel):
    """Everything inventory.json contains."""

    model_config = ConfigDict(extra="forbid")
    scenario_id: str
    dataset_commit: str
    sources: list[SourceInventory]
    key_events: list[StageKeys]

    def keys_for(self, stage_id: str) -> StageKeys:
        """Key events of a stage (StopIteration if the stage has none)."""
        return next(k for k in self.key_events if k.stage_id == stage_id)

    def source(self, key: str) -> SourceInventory:
        """Inventory of one source (StopIteration if unknown)."""
        return next(s for s in self.sources if s.source_key == key)


def _span(first: str | None, last: str | None) -> float:
    if not first or not last:
        return 0.0
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
    return (datetime.strptime(last, fmt) - datetime.strptime(first, fmt)).total_seconds()


def inventory_file(
    key: str, relative_path: str, sha256: str | None, path: Path
) -> tuple[SourceInventory, list[EvtxEvent]]:
    """Stream one EVTX file; return its metadata and the (small) list of parsed events."""
    stats = ReadStats()
    events: list[EvtxEvent] = []
    ids: Counter[int] = Counter()
    computers: set[str] = set()
    channels: set[str] = set()
    accounts: set[str] = set()
    suspicious: set[str] = set()
    for e in iter_events(path, stats):
        events.append(e)
        ids[e.event_id] += 1
        computers.add(e.computer)
        channels.add(e.channel)
        for f in ACCOUNT_FIELDS:
            v = e.data.get(f, "")
            if v and v != "-":
                accounts.add(v)
        for name, val in e.data.items():
            if INSTRUCTION_LIKE.search(val):
                suspicious.add(f"EventID{e.event_id}.{name}")
    times = sorted(e.time for e in events)
    first, last = (times[0], times[-1]) if times else (None, None)
    inv = SourceInventory(
        source_key=key,
        relative_path=relative_path,
        sha256=sha256,
        record_count=stats.records,
        corrupt_records=stats.corrupt,
        first_event_time=first,
        last_event_time=last,
        span_seconds=_span(first, last),
        computers=sorted(computers),
        channels=sorted(channels),
        top_event_ids=[EventCount(event_id=i, count=c) for i, c in ids.most_common(TOP_N)],
        accounts=sorted(accounts)[:MAX_ACCOUNTS],
        instruction_like_fields=sorted(suspicious),
    )
    return inv, events


def run_inventory(scenario: Scenario, root: Path) -> Inventory:
    """Inventory every real source and apply the stage rules to storyline sources."""
    sources: list[SourceInventory] = []
    keys: list[StageKeys] = []
    for s in scenario.sources:
        if s.kind != SourceKind.real_evtx:
            continue
        path = root / s.relative_path
        inv, events = inventory_file(s.source_key, s.relative_path, s.sha256, path)
        sources.append(inv)
        rule = RULES.get(s.stage_id or "")
        if rule is not None:
            result = rule(events)
            keys.append(
                StageKeys(stage_id=s.stage_id or "", source_key=s.source_key, result=result)
            )
    return Inventory(
        scenario_id=scenario.scenario_id,
        dataset_commit=scenario.dataset_provenance.clone_commit,
        sources=sources,
        key_events=keys,
    )


def save_inventory(path: Path, inv: Inventory) -> None:
    """Write inventory.json (deterministic: model order, indent 2, LF, trailing newline)."""
    text = json.dumps(inv.model_dump(mode="json"), indent=2, ensure_ascii=False)
    Path(path).write_text(text + "\n", encoding="utf-8", newline="\n")


def load_inventory(path: Path) -> Inventory:
    """Load inventory.json."""
    try:
        return Inventory.model_validate_json(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ScenarioError(f"{Path(path).name}: {str(e).splitlines()[0]}") from e
