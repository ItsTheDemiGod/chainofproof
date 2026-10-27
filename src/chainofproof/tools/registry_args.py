"""Argument and result models of the registered tools (split out of ``registry``).

Every argument model rejects unknown arguments; the registry validates agent input with them.
String filters accept one value or a list of up to 10 values (an empty list means no filter).
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from chainofproof.schemas.events import EventType
from chainofproof.tools import graph_query as gq
from chainofproof.tools import query as q
from chainofproof.tools.describe import ISO_EXAMPLE
from chainofproof.tools.detectors.base import Hit

MAX_VALUES = 10
ISO_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$"
Str = Annotated[str, StringConstraints(max_length=200)]
StrOrList = Str | Annotated[list[Str], Field(max_length=MAX_VALUES)]
IntOrList = int | Annotated[list[int], Field(max_length=MAX_VALUES)]
TypeOrList = EventType | Annotated[list[EventType], Field(max_length=MAX_VALUES)]
IsoTime = Annotated[
    str,
    StringConstraints(pattern=ISO_PATTERN),
    Field(description=f"ISO-8601 UTC string like {ISO_EXAMPLE}"),
]
Limit = Annotated[int | None, Field(description="int<=50 (default 25)")]


class Args(BaseModel):
    """Base of all argument models: unknown arguments are rejected."""

    model_config = ConfigDict(extra="forbid")


class NoArgs(Args):
    """No arguments."""


class SearchArgs(Args):
    """Filters of search_events (all ANDed)."""

    host: StrOrList | None = None
    event_type: TypeOrList | None = None
    user: StrOrList | None = None
    process_image: StrOrList | None = None
    text: str | None = None
    time_from: IsoTime | None = None
    time_to: IsoTime | None = None
    evidence_label: StrOrList | None = None
    conn_id: StrOrList | None = None
    event_id: IntOrList | None = None
    limit: Limit = None
    offset: int = 0


class GetEventArgs(Args):
    """An event id."""

    event_uid: str


class TimelineArgs(Args):
    """A host (or several) and a virtual time window."""

    host: StrOrList
    start: IsoTime
    end: IsoTime
    limit: Limit = None


class DetectionsArgs(Args):
    """Hayabusa detections by source label and/or event."""

    evidence_label: StrOrList | None = None
    event_uid: str | None = None
    limit: Limit = None


class LabelArgs(Args):
    """An evidence label."""

    evidence_label: str


class NodeArgs(Args):
    """A graph node id."""

    node_id: str


class NeighborsArgs(Args):
    """Neighbors of a node."""

    node_id: str
    relation: str | None = None
    direction: str = Field(default="both", description="enum[out|in|both]")
    limit: Limit = None


class PathsArgs(Args):
    """Paths between two nodes."""

    from_node: str
    to_node: str
    max_hops: int = gq.MAX_HOPS
    max_paths: int = gq.MAX_PATHS


class LimitArgs(Args):
    """Only a limit."""

    limit: Limit = None


class GetHitsArgs(Args):
    """Stored detector hits."""

    detector: str | None = None
    hit_id: str | None = None
    limit: Limit = None


class LabelList(BaseModel):
    """Sources of a case."""

    labels: list[q.LabelInfo]


class DetectorResult(BaseModel):
    """What a detector tool returns (at most 50 hits are inlined)."""

    run_id: str
    detector: str
    params: dict[str, Any]
    hit_count: int
    returned: int
    truncated: bool
    hits: list[Hit]


def det_args(name: str, base: type[BaseModel]) -> type[Args]:
    """Argument model of a detector tool: the detector's parameters, unknown keys rejected."""
    return type(
        f"{name.title().replace('_', '')}Args", (base, Args), {"__doc__": f"{name} parameters."}
    )
