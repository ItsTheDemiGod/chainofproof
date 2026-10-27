"""Argument and result models of the registered tools (split out of ``registry``).

Every argument model rejects unknown arguments; the registry validates agent input with them.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from chainofproof.tools import graph_query as gq
from chainofproof.tools import query as q
from chainofproof.tools.detectors.base import Hit


class Args(BaseModel):
    """Base of all argument models: unknown arguments are rejected."""

    model_config = ConfigDict(extra="forbid")


class NoArgs(Args):
    """No arguments."""


class SearchArgs(Args):
    """Filters of search_events (all ANDed)."""

    host: str | None = None
    event_type: str | None = None
    user: str | None = None
    process_image: str | None = None
    text: str | None = None
    time_from: str | None = None
    time_to: str | None = None
    evidence_label: str | None = None
    conn_id: str | None = None
    event_id: int | None = None
    limit: int | None = None
    offset: int = 0


class GetEventArgs(Args):
    """An event id."""

    event_uid: str


class TimelineArgs(Args):
    """A host and a virtual time window."""

    host: str
    start: str
    end: str
    limit: int | None = None


class DetectionsArgs(Args):
    """Hayabusa detections by source label and/or event."""

    evidence_label: str | None = None
    event_uid: str | None = None
    limit: int | None = None


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
    direction: str = "both"
    limit: int | None = None


class PathsArgs(Args):
    """Paths between two nodes."""

    from_node: str
    to_node: str
    max_hops: int = gq.MAX_HOPS
    max_paths: int = gq.MAX_PATHS


class LimitArgs(Args):
    """Only a limit."""

    limit: int | None = None


class GetHitsArgs(Args):
    """Stored detector hits."""

    detector: str | None = None
    hit_id: str | None = None
    limit: int | None = None


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
