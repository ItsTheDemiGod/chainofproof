"""Tool registry: every agent-facing tool with typed arguments, role permissions and a JSON schema.

No LLM is involved. ``call_tool(role, name, args, paths, case_id)`` validates the arguments with
pydantic, enforces the role's permission, bounds the output and returns a JSON-serializable dict.
Detectors are separate tools (``detect_<name>``): nothing here runs them automatically.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from chainofproof.config import Paths
from chainofproof.errors import UserError
from chainofproof.tools import graph_query as gq
from chainofproof.tools import query as q
from chainofproof.tools.detectors import DETECTORS
from chainofproof.tools.detectors.base import Hit
from chainofproof.tools.detectors.runner import HitPage, run_detector, stored_hits

ROLES = ("planner", "extractor", "correlator", "skeptic", "reporter")
MAX_OUTPUT_CHARS = 200_000
FORBIDDEN_KEYS = {
    "source_key", "synth_only", "pair_field", "pair_value", "is_synthetic", "raw_note",
    "real_computer", "real_timestamp", "locator", "evidence_id", "original_name", "vault_path",
}  # fmt: skip


class ToolError(UserError):
    """Unknown tool or role, permission denied, invalid arguments, or a failed call."""


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


def _det_args(name: str, base: type[BaseModel]) -> type[Args]:
    return type(
        f"{name.title().replace('_', '')}Args", (base, Args), {"__doc__": f"{name} parameters."}
    )


@dataclass(frozen=True)
class ToolSpec:
    """One registered tool."""

    name: str
    description: str
    params: type[BaseModel]
    returns: type[BaseModel]
    roles: frozenset[str]
    fn: Callable[[Paths, str, Any], BaseModel]

    def schema(self) -> dict[str, Any]:
        """JSON-schema export for LLM tool calling (Phase 5)."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.params.model_json_schema(),
            "returns": self.returns.model_json_schema(),
            "roles": sorted(self.roles),
        }


def _run_det(name: str) -> Callable[[Paths, str, Any], BaseModel]:
    def call(paths: Paths, case_id: str, a: BaseModel) -> DetectorResult:
        r = run_detector(paths, case_id, name, a.model_dump())
        n = len(r.hits)
        return DetectorResult(
            run_id=r.run_id,
            detector=name,
            params=r.params,
            hit_count=n,
            returned=min(n, 50),
            truncated=n > 50,
            hits=r.hits[:50],
        )

    return call


def _build() -> dict[str, ToolSpec]:
    R = frozenset  # noqa: N806
    t: list[ToolSpec] = [
        ToolSpec(
            "list_evidence_labels",
            "List the evidence sources of the case (label, kind, hosts, "
            "event count, virtual time span).",
            NoArgs,
            LabelList,
            R({"planner", "extractor"}),
            lambda p, c, a: LabelList(labels=q.list_evidence_labels(p, c)),
        ),
        ToolSpec(
            "search_events",
            "Search normalized events with filters (max 50 per call).",
            SearchArgs,
            q.EventPage,
            R({"extractor", "correlator", "skeptic"}),
            lambda p, c, a: q.search_events(p, c, **a.model_dump()),
        ),
        ToolSpec(
            "get_event",
            "One event by its EVT id.",
            GetEventArgs,
            q.EventPage,
            R({"extractor", "correlator", "skeptic", "reporter"}),
            lambda p, c, a: _one(q.get_event(p, c, a.event_uid)),
        ),
        ToolSpec(
            "timeline_window",
            "Events of one host in a virtual time window.",
            TimelineArgs,
            q.EventPage,
            R({"extractor", "skeptic"}),
            lambda p, c, a: q.timeline_window(p, c, a.host, a.start, a.end, a.limit),
        ),
        ToolSpec(
            "get_detections",
            "Hayabusa detections by source label or event.",
            DetectionsArgs,
            q.DetectionPage,
            R({"extractor"}),
            lambda p, c, a: q.get_detections(p, c, a.evidence_label, a.event_uid, a.limit),
        ),
        ToolSpec(
            "source_summary",
            "Counts by event type and top users/processes of a source.",
            LabelArgs,
            q.SourceSummary,
            R({"planner", "extractor"}),
            lambda p, c, a: q.source_summary(p, c, a.evidence_label),
        ),
        ToolSpec(
            "graph_stats",
            "Counts of the evidence graph and IP resolution.",
            NoArgs,
            gq.GraphStats,
            R({"planner", "correlator", "skeptic"}),
            lambda p, c, a: gq.graph_stats(p, c),
        ),
        ToolSpec(
            "entity_summary",
            "One graph node: attributes, relations, citable events.",
            NodeArgs,
            gq.EntitySummary,
            R({"correlator", "skeptic"}),
            lambda p, c, a: gq.entity_summary(p, c, a.node_id),
        ),
        ToolSpec(
            "neighbors",
            "Edges around a graph node.",
            NeighborsArgs,
            gq.NeighborPage,
            R({"correlator", "skeptic"}),
            lambda p, c, a: gq.neighbors(p, c, a.node_id, a.relation, a.direction, a.limit),
        ),
        ToolSpec(
            "find_paths",
            "Shortest paths between two nodes (max 4 hops, 10 paths).",
            PathsArgs,
            gq.PathPage,
            R({"correlator", "skeptic"}),
            lambda p, c, a: gq.find_paths(p, c, a.from_node, a.to_node, a.max_hops, a.max_paths),
        ),
        ToolSpec(
            "host_links",
            "Host-to-host connections through shared conn ids.",
            LimitArgs,
            gq.HostLinks,
            R({"correlator", "skeptic", "reporter"}),
            lambda p, c, a: gq.host_links(p, c, a.limit),
        ),
        ToolSpec(
            "get_hits",
            "Stored detector hits (latest run per detector) or one hit by id.",
            GetHitsArgs,
            HitPage,
            R({"planner", "correlator", "skeptic", "reporter"}),
            lambda p, c, a: stored_hits(p, c, a.detector, a.hit_id, a.limit),
        ),
    ]
    descr = {
        "timestomp": "Compare $STANDARD_INFORMATION and $FILE_NAME times in file-system records.",
        "clock_skew": "Find sources whose clocks disagree about shared conn ids / pipe names.",
        "log_gap": "Find missing sequence numbers in auth logs and what happened meanwhile.",
        "log_clear": "Find cleared audit logs and the activity right after.",
        "unmatched_connection": "Find connection ids seen at only one end.",
    }
    for name, (_, model) in DETECTORS.items():
        t.append(ToolSpec(f"detect_{name}", descr[name] + " Explicit parameters override defaults.",
                          _det_args(name, model), DetectorResult, R({"correlator", "skeptic"}),
                          _run_det(name)))  # fmt: skip
    return {s.name: s for s in t}


def _one(ev: Any) -> q.EventPage:
    evs = [ev] if ev else []
    return q.EventPage(total_matches=len(evs), returned=len(evs), truncated=False, events=evs)


TOOLS: dict[str, ToolSpec] = _build()


def allowed_tools(role: str) -> list[str]:
    """Names of the tools a role may call."""
    return sorted(n for n, s in TOOLS.items() if role in s.roles)


def export_schemas(role: str | None = None) -> list[dict[str, Any]]:
    """JSON schemas of all tools (or of one role's tools), for Phase 5 tool calling."""
    return [s.schema() for n, s in sorted(TOOLS.items()) if role is None or role in s.roles]


def call_tool(
    role: str, name: str, args: dict[str, Any] | None, paths: Paths, case_id: str
) -> dict:
    """Validate, authorize, run and bound one tool call; returns a JSON-serializable dict."""
    if role not in ROLES:
        raise ToolError(f"unknown role {role!r}")
    spec = TOOLS.get(name)
    if spec is None:
        raise ToolError(f"unknown tool {name!r}")
    if role not in spec.roles:
        raise ToolError(f"role {role!r} may not call {name!r}")
    try:
        parsed = spec.params.model_validate(args or {})
    except ValidationError as e:
        bad = ", ".join(sorted({".".join(str(x) for x in err["loc"]) or "?" for err in e.errors()}))
        raise ToolError(f"invalid arguments for {name}: {bad}") from None
    try:
        result = spec.fn(paths, case_id, parsed).model_dump(mode="json")
    except ToolError:
        raise
    except UserError as e:
        raise ToolError(f"{name} failed: {e}") from None
    if len(json.dumps(result)) > MAX_OUTPUT_CHARS:
        raise ToolError(f"{name}: output too large; narrow the query")
    return result
