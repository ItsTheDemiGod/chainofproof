"""Agent-facing graph tools (agent-view data only; bounded; every result carries event_uids).

Default limit 25, hard maximum 50. Every list result reports ``total_matches`` and ``truncated``.
The graph is rebuilt from the latest normalized events of the case (cached by input hash).
"""

from __future__ import annotations

from itertools import islice
from typing import Any

import networkx as nx
from pydantic import BaseModel

from chainofproof.config import Paths
from chainofproof.errors import UserError
from chainofproof.graph.builder import build_graph
from chainofproof.tools.loader import load_case_events

DEFAULT_LIMIT, MAX_LIMIT, MAX_HOPS, MAX_PATHS = 25, 50, 4, 10
_CACHE: dict[tuple[str, str, str], nx.MultiDiGraph] = {}


class GraphQueryError(UserError):
    """Unknown node or bad argument."""


class GraphStats(BaseModel):
    """Counts of the case graph."""

    node_count: int
    edge_count: int
    nodes_by_type: dict[str, int]
    edges_by_relation: dict[str, int]
    ips_resolved: int
    ips_unresolved: int


class EntitySummary(BaseModel):
    """One node: attributes, degrees, relation counts and citable events."""

    node_id: str
    type: str
    first_seen: str
    last_seen: str
    event_count: int
    attributes: dict[str, Any]
    in_degree: int
    out_degree: int
    relations: dict[str, int]
    event_uids: list[str]
    event_uids_truncated: bool


class NeighborItem(BaseModel):
    """One edge seen from the queried node."""

    node_id: str
    relation: str
    direction: str  # out: queried node -> neighbor; in: neighbor -> queried node
    event_count: int
    first_ts: str
    last_ts: str
    event_uids: list[str]
    attributes: dict[str, Any]


class NeighborPage(BaseModel):
    """Bounded list of neighbors."""

    node_id: str
    total_matches: int
    returned: int
    truncated: bool
    items: list[NeighborItem]


class Hop(BaseModel):
    """One step of a path."""

    from_node: str
    to_node: str
    relations: list[str]
    event_uids: list[str]


class PathItem(BaseModel):
    """A path as nodes plus per-hop evidence."""

    nodes: list[str]
    hops: list[Hop]


class PathPage(BaseModel):
    """Bounded list of paths (shortest first)."""

    from_node: str
    to_node: str
    max_hops: int
    total_matches: int
    returned: int
    truncated: bool
    paths: list[PathItem]


class HostLink(BaseModel):
    """A host-to-host connection derived from shared conn ids."""

    from_host: str
    to_host: str
    conn_ids: list[str]
    ends_seen: dict[str, str]
    event_count: int
    first_ts: str
    last_ts: str
    event_uids: list[str]


class HostLinks(BaseModel):
    """All host-to-host links of a case."""

    total_matches: int
    returned: int
    truncated: bool
    links: list[HostLink]


def _graph(paths: Paths, case_id: str) -> nx.MultiDiGraph:
    events, sha = load_case_events(paths, case_id)
    key = (str(paths.db_path), case_id, sha)
    if key not in _CACHE:
        _CACHE[key] = build_graph(events)
    return _CACHE[key]


def _limit(limit: int | None) -> int:
    return max(1, min(limit if limit is not None else DEFAULT_LIMIT, MAX_LIMIT))


def _need(g: nx.MultiDiGraph, node: str) -> None:
    if node not in g:
        raise GraphQueryError(f"unknown node id {node[:80]!r} in this case")


def _attrs(d: dict[str, Any], skip: set[str]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if k not in skip}


NODE_BASE = {"type", "first_seen", "last_seen", "event_count"}
EDGE_BASE = {"relation", "event_uids", "event_count", "first_ts", "last_ts", "evidence_labels"}


def graph_stats(paths: Paths, case_id: str) -> GraphStats:
    """Node/edge counts by type and relation plus IP resolution counts."""
    g = _graph(paths, case_id)
    nt: dict[str, int] = {}
    er: dict[str, int] = {}
    for _, d in g.nodes(data=True):
        nt[d["type"]] = nt.get(d["type"], 0) + 1
    for _, _, d in g.edges(data=True):
        er[d["relation"]] = er.get(d["relation"], 0) + 1
    return GraphStats(
        node_count=g.number_of_nodes(), edge_count=g.number_of_edges(),
        nodes_by_type=dict(sorted(nt.items())), edges_by_relation=dict(sorted(er.items())),
        ips_resolved=g.graph["ip_resolved"], ips_unresolved=g.graph["ip_unresolved"],
    )  # fmt: skip


def entity_summary(paths: Paths, case_id: str, node_id: str) -> EntitySummary:
    """Attributes, degrees, relation counts and up to 50 citable event ids of one node."""
    g = _graph(paths, case_id)
    _need(g, node_id)
    d = g.nodes[node_id]
    rels: dict[str, int] = {}
    uids: list[str] = []
    for _, _, ed in [*g.out_edges(node_id, data=True), *g.in_edges(node_id, data=True)]:
        rels[ed["relation"]] = rels.get(ed["relation"], 0) + 1
        uids += ed["event_uids"]
    uniq = sorted(set(uids))
    return EntitySummary(
        node_id=node_id, type=d["type"], first_seen=d["first_seen"], last_seen=d["last_seen"],
        event_count=d["event_count"], attributes=_attrs(d, NODE_BASE),
        in_degree=g.in_degree(node_id), out_degree=g.out_degree(node_id),
        relations=dict(sorted(rels.items())), event_uids=uniq[:MAX_LIMIT],
        event_uids_truncated=len(uniq) > MAX_LIMIT,
    )  # fmt: skip


def neighbors(
    paths: Paths, case_id: str, node_id: str, relation: str | None = None,
    direction: str = "both", limit: int | None = None,
) -> NeighborPage:  # fmt: skip
    """Edges around a node, optionally filtered by relation and direction (out|in|both)."""
    if direction not in ("out", "in", "both"):
        raise GraphQueryError("direction must be out, in or both")
    g = _graph(paths, case_id)
    _need(g, node_id)
    items: list[NeighborItem] = []
    sides = []
    if direction in ("out", "both"):
        sides += [("out", v, d) for _, v, d in g.out_edges(node_id, data=True)]
    if direction in ("in", "both"):
        sides += [("in", u, d) for u, _, d in g.in_edges(node_id, data=True)]
    for way, other, d in sides:
        if relation is None or d["relation"] == relation:
            items.append(NeighborItem(
                node_id=other, relation=d["relation"], direction=way,
                event_count=d["event_count"], first_ts=d["first_ts"], last_ts=d["last_ts"],
                event_uids=d["event_uids"][:10], attributes=_attrs(d, EDGE_BASE),
            ))  # fmt: skip
    items.sort(key=lambda i: (i.first_ts, i.relation, i.node_id, i.direction))
    n = _limit(limit)
    return NeighborPage(node_id=node_id, total_matches=len(items), returned=min(n, len(items)),
                        truncated=len(items) > n, items=items[:n])  # fmt: skip


def find_paths(
    paths: Paths, case_id: str, from_node: str, to_node: str, max_hops: int = MAX_HOPS,
    max_paths: int = MAX_PATHS,
) -> PathPage:  # fmt: skip
    """Shortest simple paths (edge direction ignored), at most 4 hops and 10 paths."""
    hops = max(1, min(max_hops, MAX_HOPS))
    cap = max(1, min(max_paths, MAX_PATHS))
    g = _graph(paths, case_id)
    _need(g, from_node)
    _need(g, to_node)
    u = nx.Graph(g)
    found: list[list[str]] = []
    more = False
    if from_node != to_node and nx.has_path(u, from_node, to_node):
        for p in islice(nx.shortest_simple_paths(u, from_node, to_node), cap + 1):
            if len(p) - 1 > hops:
                break
            if len(found) == cap:
                more = True
                break
            found.append(p)
    items = [PathItem(nodes=p, hops=[_hop(g, a, b) for a, b in zip(p, p[1:], strict=False)])
             for p in found]  # fmt: skip
    return PathPage(from_node=from_node, to_node=to_node, max_hops=hops, total_matches=len(found),
                    returned=len(found), truncated=more, paths=items)  # fmt: skip


def _hop(g: nx.MultiDiGraph, a: str, b: str) -> Hop:
    rels, uids = [], []
    for x, y in ((a, b), (b, a)):
        for d in (g.get_edge_data(x, y) or {}).values():
            rels.append(d["relation"] if x == a else f"{d['relation']} (reverse)")
            uids += d["event_uids"][:5]
    return Hop(
        from_node=a, to_node=b, relations=sorted(set(rels)), event_uids=sorted(set(uids))[:10]
    )


def host_links(paths: Paths, case_id: str, limit: int | None = None) -> HostLinks:
    """Host-to-host connections found through shared conn ids (with the ends each log saw)."""
    g = _graph(paths, case_id)
    links = [
        HostLink(
            from_host=u.split(":", 1)[1],
            to_host=v.split(":", 1)[1],
            conn_ids=d.get("conn_ids", []),
            ends_seen=d.get("ends_seen", {}),
            event_count=d["event_count"],
            first_ts=d["first_ts"],
            last_ts=d["last_ts"],
            event_uids=d["event_uids"],
        )
        for u, v, d in g.edges(data=True)
        if d["relation"] == "connected_to" and u.startswith("host:") and v.startswith("host:")
    ]  # fmt: skip
    links.sort(key=lambda x: (x.first_ts, x.from_host, x.to_host))
    n = _limit(limit)
    return HostLinks(total_matches=len(links), returned=min(n, len(links)),
                     truncated=len(links) > n, links=links[:n])  # fmt: skip
