"""Deterministic graph export (node-link JSON), graph_runs row and ledger entry."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import networkx as nx

from chainofproof.config import Paths
from chainofproof.custody.hashing import canonical_json, iso_utc, sha256_bytes, utc_now
from chainofproof.custody.ledger import Ledger
from chainofproof.custody.recorder import ToolRun
from chainofproof.graph.builder import build_graph
from chainofproof.ingest.store import EvidenceStore
from chainofproof.tools.loader import load_case_events
from chainofproof.tools.norm_store import require_version
from chainofproof.tools.runs import display_path, new_run_dir


def graph_to_json(g: nx.MultiDiGraph) -> dict[str, Any]:
    """Sorted node-link dict (nodes by id, edges by source/target/relation)."""
    nodes = [{"id": n, **d} for n, d in sorted(g.nodes(data=True), key=lambda x: x[0])]
    edges = sorted(
        ({"source": u, "target": v, **d} for u, v, d in g.edges(data=True)),
        key=lambda e: (e["source"], e["target"], e["relation"]),
    )
    meta = {
        "ip_resolved": g.graph.get("ip_resolved", 0),
        "ip_unresolved": g.graph.get("ip_unresolved", 0),
    }
    return {"nodes": nodes, "edges": edges, "meta": meta}


def graph_bytes(g: nx.MultiDiGraph) -> bytes:
    """Canonical JSON bytes of the graph (byte-identical for identical input)."""
    return (canonical_json(graph_to_json(g)) + "\n").encode("utf-8")


@dataclass
class GraphRun:
    """Outcome of ``export_graph``."""

    run_id: str
    path: Path
    node_count: int
    edge_count: int
    graph_sha256: str
    ledger_id: str
    graph: nx.MultiDiGraph


def export_graph(paths: Paths, case_id: str) -> GraphRun:
    """Build the case graph, write ``graph_<case>.json`` into a new run folder, record it."""
    require_version(paths, 3)
    events, input_sha = load_case_events(paths, case_id)
    g = build_graph(events)
    run_id, run_dir = new_run_dir(paths)
    out = run_dir / f"graph_{case_id}.json"
    command = f"graph-build {case_id} -> {display_path(paths, out)}"
    with ToolRun(Ledger(paths), "graph", command, [input_sha]) as tr:
        data = graph_bytes(g)
        out.write_bytes(data)
        tr.output = data
        tr.details.update({"run_id": run_id, "case_id": case_id, "nodes": g.number_of_nodes(),
                           "edges": g.number_of_edges()})  # fmt: skip
    assert tr.entry is not None
    digest = sha256_bytes(data)
    with EvidenceStore(paths).transaction() as conn:
        conn.execute(
            "INSERT INTO graph_runs(run_id, case_id, node_count, edge_count, graph_sha256, "
            "ledger_id, created_at) VALUES (?,?,?,?,?,?,?)",
            (run_id, case_id, g.number_of_nodes(), g.number_of_edges(), digest,
             tr.entry.ledger_id, iso_utc(utc_now())),
        )  # fmt: skip
    return GraphRun(run_id, out, g.number_of_nodes(), g.number_of_edges(), digest,
                    tr.entry.ledger_id, g)  # fmt: skip
