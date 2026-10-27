"""Phase 4 commands: evidence graph, detectors, and the EVAL-ONLY evaluation/audit commands.

Agents never get ``detect-all``; it exists for humans and the eval harness. Nothing here prints
raw evidence content: ids, counts, hosts, labels, basenames, numbers and templated explanations.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from chainofproof.config import Paths
from chainofproof.custody.migrations import migrate_to_v3
from chainofproof.eval.detector_eval import evaluate_case
from chainofproof.eval.detector_report import write_baseline
from chainofproof.eval.style_audit import audit_case, write_audit
from chainofproof.graph.export import export_graph
from chainofproof.tools import graph_query as gq
from chainofproof.tools.detectors import DETECTORS
from chainofproof.tools.detectors.base import Hit
from chainofproof.tools.detectors.runner import run_detector, stored_hits
from chainofproof.tools.runs import display_path


def measures_text(h: Hit, width: int = 90) -> str:
    """One-line summary of the scalar measures (lists and dicts are shown by length)."""
    parts = []
    for k, v in h.measures.items():
        if isinstance(v, dict | list):
            parts.append(f"{k}[{len(v)}]")
        elif v is not None:
            parts.append(f"{k}={v}")
    return ", ".join(parts)[:width]


def hit_table(hits: list[Hit], title: str) -> Table:
    """Table: hit id, detector, kind, severity, host(s), key measures."""
    t = Table("hit", "detector", "kind", "severity", "host", "measures", title=title)
    for h in hits:
        t.add_row(h.hit_id or "-", h.detector, h.kind, h.severity, ",".join(h.hosts),
                  measures_text(h))  # fmt: skip
    return t


def register(app: typer.Typer, handled: Callable[..., Any], out: Console, err: Console) -> None:
    """Add the Phase 4 commands to ``app``."""

    def paths_of(ctx: typer.Context) -> Paths:
        m = migrate_to_v3(ctx.obj)  # safe: backup first, no-op when current
        if m.migrated:
            out.print(f"migrated v{m.from_version} -> v{m.to_version}; backup {m.backup_name} "
                      f"(sha256 {(m.backup_sha256 or '')[:16]}...)", highlight=False)  # fmt: skip
        return ctx.obj

    @app.command("graph-build")
    @handled
    def graph_build(ctx: typer.Context, case_id: str) -> None:
        """Build the evidence graph of a case, export it and record the run."""
        paths = paths_of(ctx)
        r = export_graph(paths, case_id)
        g = r.graph
        out.print(
            f"{r.run_id}: {r.node_count} nodes, {r.edge_count} edges, "
            f"IPs resolved {g.graph['ip_resolved']} / unresolved {g.graph['ip_unresolved']}, "
            f"sha256 {r.graph_sha256[:16]}..., {display_path(paths, r.path)}",
            highlight=False,
        )

    @app.command("graph-show")
    @handled
    def graph_show(
        ctx: typer.Context,
        case_id: str,
        node: Annotated[str | None, typer.Option(help="Node id, e.g. host:DC-01")] = None,
        limit: Annotated[int, typer.Option(help="Max 50")] = 25,
    ) -> None:
        """Graph statistics, or one node with its neighbors."""
        paths = paths_of(ctx)
        if node is None:
            s = gq.graph_stats(paths, case_id)
            t = Table(
                "what",
                "name",
                "count",
                title=f"{case_id}: {s.node_count} nodes, {s.edge_count} edges",
            )
            for k, v in s.nodes_by_type.items():
                t.add_row("node type", k, str(v))
            for k, v in s.edges_by_relation.items():
                t.add_row("relation", k, str(v))
            t.add_row("ip", "resolved / unresolved", f"{s.ips_resolved} / {s.ips_unresolved}")
            out.print(t)
            return
        e = gq.entity_summary(paths, case_id, node)
        span = f"{e.first_seen} .. {e.last_seen}"
        out.print(
            f"{e.node_id}: type {e.type}, {e.event_count} events, {span}, "
            f"in {e.in_degree} out {e.out_degree}",
            highlight=False,
        )
        page = gq.neighbors(paths, case_id, node, limit=limit)
        t = Table(
            "dir",
            "relation",
            "node",
            "events",
            "first",
            caption=f"{page.returned} of {page.total_matches}",
        )
        for i in page.items:
            t.add_row(i.direction, i.relation, i.node_id, str(i.event_count), i.first_ts[:19])
        out.print(t)

    @app.command("detect")
    @handled
    def detect(ctx: typer.Context, case_id: str, detector: str) -> None:
        """Run ONE detector (default parameters) and print its hits."""
        r = run_detector(paths_of(ctx), case_id, detector)
        out.print(hit_table(r.hits, f"{r.run_id} {detector}: {len(r.hits)} hit(s)"))

    @app.command("detect-all")
    @handled
    def detect_all(ctx: typer.Context, case_id: str) -> None:
        """Run every detector (humans and the eval harness only; agents never get this)."""
        paths = paths_of(ctx)
        out.print(
            "note: detect-all is for humans and the eval harness; agents call detectors one by one"
        )
        for name in DETECTORS:
            r = run_detector(paths, case_id, name)
            out.print(hit_table(r.hits, f"{r.run_id} {name}: {len(r.hits)} hit(s)"))

    @app.command("hits-show")
    @handled
    def hits_show(
        ctx: typer.Context,
        case_id: str,
        detector: Annotated[str | None, typer.Option(help="Only this detector")] = None,
    ) -> None:
        """Show stored hits (latest run of each detector)."""
        page = stored_hits(paths_of(ctx), case_id, detector, limit=50)
        out.print(hit_table(page.hits, f"{page.returned} of {page.total_matches}"))

    @app.command("eval-detectors")
    @handled
    def eval_detectors(
        ctx: typer.Context,
        case_ids: list[str],
        baseline_md: Annotated[Path | None, typer.Option(help="Write detector_baseline.md")] = None,
        robustness: Annotated[bool, typer.Option(help="Also run seeds 101-105")] = True,
    ) -> None:
        """EVAL ONLY: run all detectors and score them against the answer keys."""
        paths = paths_of(ctx)
        results = [evaluate_case(paths, c) for c in case_ids]
        for r in results:
            out.print(r.summary_text(), highlight=False, markup=False)
        if baseline_md:
            write_baseline(paths, baseline_md, results, robustness)
            out.print(f"wrote {baseline_md.name}")

    @app.command("style-audit")
    @handled
    def style_audit(
        ctx: typer.Context,
        case_ids: list[str],
        out_md: Annotated[Path | None, typer.Option("--out", help="Write style_audit.md")] = None,
    ) -> None:
        """EVAL ONLY: can referenced lines be told apart from benign ones by surface features?"""
        paths = paths_of(ctx)
        audits = [audit_case(paths, c) for c in case_ids]
        for a in audits:
            out.print(a.summary_text(), highlight=False, markup=False)
        if out_md:
            write_audit(out_md, audits)
            out.print(f"wrote {out_md.name}")
