"""Phase 3 commands (registered on the main typer app by ``register``).

Agent-view commands (``events-stats``, ``events-show``) go through ``tools.query`` only.
``eval-coverage`` is EVAL ONLY (it reads the answer key). Nothing here prints raw evidence content,
command lines or Hayabusa output: ids, counts, hosts, rule titles/levels and basenames only.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from chainofproof.config import Paths, load_settings
from chainofproof.custody.migrations import migrate_to_v4
from chainofproof.eval.baseline import compute_baseline, totals_by_level, write_markdown
from chainofproof.eval.coverage import run_coverage
from chainofproof.tools import query
from chainofproof.tools.case_run import normalize_case
from chainofproof.tools.hayabusa import run_hayabusa
from chainofproof.tools.hayabusa_fp import hayabusa_fingerprint, locate_exe, run_help
from chainofproof.tools.runs import display_path


def register(app: typer.Typer, handled: Callable[..., Any], out: Console, err: Console) -> None:
    """Add the Phase 3 commands to ``app``."""

    def paths_of(ctx: typer.Context) -> Paths:
        return ctx.obj

    @app.command("tools-check")
    @handled
    def tools_check() -> None:
        """Check Hayabusa: present, version, exe hash, rules tree hash, can it run help."""
        cfg = load_settings().tools
        exe = locate_exe(cfg)
        fp = hayabusa_fingerprint(cfg)
        ran, _ = run_help(exe, cfg)
        out.print(f"hayabusa: {exe.name}  version {fp.version}")
        out.print(f"exe sha256:   {fp.exe_sha256[:16]}...")
        out.print(f"rules sha256: {(fp.rules_tree_sha256 or 'none')[:16]}...")
        out.print(f"help runs: {'yes' if ran else 'NO'}")
        if not ran:
            raise typer.Exit(1)

    @app.command("hayabusa-run")
    @handled
    def hayabusa_run(ctx: typer.Context, evidence_id: str) -> None:
        """Run Hayabusa on the working copy of one EVTX evidence item."""
        res = run_hayabusa(paths_of(ctx), evidence_id)
        out.print(
            f"{res.run_id}: {len(res.detections)} detections, {res.unparseable} unparseable "
            f"lines, ledger {res.ledger_id}, output {display_path(paths_of(ctx), res.output_path)}",
            highlight=False,
        )

    @app.command("db-migrate")
    @handled
    def db_migrate(ctx: typer.Context) -> None:
        """Migrate the database to the latest schema version (backup first; no-op if current)."""
        _migrate(paths_of(ctx))

    def _migrate(paths: Paths) -> None:
        m = migrate_to_v4(paths)
        if m.migrated:
            out.print(f"migrated v{m.from_version} -> v{m.to_version}; backup {m.backup_name} "
                      f"(sha256 {(m.backup_sha256 or '')[:16]}...)", highlight=False)  # fmt: skip

    @app.command("normalize")
    @handled
    def normalize(
        ctx: typer.Context,
        case_id: str,
        evidence: Annotated[str | None, typer.Option(help="Only this evidence id")] = None,
    ) -> None:
        """Normalize a case (migrates the database first) and run Hayabusa on every EVTX."""
        paths = paths_of(ctx)
        _migrate(paths)
        rows = normalize_case(paths, case_id, only=evidence)
        t = Table("evidence", "label", "kind", "hosts", "events", "detections", "unlinked",
                  "corrupt", title=case_id)  # fmt: skip
        for r in rows:
            t.add_row(r.evidence_id, r.label, r.source_kind, ",".join(r.hosts), str(r.events),
                      str(r.detections), str(r.unlinked), str(r.corrupt))  # fmt: skip
        out.print(t)

    @app.command("events-stats")
    @handled
    def events_stats(ctx: typer.Context, case_id: str) -> None:
        """Per-source event counts and event types (agent view only)."""
        paths = paths_of(ctx)
        t = Table("label", "kind", "hosts", "events", "first (virtual)", "last (virtual)",
                  title=case_id)  # fmt: skip
        for li in query.list_evidence_labels(paths, case_id):
            t.add_row(li.label, li.source_kind, ",".join(li.hosts), str(li.event_count),
                      (li.first_timestamp or "")[:19], (li.last_timestamp or "")[:19])  # fmt: skip
        out.print(t)
        for li in query.list_evidence_labels(paths, case_id):
            s = query.source_summary(paths, case_id, li.label)
            types = " ".join(f"{k}={v}" for k, v in s.by_event_type.items())
            out.print(f"{li.label}: {types}", highlight=False, markup=False)

    @app.command("events-show")
    @handled
    def events_show(
        ctx: typer.Context,
        case_id: str,
        host: Annotated[str | None, typer.Option(help="Virtual host")] = None,
        type_: Annotated[str | None, typer.Option("--type", help="Event type")] = None,
        limit: Annotated[int, typer.Option(help="Max 50")] = 25,
    ) -> None:
        """Show normalized events (agent view only)."""
        page = query.search_events(paths_of(ctx), case_id, host=host, event_type=type_, limit=limit)
        t = Table("timestamp", "host", "type", "event", "summary",
                  caption=f"{page.returned} of {page.total_matches}"
                          f"{' (truncated)' if page.truncated else ''}")  # fmt: skip
        for e in page.events:
            t.add_row(e.timestamp, e.host, e.event_type.value, e.event_uid, e.summary)
        out.print(t)

    @app.command("eval-coverage")
    @handled
    def eval_coverage(
        ctx: typer.Context,
        case_ids: list[str],
        baseline_md: Annotated[
            Path | None, typer.Option(help="Write the Hayabusa baseline")
        ] = None,
    ) -> None:
        """EVAL ONLY: key coverage, count/alignment checks and the Hayabusa-only baseline."""
        paths, bad, all_rows = paths_of(ctx), False, {}
        for case_id in case_ids:
            rep, idx, key, adj, scn = run_coverage(paths, case_id)
            rows = compute_baseline(paths, case_id, idx, key, adj, scn)
            all_rows[case_id] = rows
            out.print(f"[bold]{case_id}[/bold]: {rep.refs_checked} refs, "
                      f"{len(rep.unresolved)} unresolved, {len(rep.count_mismatches)} count "
                      f"mismatches, {rep.alignment_checked} alignment checks "
                      f"({len(rep.alignment_problems)} problems)")  # fmt: skip
            for name, state in rep.perturbations.items():
                out.print(f"  {name}: {state}", highlight=False, markup=False)
            for msg in [*rep.unresolved, *rep.count_mismatches, *rep.alignment_problems]:
                err.print(f"  - {msg}", highlight=False, markup=False)
            for kind in ("GT-ACT", "GT-ADJ"):
                n = sum(r.kind == kind for r in rows)
                tot = {k: v for k, v in totals_by_level(rows, kind).items() if v}
                out.print(f"  Hayabusa {kind}: {n - tot.get('none', 0)} of {n} detected {tot}",
                          highlight=False, markup=False)  # fmt: skip
            bad = bad or not rep.ok
        if baseline_md:
            write_markdown(baseline_md, all_rows)
        if bad:
            raise typer.Exit(1)
