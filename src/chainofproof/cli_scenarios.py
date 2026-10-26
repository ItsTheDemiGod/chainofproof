"""Scenario commands (registered on the main typer app by ``register``)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from chainofproof.config import Paths
from chainofproof.scenarios import build
from chainofproof.scenarios.dataset import scenario_dir
from chainofproof.scenarios.inventory import Inventory
from chainofproof.schemas.scenario import AnswerKey, ScenarioError, Variant, load_key, load_scenario

VariantArg = Annotated[Variant, typer.Argument(help="clean or perturbed")]
Force = Annotated[bool, typer.Option("--force", help="Overwrite existing outputs")]


def inventory_tables(inv: Inventory) -> list[Table]:
    """Metadata-only tables for a console (never raw event content)."""
    meta = Table("source", "records", "corrupt", "computers", "first", "span_s", "top EventIDs")
    for s in inv.sources:
        top = " ".join(f"{e.event_id}x{e.count}" for e in s.top_event_ids[:5])
        meta.add_row(
            s.source_key,
            str(s.record_count),
            str(s.corrupt_records),
            ",".join(s.computers),
            (s.first_event_time or "")[:19],
            f"{s.span_seconds:.0f}",
            top,
        )
    keys = Table("stage", "record", "EventID", "real time", "supports", "rationale")
    for sk in inv.key_events:
        for e in sk.result.events:
            keys.add_row(
                sk.stage_id,
                str(e.record_id),
                str(e.event_id),
                e.real_time[:23],
                ",".join(e.supports),
                e.rationale,
            )
        if sk.result.unresolved:
            keys.add_row(sk.stage_id, "-", "-", "-", "LOW", sk.result.note)
    return [meta, keys]


def key_tables(key: AnswerKey) -> list[Table]:
    """Pretty tables for an answer key."""
    act = Table("id", "stage", "technique", "host", "account", "virtual time", "conf", "refs")
    for a in key.actions:
        refs = ",".join(f"{r.source_key}:{r.event_record_id}" for r in a.supporting_refs)
        act.add_row(
            a.id,
            a.stage_id,
            a.attack_technique_id,
            a.virtual_host,
            a.account or "-",
            a.virtual_time[:19],
            a.confidence.value,
            refs,
        )
    con = Table("id", "kind", "magnitude", "sources", "detectable by")
    for c in key.contradictions:
        con.add_row(
            c.id,
            c.kind.value,
            f"{c.magnitude:g} {c.magnitude_unit}",
            ",".join(c.sources_involved),
            c.detectable_by,
        )
    dec = Table("id", "source", "why out of scope")
    for d in key.decoys:
        dec.add_row(d.id, d.source_key, d.why_out_of_scope)
    mis = Table("id", "missing evidence", "would confirm")
    for m in key.missing_evidence:
        mis.add_row(m.id, m.description, m.confirms_claim)
    return [act, con, dec, mis]


def register(app: typer.Typer, handled: Callable[..., Any], out: Console, err: Console) -> None:
    """Add the scenario-* commands to ``app``."""

    def paths_of(ctx: typer.Context) -> Paths:
        return ctx.obj

    @app.command("scenario-list")
    @handled
    def scenario_list() -> None:
        """List scenarios and their answer-key variants."""
        t = Table("scenario_id", "title", "variants")
        for row in build.list_scenarios():
            t.add_row(*row)
        out.print(t)

    @app.command("scenario-inventory")
    @handled
    def scenario_inventory(ctx: typer.Context, scenario_id: str, force: Force = False) -> None:
        """Inventory the real EVTX sources and discover key events (writes inventory.json)."""
        inv = build.inventory_scenario(paths_of(ctx), scenario_id, force)
        for t in inventory_tables(inv):
            out.print(t)

    @app.command("scenario-keys")
    @handled
    def scenario_keys(scenario_id: str) -> None:
        """(Re)write key_clean.yaml and key_perturbed.yaml from the inventory and generator."""
        for p in build.write_keys(scenario_id):
            out.print(f"wrote {p.name}")

    @app.command("scenario-generate")
    @handled
    def scenario_generate(
        ctx: typer.Context, scenario_id: str, variant: VariantArg, force: Force = False
    ) -> None:
        """Generate the SYNTHETIC companion files of one variant."""
        folder, gen = build.generate(paths_of(ctx), scenario_id, variant, force)
        t = Table("file", "bytes", "sha256")
        for rel, h in gen.hashes.items():
            t.add_row(rel, str((Path(folder) / rel).stat().st_size), h)
        out.print(t)

    @app.command("scenario-build")
    @handled
    def scenario_build(
        ctx: typer.Context, scenario_id: str, variant: VariantArg, force: Force = False
    ) -> None:
        """Verify dataset hashes, generate companions, create the case and ingest everything."""
        case_id, items = build.build_case(paths_of(ctx), scenario_id, variant, force)
        t = Table("evidence_id", "source_key", "type", "bytes", "sha256", title=f"case {case_id}")
        for i in items:
            t.add_row(i.evidence_id, i.source_key, i.source_type, str(i.size_bytes), i.sha256[:16])
        out.print(t)

    @app.command("scenario-verify")
    @handled
    def scenario_verify(ctx: typer.Context, scenario_id: str) -> None:
        """Check dataset hashes, alignment, key validity and generator determinism (exit 0/1)."""
        problems = build.verify_scenario(paths_of(ctx), scenario_id)
        if not problems:
            out.print(f"scenario {scenario_id}: OK (dataset hashes, keys, determinism)")
            return
        err.print(f"[red]scenario {scenario_id}: FAILED[/red]", highlight=False)
        for p in problems:
            err.print(f"  - {p}", highlight=False, markup=False)
        raise typer.Exit(1)

    @app.command("scenario-key-show")
    @handled
    def scenario_key_show(scenario_id: str, variant: VariantArg) -> None:
        """Pretty-print an answer key."""
        d = scenario_dir(scenario_id)
        f = d / build.KEY_FILES[variant]
        if not f.is_file():
            raise ScenarioError(f"{f.name} not found for {scenario_id}")
        key = load_key(f, load_scenario(d / "scenario.yaml"))
        for t in key_tables(key):
            out.print(t)
