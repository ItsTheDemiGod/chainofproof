"""Command-line interface (typer + rich)."""

from __future__ import annotations

import functools
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from chainofproof.config import Paths, get_paths
from chainofproof.custody.ledger import Ledger
from chainofproof.errors import UserError
from chainofproof.ingest.ingest import ingest_evidence
from chainofproof.ingest.integrity import get_working_copy, verify_all, verify_evidence
from chainofproof.ingest.store import EvidenceStore
from chainofproof.schemas.custody import EvidenceRecord, IntegrityResult, SourceType

app = typer.Typer(
    help="ChainOfProof: evidence ingestion and chain of custody.", no_args_is_help=True
)
out = Console()
err = Console(stderr=True)


@app.callback()
def main(
    ctx: typer.Context,
    base_dir: Annotated[
        Path | None,
        typer.Option(
            "--base-dir",
            envvar="CHAINOFPROOF_BASE_DIR",
            hidden=True,
            help="Alternate data root (tests and demos); default is data/ from settings.yaml.",
        ),
    ] = None,
) -> None:
    """Resolve the data folders once and share them with every command."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(console=err, show_path=False)],
    )
    paths = get_paths(base_dir=base_dir) if base_dir else get_paths()
    paths.ensure_dirs()
    ctx.obj = paths


def _handled(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Turn expected errors into one clean line and a non-zero exit code."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except UserError as e:
            err.print(f"[red]error:[/red] {e}", highlight=False)
            raise typer.Exit(1) from None

    return wrapper


def _paths(ctx: typer.Context) -> Paths:
    return ctx.obj


def _print_result(res: IntegrityResult, label: str) -> None:
    status = "[green]OK[/green]" if res.ok else "[red]FAILED[/red]"
    out.print(f"{label}: {status} ({res.checked} checked)")
    for p in res.problems:
        out.print(f"  - {p}", highlight=False, markup=False)


@app.command("case-create")
@_handled
def case_create(
    ctx: typer.Context,
    case_id: str,
    title: Annotated[str, typer.Option(help="Case title")] = "",
    description: Annotated[str, typer.Option(help="Case description")] = "",
) -> None:
    """Create a case (its ID becomes a folder name)."""
    paths = _paths(ctx)
    case = EvidenceStore(paths).create_case(case_id, title, description)
    Ledger(paths).append("cli", "case_create", details={"case_id": case_id, "title": title})
    out.print(f"created case {case.case_id}")


@app.command("case-list")
@_handled
def case_list(ctx: typer.Context) -> None:
    """List cases."""
    t = Table("case_id", "title", "created_at")
    for c in EvidenceStore(_paths(ctx)).list_cases():
        t.add_row(c.case_id, c.title, c.created_at.isoformat())
    out.print(t)


@app.command()
@_handled
def ingest(
    ctx: typer.Context,
    case_id: str,
    file_path: Path,
    description: Annotated[str, typer.Option(help="Free-text description")] = "",
    type_: Annotated[SourceType | None, typer.Option("--type", help="Override detection")] = None,
) -> None:
    """Ingest a file into the evidence vault."""
    rec = ingest_evidence(_paths(ctx), case_id, file_path, description, type_)
    out.print(f"{rec.evidence_id}  {rec.source_type.value}  {rec.size_bytes} bytes  {rec.sha256}")


def _evidence_table(rows: list[EvidenceRecord]) -> Table:
    t = Table("evidence_id", "case", "name", "type", "bytes", "sha256")
    for r in rows:
        t.add_row(
            r.evidence_id, r.case_id, r.original_name, r.source_type.value, str(r.size_bytes),
            r.sha256[:16] + "...",
        )  # fmt: skip
    return t


@app.command("evidence-list")
@_handled
def evidence_list(
    ctx: typer.Context, case: Annotated[str | None, typer.Option(help="Filter by case")] = None
) -> None:
    """List evidence."""
    out.print(_evidence_table(EvidenceStore(_paths(ctx)).list_evidence(case)))


@app.command("evidence-show")
@_handled
def evidence_show(ctx: typer.Context, evidence_id: str) -> None:
    """Show one evidence record."""
    rec = EvidenceStore(_paths(ctx)).get_evidence(evidence_id)
    if rec is None:
        raise UserError(f"unknown evidence id: {evidence_id}")
    t = Table("field", "value", show_header=False)
    for k, v in rec.model_dump(mode="json").items():
        t.add_row(k, str(v))
    out.print(t)


@app.command("verify-evidence")
@_handled
def verify_evidence_cmd(
    ctx: typer.Context,
    evidence_id: Annotated[str | None, typer.Argument()] = None,
    case: Annotated[str | None, typer.Option(help="Verify only this case")] = None,
) -> None:
    """Verify one evidence item, or all of them."""
    paths = _paths(ctx)
    res = verify_evidence(paths, evidence_id) if evidence_id else verify_all(paths, case)
    _print_result(res, evidence_id or "evidence")
    if not res.ok:
        raise typer.Exit(1)


@app.command("working-copy")
@_handled
def working_copy(ctx: typer.Context, evidence_id: str) -> None:
    """Create (or reuse) the verified read-only working copy and print its path."""
    out.print(str(get_working_copy(_paths(ctx), evidence_id)), highlight=False, markup=False)


@app.command("ledger-show")
@_handled
def ledger_show(
    ctx: typer.Context, tail: Annotated[int, typer.Option(help="Show the last N entries")] = 20
) -> None:
    """Show recent ledger entries."""
    t = Table("ledger_id", "timestamp", "actor", "action", "entry_hash")
    for e in Ledger(_paths(ctx)).tail(tail):
        t.add_row(
            e.ledger_id, e.timestamp.isoformat(), e.actor, e.action, e.entry_hash[:16] + "..."
        )
    out.print(t)


@app.command("ledger-verify")
@_handled
def ledger_verify(ctx: typer.Context) -> None:
    """Verify the ledger chain and head anchor (exit 1 if broken)."""
    res = Ledger(_paths(ctx)).verify()
    if res.ok:
        out.print(f"ledger OK: {res.checked} entries, chain and head anchor consistent")
        return
    err.print(f"[red]ledger BROKEN:[/red] first problem: {res.problems[0]}", highlight=False)
    for p in res.problems[1:]:
        err.print(f"  - {p}", highlight=False, markup=False)
    raise typer.Exit(1)


@app.command("ledger-head")
@_handled
def ledger_head(ctx: typer.Context) -> None:
    """Print the ledger head (ledger_id, count, entry_hash) as JSON."""
    out.print(
        json.dumps(Ledger(_paths(ctx)).export_head(), indent=2), highlight=False, markup=False
    )
