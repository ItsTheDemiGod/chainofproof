"""Freeze guard (rules E1 to E3): TEST-split cases run only under a matching ``prompt_freeze``.

A freeze records the prompt version, the hash of the agent settings block, the model and the hash
of all registered tool specs. ``run_agent`` calls ``check_run_allowed`` itself, so the guard cannot
be bypassed by calling the library instead of the CLI. Any later change of a prompt, a setting or a
tool spec makes the freeze stale and the run is refused.
"""

from __future__ import annotations

from dataclasses import dataclass

from chainofproof.config import AgentSettings, Paths
from chainofproof.custody.hashing import sha256_json
from chainofproof.custody.ledger import Ledger
from chainofproof.errors import UserError
from chainofproof.protocol.splits import Split, split_of

FIELDS = ("prompt_version", "settings_sha256", "tool_registry_sha256")


class FreezeError(UserError):
    """A TEST-split case was used without a matching freeze."""


@dataclass(frozen=True)
class Fingerprint:
    """What a freeze pins."""

    prompt_version: str
    settings_sha256: str
    tool_registry_sha256: str


def current_fingerprint(agent: AgentSettings) -> Fingerprint:
    """The fingerprint of the code and settings as they are now."""
    from chainofproof.agents.prompts import prompt_version  # lazy: agents import this package
    from chainofproof.tools.registry import TOOLS

    specs = [TOOLS[n].schema() for n in sorted(TOOLS)]
    return Fingerprint(prompt_version(), sha256_json(agent.model_dump()), sha256_json(specs))


def write_freeze(paths: Paths, agent: AgentSettings, model: str, note: str | None = None) -> str:
    """Append the ``prompt_freeze`` ledger entry (humans only, rule E3); returns its ledger id."""
    fp = current_fingerprint(agent)
    details = {"prompt_version": fp.prompt_version, "settings_sha256": fp.settings_sha256,
               "model": model, "tool_registry_sha256": fp.tool_registry_sha256}  # fmt: skip
    if note:
        details["note"] = note
    return (
        Ledger(paths)
        .append("protocol", "prompt_freeze", "agent-freeze", [], None, details)
        .ledger_id
    )


def _freezes(paths: Paths):
    return [e for e in Ledger(paths).read_all() if e.action == "prompt_freeze"]


def find_freeze(paths: Paths, fp: Fingerprint) -> str | None:
    """Ledger id of the latest freeze equal to ``fp`` in all three values, or None."""
    for e in reversed(_freezes(paths)):
        if all(e.details.get(k) == getattr(fp, k) for k in FIELDS):
            return e.ledger_id
    return None


def _refuse(paths: Paths, case_id: str, fp: Fingerprint) -> FreezeError:
    last = next(iter(reversed(_freezes(paths))), None)
    if last is None:
        return FreezeError(
            f"{case_id} is in the TEST split: no prompt_freeze exists (agent-freeze)"
        )
    changed = [k for k in FIELDS if last.details.get(k) != getattr(fp, k)]
    return FreezeError(
        f"{case_id} is in the TEST split: the freeze {last.ledger_id} is stale "
        f"({', '.join(changed)} changed); a new agent-freeze is required"
    )


def check_run_allowed(
    paths: Paths, case_id: str, agent: AgentSettings
) -> tuple[Split | None, str | None]:
    """(split, freeze ledger id). DEV and unassigned cases pass; TEST needs a matching freeze."""
    split = split_of(case_id)
    if split != "test":
        return split, None
    fp = current_fingerprint(agent)
    fid = find_freeze(paths, fp)
    if fid is None:
        raise _refuse(paths, case_id, fp)
    return split, fid


def record_test_run(paths: Paths, freeze_id: str, case_id: str, run_id: str) -> None:
    """Ledger entry ``test_split_run`` at the start of a TEST-split run."""
    details = {"freeze_ledger_id": freeze_id, "case_id": case_id, "run_id": run_id}
    Ledger(paths).append("protocol", "test_split_run", f"agent-run {case_id}", [], None, details)
