"""Deterministic generator of the SYNTHETIC companion sources and their perturbations.

Inputs: scenario.yaml, inventory.json (key events) and the scenario seed. No wall clock, no uuid,
no system randomness: the same inputs give byte-identical files. The perturbed variant is the
clean data plus exactly three recorded perturbations (P1 timestomp, P2 clock skew, P3 log gap; see
``gen_perturb``).

Every synthetic attacker record is paired with real events or marked synthetic_only (rule R1).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from chainofproof.custody.hashing import sha256_bytes
from chainofproof.scenarios.companions import Pairing
from chainofproof.scenarios.gen_auth import AuthResult, generate_all_auth, render_auth
from chainofproof.scenarios.gen_context import GenContext
from chainofproof.scenarios.gen_fs import generate_fs, render_fs
from chainofproof.scenarios.gen_perturb import clock_skew, line_at, log_gap, slug, timestomp
from chainofproof.scenarios.gen_vocab import HOSTS
from chainofproof.scenarios.inventory import Inventory
from chainofproof.schemas.scenario import GroundTruthContradiction, Scenario, Variant


@dataclass
class GenResult:
    """What was generated: file hashes, where attacker artifacts/lines are, contradictions."""

    hashes: dict[str, str]
    fs_ids: dict[str, tuple[str, int]] = field(default_factory=dict)  # tag -> (source_key, id)
    auth_seq: dict[str, tuple[str, int]] = field(default_factory=dict)  # present lines only
    pairings: dict[str, Pairing] = field(default_factory=dict)  # tag -> pairing (fs and auth)
    link_seq: dict[str, tuple[str, int]] = field(default_factory=dict)  # LINK_* tag, present only
    link_conn: dict[str, str] = field(default_factory=dict)  # LINK_A / LINK_B -> conn_id
    contradictions: list[GroundTruthContradiction] = field(default_factory=list)


def generate_variant(
    scenario: Scenario,
    inventory: Inventory,
    variant: Variant,
    out_dir: Path,
    real_pipes: dict[str, frozenset[str]] | None = None,
) -> GenResult:
    """Write the companion files of one variant into out_dir; returns hashes and bookkeeping.

    ``real_pipes`` (virtual host -> pipe names of its REAL events) keeps benign pipe lines from
    ever sharing a name with a real pipe event of the same host.
    """
    ctx = GenContext(scenario, inventory, real_pipes or {})
    texts: dict[str, str] = {}
    res = GenResult(hashes={})
    all_auth = generate_all_auth(ctx)  # all hosts together: connection ids are global
    res.link_conn = {
        "LINK_A": line_at(all_auth["WS-FIN-07"], "LINK_A:src")["conn_id"],
        "LINK_B": line_at(all_auth["SRV-FILE-02"], "LINK_B:src")["conn_id"],
    }
    for host in HOSTS:
        fs, auth = generate_fs(ctx, host), all_auth[host]
        fsk, auk = f"fs_{slug(host)}", f"auth_{slug(host)}"
        if variant == Variant.perturbed:
            if host == "SRV-FILE-02":
                res.contradictions.append(timestomp(ctx, fs, host))
                res.contradictions.append(clock_skew(ctx, auth, host, all_auth))
            if host == "DC-01":
                res.contradictions.append(log_gap(ctx, auth, host, all_auth))
        texts[scenario.source(fsk).relative_path] = render_fs(ctx, fs.rows)
        texts[scenario.source(auk).relative_path] = render_auth(ctx, auth.lines)
        res.fs_ids.update({t: (fsk, i) for t, i in fs.artifacts.items()})
        res.auth_seq.update({t: (auk, s) for t, s in auth.key_seq.items() if _present(auth, s)})
        res.link_seq.update({t: (auk, s) for t, s in auth.link_seq.items() if _present(auth, s)})
        res.pairings.update(fs.pairings)
        res.pairings.update(auth.pairings)
    res.contradictions.sort(key=lambda c: c.id)
    out_dir.mkdir(parents=True, exist_ok=True)
    for rel in sorted(texts):
        data = texts[rel].encode("utf-8")
        (out_dir / rel).write_bytes(data)
        res.hashes[rel] = sha256_bytes(data)
    return res


def _present(auth: AuthResult, seq: int) -> bool:
    return any(int(ln["seq"]) == seq for ln in auth.lines)
