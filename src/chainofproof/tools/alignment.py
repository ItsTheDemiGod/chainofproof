"""Alignment layer: per SOURCE FILE (via its source_key), never per computer name.

``IEWIN7`` appears in three real sources that map to three different virtual hosts, so aliases are
looked up in the alignment entry of the file being parsed. virtual_time = real_time + offset.
Synthetic files are already in virtual time (offset 0). Planted perturbations (clock skew,
timestomped times, removed lines) are NOT corrected here: the Phase 4 correlator must find them.
"""

from __future__ import annotations

from datetime import timedelta

from chainofproof.schemas.events import SourceKindName
from chainofproof.schemas.scenario import Scenario, SourceKind, SourceSpec
from chainofproof.tools.parse_common import ParseContext

KIND_MAP = {
    SourceKind.real_evtx: SourceKindName.evtx,
    SourceKind.synthetic_file_timeline: SourceKindName.fs_timeline,
    SourceKind.synthetic_auth_log: SourceKindName.auth_log,
}


def build_context(
    scenario: Scenario, spec: SourceSpec, evidence_id: str, evidence_sha256: str
) -> ParseContext:
    """Parse context of one evidence file: label inputs, offset and host aliases of its source."""
    offset, aliases = timedelta(0), {}
    if spec.kind == SourceKind.real_evtx:
        a = scenario.aligned(spec.source_key)
        offset = timedelta(seconds=a.time_offset_seconds)
        aliases = {real.lower(): virt for real, virt in a.host_aliases.items()}
    return ParseContext(
        evidence_id=evidence_id,
        evidence_sha256=evidence_sha256,
        source_key=spec.source_key,
        source_kind=KIND_MAP[spec.kind],
        is_synthetic=spec.is_synthetic,
        offset=offset,
        aliases=aliases,
        virtual_hosts=frozenset(h.hostname for h in scenario.virtual_hosts),
    )
