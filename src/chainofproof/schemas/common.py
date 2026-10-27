"""Shared building blocks of the scenario, answer-key and adjudication schemas.

ID patterns, enums, the strict base model and the YAML load/save helpers live here, in one
place. YAML is validated through JSON mode so enums and strings load cleanly.
"""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import yaml
from pydantic import BaseModel, ConfigDict, StringConstraints, ValidationError

from chainofproof.errors import UserError

ACT_ID_PATTERN = r"^GT-ACT-\d{3}$"
CON_ID_PATTERN = r"^GT-CON-\d{3}$"
DEC_ID_PATTERN = r"^GT-DEC-\d{3}$"
INJ_ID_PATTERN = r"^GT-INJ-\d{3}$"
MIS_ID_PATTERN = r"^GT-MIS-\d{3}$"
ADJ_ID_PATTERN = r"^GT-ADJ-\d{3}$"
LNK_ID_PATTERN = r"^GT-LNK-\d{3}$"
CONN_ID_PATTERN = r"^CONN-\d{3}$"
STAGE_ID_PATTERN = r"^(S[1-9]|D[1-9])$"
SOURCE_KEY_PATTERN = r"^[a-z0-9_]{1,48}$"
TECHNIQUE_PATTERN = r"^T\d{4}(\.\d{3})?$"
UTC_TS_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$"
SHA256_RE = r"^[0-9a-f]{64}$"

UtcTs = Annotated[str, StringConstraints(pattern=UTC_TS_PATTERN)]
SourceKey = Annotated[str, StringConstraints(pattern=SOURCE_KEY_PATTERN)]
StageId = Annotated[str, StringConstraints(pattern=STAGE_ID_PATTERN)]
Technique = Annotated[str, StringConstraints(pattern=TECHNIQUE_PATTERN)]


class ScenarioError(UserError):
    """A scenario, answer key or adjudication file is missing, invalid or inconsistent."""


class SourceKind(StrEnum):
    """What a source file is."""

    real_evtx = "real_evtx"
    synthetic_file_timeline = "synthetic_file_timeline"
    synthetic_auth_log = "synthetic_auth_log"


class Role(StrEnum):
    """Stage role."""

    storyline = "storyline"
    decoy = "decoy"


class Confidence(StrEnum):
    """Confidence level of a ground-truth label."""

    high = "high"
    medium = "medium"
    low = "low"


class ContradictionKind(StrEnum):
    """Anti-forensic contradiction kinds."""

    timestomp = "timestomp"
    log_gap = "log_gap"
    clock_skew = "clock_skew"


class LinkKind(StrEnum):
    """What a ground-truth cross-stage / cross-host link is."""

    credential_reuse = "credential_reuse"
    lateral_movement = "lateral_movement"
    remote_replication = "remote_replication"
    stage_continuation = "stage_continuation"


class LinkBasis(StrEnum):
    """Why the link exists: only SYNTHETIC lines say so, or only the alignment layer does."""

    synthetic_only = "synthetic_only"
    alignment_constructed = "alignment_constructed"


class Variant(StrEnum):
    """Dataset variant."""

    clean = "clean"
    perturbed = "perturbed"


class StrictModel(BaseModel):
    """Base of every schema: strict types, unknown fields rejected."""

    model_config = ConfigDict(strict=True, extra="forbid")


def load_model(path: Path, model: type[StrictModel]) -> Any:
    """Load a YAML file into ``model``; errors become ScenarioError (file, field, no content)."""
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return model.model_validate_json(json.dumps(data))
    except ValidationError as e:
        first = e.errors()[0]
        where = ".".join(str(x) for x in first["loc"])
        raise ScenarioError(
            f"{Path(path).name}: {where}: {first['msg']} ({e.error_count()} error(s))"
        ) from e
    except (OSError, ValueError, yaml.YAMLError) as e:
        raise ScenarioError(f"{Path(path).name}: {str(e).splitlines()[0]}") from e


def save_model(path: Path, obj: StrictModel) -> None:
    """Write a model as YAML (field order is the model order: deterministic)."""
    text = yaml.safe_dump(
        obj.model_dump(mode="json"), sort_keys=False, allow_unicode=True, width=100
    )
    Path(path).write_text(text, encoding="utf-8", newline="\n")
