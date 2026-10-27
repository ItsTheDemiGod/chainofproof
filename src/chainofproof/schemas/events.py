"""Normalized event schemas: the AGENT VIEW and the EVAL LAYER (kept strictly apart).

``NormalizedEvent`` is the only event shape an agent can ever see: opaque labels and IDs, virtual
time, virtual hosts, no ground-truth hints. ``EventEvalMeta`` holds everything stripped from it
(source key, raw locator, real computer, real time, pairing markers) and is read only by code in
``chainofproof/eval/``, ``chainofproof/scenarios/``, ``scripts/``, ``tests/`` and CLI modules.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

EVENT_UID_RE = r"^EVT-[0-9a-f]{12}$"
LABEL_RE = r"^(EVTX|FSTL|AUTH)-[0-9a-f]{6}$"
DETECTION_ID_RE = r"^DET-\d{6}$"
RUN_ID_RE = r"^RUN-\d{6}$"
MAX_FIELDS = 40
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")

EventUid = Annotated[str, StringConstraints(pattern=EVENT_UID_RE)]
EvidenceLabel = Annotated[str, StringConstraints(pattern=LABEL_RE)]


class SourceKindName(StrEnum):
    """Kind of the source file an event came from."""

    evtx = "evtx"
    fs_timeline = "fs_timeline"
    auth_log = "auth_log"


LABEL_PREFIX = {
    SourceKindName.evtx: "EVTX",
    SourceKindName.fs_timeline: "FSTL",
    SourceKindName.auth_log: "AUTH",
}


class EventType(StrEnum):
    """Small fixed set of normalized event types."""

    process_create = "process_create"
    network_connect = "network_connect"
    image_load = "image_load"
    process_access = "process_access"
    file_create = "file_create"
    registry_set = "registry_set"
    pipe_created = "pipe_created"
    pipe_connected = "pipe_connected"
    logon = "logon"
    special_privileges = "special_privileges"
    audit_log_cleared = "audit_log_cleared"
    directory_service_access = "directory_service_access"
    service_install = "service_install"
    process_create_security = "process_create_security"
    file_timeline = "file_timeline"
    auth_logon = "auth_logon"
    auth_conn = "auth_conn"
    other = "other"


class NormalizedEvent(BaseModel):
    """Agent view of one event. Free text is sanitized and capped; no raw XML, ever."""

    model_config = ConfigDict(extra="forbid")

    event_uid: EventUid
    evidence_label: EvidenceLabel
    source_kind: SourceKindName
    host: str  # VIRTUAL host name
    timestamp: str  # VIRTUAL, UTC, microseconds: YYYY-MM-DDTHH:MM:SS.ffffffZ
    event_type: EventType
    channel: str | None = None
    provider: str | None = None
    event_id: int | None = None
    record_id: int | None = None  # EventRecordID / seq / record_id: the locator an agent may cite
    user: str | None = None
    logon_type: str | None = None
    logon_id: str | None = None
    process_image: str | None = None  # basename
    parent_image: str | None = None  # basename
    target_image: str | None = None  # basename
    command_line: str | None = None
    command_line_length: int | None = None
    pipe_name: str | None = None
    service_name: str | None = None
    registry_target: str | None = None
    file_path: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    dst_host: str | None = None
    conn_id: str | None = None
    fields: dict[str, str] = Field(default_factory=dict)
    summary: str = ""
    injection_flags: list[str] = Field(default_factory=list)  # reserved for Phase 7
    truncated: bool = False

    def model_post_init(self, __context: object) -> None:
        """Hard limits: timestamp format and at most MAX_FIELDS extra fields."""
        if not _TS_RE.match(self.timestamp):
            raise ValueError("timestamp must be YYYY-MM-DDTHH:MM:SS.ffffffZ")
        if len(self.fields) > MAX_FIELDS:
            raise ValueError(f"more than {MAX_FIELDS} fields")


class EventEvalMeta(BaseModel):
    """EVAL LAYER: what was stripped from the agent view. Never imported by agent-facing code."""

    model_config = ConfigDict(extra="forbid")

    event_uid: EventUid
    source_key: str
    evidence_id: str
    locator: str  # raw: EventRecordID, or fs record_id, or auth seq (as text)
    real_computer: str | None = None
    real_timestamp: str | None = None
    synth_only: bool = False
    pair_field: str | None = None
    pair_value: str | None = None
    is_synthetic: bool = False
    raw_note: str | None = None


class Detection(BaseModel):
    """One Hayabusa detection (sanitized); timestamp and computer are as printed (REAL values)."""

    model_config = ConfigDict(extra="forbid")

    rule_title: str
    rule_id: str | None = None
    level: str
    mitre_tags: list[str] = Field(default_factory=list)
    record_id: int | None = None
    channel: str | None = None
    computer: str | None = None
    timestamp: str | None = None
    event_id: int | None = None


class AgentDetection(BaseModel):
    """Agent view of a detection: virtual time and host, linked to an event when possible."""

    model_config = ConfigDict(extra="forbid")

    detection_id: Annotated[str, StringConstraints(pattern=DETECTION_ID_RE)]
    event_uid: EventUid | None
    evidence_label: EvidenceLabel
    rule_title: str
    rule_id: str | None
    level: str
    mitre_tags: list[str]
    record_id: int | None
