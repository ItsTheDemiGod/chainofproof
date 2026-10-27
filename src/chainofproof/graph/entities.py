"""Entity resolution rules for the evidence graph (deterministic; see docs/graph.md).

* The same image name on two hosts is two different ``proc`` nodes (the host is part of the id).
* Account names are compared case-insensitively and WITHOUT a domain prefix; the original display
  forms are kept as an attribute. Names ending in ``$`` are machine accounts.
* Paths, registry targets and pipe names are used as given (already sanitized by the parsers),
  capped in length so a node id can never be huge.
"""

from __future__ import annotations

from dataclasses import dataclass

from chainofproof.ingest.sanitize import clean

ID_CAP = 200


def host_id(host: str) -> str:
    """``host:<virtual host>``."""
    return f"host:{host}"


def user_key(name: str) -> tuple[str, str, bool]:
    """(match key, display form, is_machine_account) of an account name."""
    display = clean(name, 128)
    short = display.rsplit("\\", 1)[-1].strip()
    return short.lower(), display, short.endswith("$")


def user_id(name: str) -> str:
    """``user:<normalized account name>``."""
    return f"user:{user_key(name)[0]}"


def proc_id(host: str, image: str) -> str:
    """``proc:<host>:<image basename, lower case>``."""
    return f"proc:{host}:{image.lower()}"


def file_id(host: str, path: str) -> str:
    """``file:<host>:<path>``."""
    return f"file:{host}:{path[:ID_CAP]}"


def ip_id(addr: str) -> str:
    """``ip:<address>``."""
    return f"ip:{addr}"


def conn_id_node(conn_id: str) -> str:
    """``conn:<conn_id>``."""
    return f"conn:{conn_id}"


def pipe_id(name: str) -> str:
    """``pipe:<pipe name>``: leading backslashes are dropped (``\\x`` and ``x`` are one pipe)."""
    return f"pipe:{name.lstrip(chr(92))[:ID_CAP]}"


def svc_id(host: str, name: str) -> str:
    """``svc:<host>:<service name>``."""
    return f"svc:{host}:{name[:ID_CAP]}"


def regkey_id(host: str, target: str) -> str:
    """``regkey:<host>:<target>`` (capped)."""
    return f"regkey:{host}:{target[:ID_CAP]}"


def source_id(label: str) -> str:
    """``source:<evidence label>``."""
    return f"source:{label}"


def node_type(node: str) -> str:
    """The type prefix of a node id."""
    return node.split(":", 1)[0]


@dataclass(frozen=True)
class Rel:
    """Relation names used by the builder."""

    OBSERVED = "observed_on"
    LOGGED_ON = "logged_on"
    RAN_ON = "ran_on"
    RAN_AS = "ran_as"
    SPAWNED = "spawned"
    ACCESSED = "accessed"
    CREATED = "created"
    WROTE = "wrote"
    CREATED_PIPE = "created_pipe"
    CONNECTED_PIPE = "connected_pipe"
    OPENED_PIPE = "opened_pipe"
    CONNECTED_TO = "connected_to"
    SAW_CONN = "saw_conn"
    AUTHENTICATED = "authenticated_to"
    USED_BY = "used_by"
    HAS_SERVICE = "has_service"
    HAS_FILE = "has_file"
