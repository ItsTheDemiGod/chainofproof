"""Build the evidence graph (networkx MultiDiGraph) from agent-view events ONLY.

Nodes and edges come from fixed rules over structured fields (docs/graph.md). One edge exists per
(source, target, relation); it aggregates every event that supports it. Nothing here reads the
scenario IP map: an IP is attached to a host only when the events themselves show it (see
``_ip_rules``); all other IPs stay unresolved and are counted.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import networkx as nx

from chainofproof.graph import entities as en
from chainofproof.graph.entities import Rel
from chainofproof.schemas.events import EventType, NormalizedEvent

EDGE_UID_CAP = 50


class _Builder:
    def __init__(self) -> None:
        self.g: nx.MultiDiGraph = nx.MultiDiGraph()
        self.conn_groups: dict[str, list[NormalizedEvent]] = {}
        self._touched: set[str] = set()

    # ---- nodes / edges ------------------------------------------------------------------
    def node(self, nid: str, ev: NormalizedEvent, **attrs: Any) -> str:
        d = self.g.nodes.get(nid)
        if d is None:
            self.g.add_node(
                nid, type=en.node_type(nid), first_seen=ev.timestamp, last_seen=ev.timestamp,
                event_count=0,
            )  # fmt: skip
            d = self.g.nodes[nid]
        d["last_seen"] = max(d["last_seen"], ev.timestamp)
        d["first_seen"] = min(d["first_seen"], ev.timestamp)
        if nid not in self._touched:
            self._touched.add(nid)
            d["event_count"] += 1
        for k, v in attrs.items():
            if isinstance(v, set):
                d.setdefault(k, set()).update(v)
            elif k not in d:
                d[k] = v
        return nid

    def edge(self, u: str, v: str, rel: str, ev: NormalizedEvent, **extra: Any) -> None:
        if not self.g.has_edge(u, v, rel):
            self.g.add_edge(
                u, v, key=rel, relation=rel, event_uids=[], event_count=0,
                first_ts=ev.timestamp, last_ts=ev.timestamp, evidence_labels=set(),
            )  # fmt: skip
        d = self.g.edges[u, v, rel]
        d["event_count"] += 1
        if len(d["event_uids"]) < EDGE_UID_CAP and ev.event_uid not in d["event_uids"]:
            d["event_uids"].append(ev.event_uid)
        d["first_ts"], d["last_ts"] = (
            min(d["first_ts"], ev.timestamp),
            max(d["last_ts"], ev.timestamp),
        )
        d["evidence_labels"].add(ev.evidence_label)
        for k, val in extra.items():
            if isinstance(val, set):
                d.setdefault(k, set()).update(val)
            elif isinstance(val, dict):
                d.setdefault(k, {}).update(val)
            elif val is not None:
                d.setdefault(k, val)

    # ---- per-event rules ------------------------------------------------------------------
    def add_event(self, ev: NormalizedEvent) -> None:
        self._touched = set()
        host = self.node(en.host_id(ev.host), ev)
        self.edge(self.node(en.source_id(ev.evidence_label), ev), host, Rel.OBSERVED, ev)
        user = self._user(ev)
        proc = self._proc(ev, host, user)
        et, f = ev.event_type, ev.fields
        if et in (EventType.process_create, EventType.process_create_security) and ev.parent_image:
            parent = self.node(en.proc_id(ev.host, ev.parent_image), ev, name=ev.parent_image)
            self.edge(
                parent, self.node(en.proc_id(ev.host, ev.process_image or "?"), ev), Rel.SPAWNED, ev
            )
            self.edge(parent, host, Rel.RAN_ON, ev)
        if et == EventType.process_access and proc and ev.target_image:
            target = self.node(en.proc_id(ev.host, ev.target_image), ev, name=ev.target_image)
            self.edge(proc, target, Rel.ACCESSED, ev)
        if et == EventType.file_timeline and ev.file_path:
            self.edge(host, self.node(en.file_id(ev.host, ev.file_path), ev), Rel.HAS_FILE, ev)
        if et == EventType.file_create and proc and ev.file_path:
            self.edge(proc, self.node(en.file_id(ev.host, ev.file_path), ev), Rel.CREATED, ev)
        if et == EventType.registry_set and proc and ev.registry_target:
            self.edge(proc, self.node(en.regkey_id(ev.host, ev.registry_target), ev), Rel.WROTE, ev)
        if ev.service_name and et in (EventType.registry_set, EventType.service_install):
            self.edge(host, self.node(en.svc_id(ev.host, ev.service_name), ev), Rel.HAS_SERVICE, ev)
        if ev.pipe_name:
            pipe = self.node(en.pipe_id(ev.pipe_name), ev)
            if proc and et == EventType.pipe_created:
                self.edge(proc, pipe, Rel.CREATED_PIPE, ev)
            elif proc and et == EventType.pipe_connected:
                self.edge(proc, pipe, Rel.CONNECTED_PIPE, ev)
            else:
                self.edge(host, pipe, Rel.OPENED_PIPE, ev)
        self._logon(ev, host, user)
        self._network(ev, host, proc)
        if ev.conn_id:
            conn = self.node(en.conn_id_node(ev.conn_id), ev)
            end = {ev.host: f.get("auth_event", ev.event_type.value)}
            self.edge(host, conn, Rel.SAW_CONN, ev, ends=end)
            self.conn_groups.setdefault(ev.conn_id, []).append(ev)

    def _user(self, ev: NormalizedEvent) -> str | None:
        if not ev.user or ev.user == "-":
            return None
        key, display, machine = en.user_key(ev.user)
        return self.node(f"user:{key}", ev, display_forms={display}, is_machine_account=machine)

    def _proc(self, ev: NormalizedEvent, host: str, user: str | None) -> str | None:
        if not ev.process_image:
            return None
        proc = self.node(en.proc_id(ev.host, ev.process_image), ev, name=ev.process_image)
        self.edge(proc, host, Rel.RAN_ON, ev)
        if user:
            self.edge(proc, user, Rel.RAN_AS, ev)
        return proc

    def _logon(self, ev: NormalizedEvent, host: str, user: str | None) -> None:
        name = ev.fields.get("auth_event", "")
        if not user or name == "LOGON_FAILURE" or ev.event_type not in (
            EventType.logon, EventType.auth_logon,
        ):  # fmt: skip
            return
        self.edge(
            host, user, Rel.LOGGED_ON, ev, logon_types={ev.logon_type} if ev.logon_type else None
        )
        if ev.event_type == EventType.auth_logon:
            self.edge(user, host, Rel.AUTHENTICATED, ev, src_ips={ev.src_ip} if ev.src_ip else None)

    def _network(self, ev: NormalizedEvent, host: str, proc: str | None) -> None:
        initiated = ev.fields.get("Initiated", "").lower()
        if ev.event_type == EventType.network_connect:
            remote = ev.src_ip if initiated == "false" else ev.dst_ip
            if proc and remote:
                direction = "inbound" if initiated == "false" else "outbound"
                self.edge(proc, self.node(en.ip_id(remote), ev), Rel.CONNECTED_TO, ev,
                          directions={direction})  # fmt: skip
        self._ip_rules(ev, host, initiated)

    def _ip_rules(self, ev: NormalizedEvent, host: str, initiated: str) -> None:
        """Attach an IP to a host ONLY when the event itself shows the association."""
        local: str | None = None
        if ev.event_type == EventType.network_connect:
            local = (
                ev.src_ip if initiated == "true" else ev.dst_ip if initiated == "false" else None
            )
        elif ev.fields.get("auth_event") == "CONN_OUT":  # the sender's own address
            local = ev.src_ip
        if local:
            self.edge(self.node(en.ip_id(local), ev), host, Rel.USED_BY, ev)
        elif ev.src_ip and ev.event_type in (
            EventType.auth_logon,
            EventType.auth_conn,
            EventType.other,
        ):
            self.edge(self.node(en.ip_id(ev.src_ip), ev), host, "seen_from", ev)

    # ---- host-to-host links from conn ids --------------------------------------------------
    def host_links(self) -> None:
        ip_host = self._ip_hosts()
        for cid in sorted(self.conn_groups):
            evs = self.conn_groups[cid]
            ends = {e.host: e.fields.get("auth_event", e.event_type.value) for e in evs}
            sources = [e for e in evs if e.fields.get("auth_event") == "CONN_OUT" and e.dst_host]
            pairs = [(e.host, e.dst_host or "", e) for e in sources]
            if not sources:  # only a destination end: the source host must be provable from IPs
                for e in evs:
                    src = ip_host.get(e.src_ip or "")
                    if src and src != e.host:
                        pairs.append((src, e.host, e))
            for a, b, e in pairs:
                if a and b and a != b:
                    for nid in (en.host_id(a), en.host_id(b)):
                        if nid not in self.g:  # a host known only from a conn id: no own events
                            self.g.add_node(nid, type="host", first_seen=e.timestamp,
                                            last_seen=e.timestamp, event_count=0)  # fmt: skip
                    self.edge(en.host_id(a), en.host_id(b), Rel.CONNECTED_TO, e,
                              conn_ids={cid}, ends_seen=ends)  # fmt: skip

    def _ip_hosts(self) -> dict[str, str]:
        out: dict[str, set[str]] = {}
        for u, v, d in self.g.edges(data=True):
            if d["relation"] == Rel.USED_BY:
                out.setdefault(u.split(":", 1)[1], set()).add(v.split(":", 1)[1])
        return {ip: next(iter(h)) for ip, h in out.items() if len(h) == 1}

    # ---- finish ---------------------------------------------------------------------------
    def finish(self) -> nx.MultiDiGraph:
        ips = [n for n, d in self.g.nodes(data=True) if d["type"] == "ip"]
        resolved = [
            n
            for n in ips
            if any(d["relation"] == Rel.USED_BY for _, _, d in self.g.out_edges(n, data=True))
        ]
        self.g.graph["ip_resolved"] = len(resolved)
        self.g.graph["ip_unresolved"] = len(ips) - len(resolved)
        for _, d in self.g.nodes(data=True):
            for k, v in list(d.items()):
                if isinstance(v, set):
                    d[k] = sorted(v)
        for _, _, d in self.g.edges(data=True):
            for k, v in list(d.items()):
                if isinstance(v, set):
                    d[k] = sorted(v)
        return self.g


def build_graph(events: Iterable[NormalizedEvent]) -> nx.MultiDiGraph:
    """Evidence graph from events (processed in the order given; pass them sorted)."""
    b = _Builder()
    for ev in events:
        b.add_event(ev)
    b.host_links()
    return b.finish()
