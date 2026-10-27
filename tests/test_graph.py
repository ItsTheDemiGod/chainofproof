"""Evidence graph: entity resolution, relations, unresolved IPs, deterministic export, tools."""

import json

import pytest

from chainofproof.custody.ledger import Ledger
from chainofproof.graph import entities as en
from chainofproof.graph.builder import build_graph
from chainofproof.graph.export import export_graph, graph_bytes
from chainofproof.schemas.scenario import Variant
from chainofproof.tools import graph_query as gq
from evfactory import auth, ev

CLEAN, PERT = "credtheft_lateral_v4_clean", "credtheft_lateral_v4_perturbed"
FORBIDDEN = ("source_key", "synth_only", "pair=", "SYNTHETIC", "GT-", "is_synthetic", "raw_note")


def rels(g, u, v):
    return sorted(d["relation"] for d in (g.get_edge_data(u, v) or {}).values())


def test_same_image_on_two_hosts_is_two_nodes_and_users_are_normalized():
    evs = [
        ev(etype="process_create", host="H1", process_image="cmd.exe", user="CORP\\Alice"),
        ev(etype="process_create", host="H2", process_image="CMD.EXE", user="alice"),
        ev(etype="logon", host="H1", user="PC1$", logon_type="3"),
    ]
    g = build_graph(evs)
    assert {"proc:H1:cmd.exe", "proc:H2:cmd.exe"} <= set(g.nodes)
    assert g.nodes["user:alice"]["event_count"] == 2
    assert g.nodes["user:alice"]["display_forms"] == ["CORP\\Alice", "alice"]
    assert g.nodes["user:pc1$"]["is_machine_account"] is True
    assert g.nodes["user:alice"].get("is_machine_account") is False
    assert en.user_id("DOM\\Bob") == "user:bob" and en.pipe_id("\\a\\b") == "pipe:a\\b"


def test_relations_from_structured_fields():
    evs = [
        ev(
            etype="process_create",
            process_image="b.exe",
            parent_image="a.exe",
            user="u",
            ts="2024-03-12T09:00:01.000000Z",
        ),
        ev(etype="process_access", process_image="a.exe", target_image="lsass.exe"),
        ev(etype="file_create", process_image="a.exe", file_path="C:\\x\\out.txt"),
        ev(
            etype="registry_set",
            process_image="a.exe",
            registry_target="HKLM\\S\\Run",
            service_name="svc1",
        ),
        ev(etype="pipe_created", process_image="a.exe", pipe_name="\\p1"),
        ev(etype="pipe_connected", process_image="a.exe", pipe_name="\\p1"),
        ev(
            etype="network_connect",
            process_image="a.exe",
            dst_ip="9.9.9.9",
            src_ip="10.0.0.5",
            fields={"Initiated": "true"},
        ),
        ev(
            etype="auth_logon",
            user="bob",
            src_ip="1.2.3.4",
            logon_type="3",
            fields={"auth_event": "LOGON_SUCCESS"},
        ),
        ev(etype="auth_logon", user="mallory", fields={"auth_event": "LOGON_FAILURE"}),
        ev(etype="other", pipe_name="p2"),
    ]
    g = build_graph(evs)
    assert rels(g, "proc:H1:a.exe", "proc:H1:b.exe") == ["spawned"]
    assert rels(g, "proc:H1:a.exe", "proc:H1:lsass.exe") == ["accessed"]
    assert rels(g, "proc:H1:a.exe", "file:H1:C:\\x\\out.txt") == ["created"]
    assert rels(g, "proc:H1:a.exe", "regkey:H1:HKLM\\S\\Run") == ["wrote"]
    assert rels(g, "host:H1", "svc:H1:svc1") == ["has_service"]
    assert rels(g, "proc:H1:a.exe", "pipe:p1") == ["connected_pipe", "created_pipe"]
    assert rels(g, "host:H1", "pipe:p2") == ["opened_pipe"]
    assert rels(g, "proc:H1:a.exe", "ip:9.9.9.9") == ["connected_to"]
    assert rels(g, "host:H1", "user:bob") == ["logged_on"]
    assert rels(g, "user:bob", "host:H1") == ["authenticated_to"]
    assert "user:mallory" in g and not g.has_edge("host:H1", "user:mallory")  # failed logon
    assert rels(g, "proc:H1:a.exe", "host:H1") == ["ran_on"]
    assert rels(g, "source:AUTH-aaaaaa", "host:H1") == ["observed_on"]


def test_ip_resolution_only_from_agent_view_evidence():
    evs = [
        ev(
            etype="network_connect",
            process_image="a.exe",
            src_ip="10.0.0.5",
            dst_ip="8.8.8.8",
            fields={"Initiated": "true"},
        ),
        auth(
            1,
            "2024-03-12T09:00:00.000000Z",
            "H1",
            "CONN_OUT",
            src_ip="10.0.0.9",
            dst_host="H2",
            conn_id="CONN-001",
        ),
        auth(2, "2024-03-12T09:00:00.000000Z", "H1", "LOGON_SUCCESS", src_ip="10.0.0.77"),
    ]
    g = build_graph(evs)
    assert rels(g, "ip:10.0.0.5", "host:H1") == ["used_by"]
    assert rels(g, "ip:10.0.0.9", "host:H1") == ["used_by"]  # the sender's own address
    assert rels(g, "ip:10.0.0.77", "host:H1") == ["seen_from"]  # not claimed as H1's address
    assert (g.graph["ip_resolved"], g.graph["ip_unresolved"]) == (2, 2)  # 8.8.8.8, .77 unresolved


def test_host_links_through_conn_ids_including_single_end():
    both = [
        auth(
            1,
            "2024-03-12T09:00:00.000000Z",
            "A",
            "CONN_OUT",
            src_ip="10.0.0.1",
            dst_host="B",
            conn_id="CONN-001",
            label="AUTH-aaaaaa",
        ),
        auth(
            1,
            "2024-03-12T09:00:00.000000Z",
            "B",
            "CONN_ACCEPTED",
            src_ip="10.0.0.1",
            dst_host="B",
            conn_id="CONN-001",
            label="AUTH-bbbbbb",
        ),
        auth(
            2,
            "2024-03-12T09:05:00.000000Z",
            "B",
            "CONN_OUT",
            src_ip="10.0.0.2",
            dst_host="C",
            conn_id="CONN-002",
            label="AUTH-bbbbbb",
        ),
    ]
    g = build_graph(both)
    ab = g.edges["host:A", "host:B", "connected_to"]
    assert ab["conn_ids"] == ["CONN-001"] and ab["ends_seen"] == {
        "A": "CONN_OUT",
        "B": "CONN_ACCEPTED",
    }
    bc = g.edges["host:B", "host:C", "connected_to"]
    assert bc["conn_ids"] == ["CONN-002"] and bc["ends_seen"] == {"B": "CONN_OUT"}


def test_edges_cap_event_uids_but_keep_the_total():
    evs = [ev(etype="process_create", process_image="a.exe") for _ in range(70)]
    d = build_graph(evs).edges["proc:H1:a.exe", "host:H1", "ran_on"]
    assert len(d["event_uids"]) == 50 and d["event_count"] == 70


def test_export_is_byte_identical_and_deterministic():
    evs = [ev(etype="process_create", process_image=f"p{i}.exe") for i in range(5)]
    assert graph_bytes(build_graph(evs)) == graph_bytes(build_graph(list(evs)))
    data = json.loads(graph_bytes(build_graph(evs)))
    ids = [n["id"] for n in data["nodes"]]
    assert ids == sorted(ids) and {"nodes", "edges", "meta"} == set(data)


def test_export_graph_records_run_and_ledger(synth_norm):
    paths, _ = synth_norm
    a, b = export_graph(paths, CLEAN), export_graph(paths, CLEAN)
    assert a.path.read_bytes() == b.path.read_bytes() and a.graph_sha256 == b.graph_sha256
    assert a.run_id != b.run_id and a.node_count > 100
    e = [x for x in Ledger(paths).read_all() if x.actor == "graph"][-1]
    assert e.output_hash == a.graph_sha256 and e.input_hashes and "RUN-" in e.command


def test_query_tools_bounded_and_without_eval_data(synth_norm, v4):
    paths, _ = synth_norm
    links_key = {k.id: k for k in v4.keys[Variant.perturbed].links}
    conn_a = links_key["GT-LNK-002"].evidence_refs[0].conn_id
    conn_b = links_key["GT-LNK-004"].evidence_refs[0].conn_id
    s = gq.graph_stats(paths, PERT)
    assert s.nodes_by_type["host"] == 3 and s.edges_by_relation["connected_to"] >= 1
    page = gq.neighbors(paths, PERT, "host:SRV-FILE-02")
    assert page.returned == 25 and page.truncated and page.total_matches > 25
    assert gq.neighbors(paths, PERT, "host:SRV-FILE-02", limit=1000).returned == 50
    only = gq.neighbors(paths, PERT, "host:SRV-FILE-02", relation="connected_to", direction="out")
    assert [i.node_id for i in only.items] == ["host:DC-01"] and only.items[0].event_uids
    ent = gq.entity_summary(paths, PERT, "host:SRV-FILE-02")
    assert ent.type == "host" and ent.event_uids and len(ent.event_uids) <= 50
    links = gq.host_links(paths, PERT)
    pairs = {(x.from_host, x.to_host): x.conn_ids for x in links.links}
    # v4: the key links are two of many connections between the logged hosts (ids are time-ordered)
    assert (
        conn_a in pairs[("WS-FIN-07", "SRV-FILE-02")]
        and len(pairs[("WS-FIN-07", "SRV-FILE-02")]) > 5
    )
    assert conn_b in pairs[("SRV-FILE-02", "DC-01")] and len(pairs[("SRV-FILE-02", "DC-01")]) > 5
    assert ("DC-01", "WS-FIN-07") not in pairs  # benign connections never start on the DC
    blob = " ".join(x.model_dump_json() for x in (s, page, only, ent, links))
    assert not [bad for bad in FORBIDDEN if bad in blob]


def test_find_paths_hops_and_limits(synth_norm):
    paths, _ = synth_norm
    r = gq.find_paths(paths, PERT, "host:WS-FIN-07", "host:DC-01", max_hops=4)
    assert r.returned >= 1 and all(len(p.nodes) - 1 <= 4 for p in r.paths)
    assert r.paths[0].nodes[0] == "host:WS-FIN-07" and r.paths[0].nodes[-1] == "host:DC-01"
    assert r.paths[0].hops[0].event_uids
    # v4: workstations also talk to the DC directly (benign kerberos/ldap), so one hop exists ...
    assert gq.find_paths(paths, PERT, "host:WS-FIN-07", "host:DC-01", max_hops=1).returned == 1
    # ... plus longer routes (the lateral one through the file server is in the host_links test)
    two = gq.find_paths(paths, PERT, "host:WS-FIN-07", "host:DC-01", max_hops=2)
    assert two.returned > 1
    assert gq.find_paths(paths, PERT, "host:WS-FIN-07", "host:DC-01", max_hops=99).max_hops == 4
    many = gq.find_paths(paths, PERT, "host:WS-FIN-07", "host:DC-01", max_paths=99)
    assert many.returned <= 10


def test_unknown_node_and_bad_direction(synth_norm):
    paths, _ = synth_norm
    with pytest.raises(gq.GraphQueryError):
        gq.entity_summary(paths, PERT, "host:NOPE")
    with pytest.raises(gq.GraphQueryError):
        gq.neighbors(paths, PERT, "host:DC-01", direction="sideways")
