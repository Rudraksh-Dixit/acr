"""NetworkX attack-graph construction for a reconstructed chain.

Produces a frontend-ready payload: nodes (EVENT/USER/HOST/PROCESS/FILE/IP/
DOMAIN/TECHNIQUE) and edges with explicit relationship types.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

import networkx as nx

from app.ingestion.entity_extractor import display_entity, process_entity_value

REL_GENERATED = "GENERATED"
REL_AUTHENTICATED = "AUTHENTICATED"
REL_SPAWNED = "SPAWNED"
REL_CREATED = "CREATED"
REL_MODIFIED = "MODIFIED"
REL_CONNECTED = "CONNECTED"
REL_DOWNLOADED = "DOWNLOADED"
REL_EXECUTED = "EXECUTED"
REL_ASSOCIATED = "ASSOCIATED_WITH"
REL_PRECEDES = "PRECEDES"


def _entity_node(entity_type: str, value: str) -> dict[str, Any]:
    return {
        "id": f"{entity_type}:{value}",
        "type": entity_type,
        "label": display_entity(entity_type, value),
        "value": value,
    }


def build_attack_graph(
    events: list[dict[str, Any]],
    detections: list[dict[str, Any]] | None = None,
    chain_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    graph = nx.DiGraph()
    detections = detections or []
    det_by_event: dict[str, list[dict[str, Any]]] = {}
    for det in detections:
        if det.get("event_id"):
            det_by_event.setdefault(str(det["event_id"]), []).append(det)

    events_sorted = sorted(
        events,
        key=lambda e: (e.get("timestamp") is None, e.get("timestamp") or datetime.min),
    )

    for event in events_sorted:
        eid = event.get("event_id")
        if not eid:
            continue
        ts = event.get("timestamp")
        graph.add_node(
            eid,
            type="EVENT",
            label=event.get("event_type", "EVENT"),
            event_id=eid,
            event_type=event.get("event_type"),
            timestamp=(ts.isoformat() + "Z") if isinstance(ts, datetime) else None,
            severity=event.get("severity", "INFO"),
            host=event.get("host"),
            user=event.get("user"),
            process=event.get("process_name"),
            command_line=event.get("command_line"),
            technique_id=event.get("technique_id"),
        )

        host = event.get("host")
        user = event.get("user")
        if host:
            graph.add_node(f"HOST:{host}", **_entity_node("HOST", host))
            graph.add_edge(eid, f"HOST:{host}", relation=REL_ASSOCIATED, detail="event occurred on host")
        if user:
            graph.add_node(f"USER:{user}", **_entity_node("USER", user))
            relation = REL_AUTHENTICATED if event.get("event_type") in {
                "LOGIN_SUCCESS", "LOGIN_ATTEMPT", "AUTHENTICATION", "PRIVILEGE_CHANGE"
            } else REL_ASSOCIATED
            graph.add_edge(eid, f"USER:{user}", relation=relation, detail=f"actor {user}")

        proc = process_entity_value(host, event.get("process_name"))
        if proc:
            graph.add_node(f"PROCESS:{proc}", **_entity_node("PROCESS", proc))
            relation = REL_SPAWNED if event.get("event_type") == "PROCESS_CREATED" else REL_ASSOCIATED
            graph.add_edge(eid, f"PROCESS:{proc}", relation=relation, detail="process involved")
        parent_proc = process_entity_value(host, event.get("parent_process"))
        if parent_proc:
            graph.add_node(f"PROCESS:{parent_proc}", **_entity_node("PROCESS", parent_proc))
            graph.add_edge(eid, f"PROCESS:{parent_proc}", relation=REL_ASSOCIATED, detail="parent process")
        if parent_proc and proc and parent_proc != proc:
            graph.add_edge(f"PROCESS:{parent_proc}", f"PROCESS:{proc}", relation=REL_SPAWNED,
                           detail="process lineage", event_id=eid)

        file_path = event.get("file_path")
        if file_path:
            graph.add_node(f"FILE:{file_path}", **_entity_node("FILE", file_path))
            etype = event.get("event_type")
            if etype == "FILE_CREATED":
                relation = REL_CREATED
            elif etype == "FILE_MODIFIED" or etype == "REGISTRY_MODIFIED":
                relation = REL_MODIFIED
            elif etype == "PROCESS_CREATED":
                relation = REL_EXECUTED
            else:
                relation = REL_ASSOCIATED
            graph.add_edge(eid, f"FILE:{file_path}", relation=relation, detail=f"file {relation.lower()}")

        for field, relation in (("destination_ip", REL_CONNECTED), ("source_ip", REL_ASSOCIATED)):
            ip = event.get(field)
            if ip:
                graph.add_node(f"IP:{ip}", **_entity_node("IP", ip))
                graph.add_edge(eid, f"IP:{ip}", relation=relation, detail=f"{field} {ip}")
        if event.get("domain"):
            domain = str(event["domain"])
            graph.add_node(f"DOMAIN:{domain}", **_entity_node("DOMAIN", domain))
            graph.add_edge(eid, f"DOMAIN:{domain}", relation=REL_ASSOCIATED, detail="DNS/parsed domain")

        technique_id = event.get("technique_id")
        if technique_id:
            graph.add_node(f"TECHNIQUE:{technique_id}", type="TECHNIQUE",
                           label=event.get("technique_name") or technique_id,
                           value=technique_id, tactic=event.get("tactic"))
            graph.add_edge(eid, f"TECHNIQUE:{technique_id}", relation=REL_ASSOCIATED,
                           detail=event.get("technique_name") or technique_id)

    for det in detections:
        eid = det.get("event_id")
        tid = det.get("technique_id")
        if eid and tid and eid in graph:
            node_id = f"TECHNIQUE:{tid}"
            if node_id not in graph:
                graph.add_node(node_id, type="TECHNIQUE", label=det.get("technique_name") or tid,
                               value=tid, tactic=det.get("tactic"))
            graph.add_edge(eid, node_id, relation=REL_ASSOCIATED, detail=det.get("title", "detection"))

    # temporal precedence edges for replay animation
    sequence = [e["event_id"] for e in events_sorted if e.get("event_id") in graph]
    for prev, curr in zip(sequence, sequence[1:]):
        graph.add_edge(prev, curr, relation=REL_PRECEDES, detail="temporal order")

    nodes = []
    for node_id, props in graph.nodes(data=True):
        nodes.append({"id": node_id, **props})
    edges = []
    for index, (src, dst, props) in enumerate(graph.edges(data=True), start=1):
        edges.append({"id": f"e{index}", "source": src, "target": dst, **props})

    metadata: dict[str, Any] = {
        "node_count": graph.number_of_nodes(),
        "edge_count": graph.number_of_edges(),
        "is_dag": nx.is_directed_acyclic_graph(graph),
        "node_type_counts": {},
        "relation_counts": {},
    }
    for node in nodes:
        metadata["node_type_counts"][node["type"]] = metadata["node_type_counts"].get(node["type"], 0) + 1
    for edge in edges:
        metadata["relation_counts"][edge["relation"]] = metadata["relation_counts"].get(edge["relation"], 0) + 1
    if chain_meta:
        metadata["chain"] = chain_meta

    return {"nodes": nodes, "edges": edges, "relationships": edges, "metadata": metadata}
