"""Investigation views: replay timeline, process tree, network view and the
summary service interface (rule-based today, LLM-assisted later)."""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Optional

from app.core.config import Settings, settings as default_settings
from app.mitre import get_mapper
from app.reconstruction.graph_builder import build_attack_graph
from app.services.chain_service import iso

# --- timeline / attack replay ---------------------------------------------


def _primary_entity(event: dict[str, Any]) -> Optional[dict[str, str]]:
    if event.get("process_name"):
        return {"type": "PROCESS", "value": event["process_name"], "label": event["process_name"]}
    if event.get("file_path"):
        return {"type": "FILE", "value": event["file_path"], "label": event["file_path"].split("\\")[-1].split("/")[-1]}
    if event.get("destination_ip"):
        return {"type": "IP", "value": event["destination_ip"], "label": event["destination_ip"]}
    if event.get("domain"):
        return {"type": "DOMAIN", "value": event["domain"], "label": event["domain"]}
    if event.get("user"):
        return {"type": "USER", "value": event["user"], "label": event["user"]}
    if event.get("host"):
        return {"type": "HOST", "value": event["host"], "label": event["host"]}
    return None


def _event_summary(event: dict[str, Any]) -> str:
    etype = event.get("event_type", "EVENT")
    parts: list[str] = []
    if etype == "PROCESS_CREATED":
        parent = event.get("parent_process") or "unknown parent"
        parts.append(f"{event.get('process_name')} started by {parent}")
    elif etype == "LOGIN_SUCCESS":
        parts.append(f"{event.get('user')} authenticated successfully")
    elif etype == "LOGIN_ATTEMPT":
        parts.append(f"failed login attempt for {event.get('user')}")
    elif etype in {"FILE_CREATED", "FILE_MODIFIED"}:
        parts.append(f"file {event.get('file_path')} {'created' if etype == 'FILE_CREATED' else 'modified'}")
    elif etype == "REGISTRY_MODIFIED":
        parts.append(f"registry key {event.get('file_path')} modified")
    elif etype == "NETWORK_CONNECTION":
        parts.append(f"{event.get('process_name') or 'process'} connected to "
                     f"{event.get('destination_ip')}:{event.get('destination_port') or '?'}")
    elif etype == "DNS_QUERY":
        parts.append(f"DNS query for {event.get('domain')}")
    elif etype == "PRIVILEGE_CHANGE":
        parts.append(f"privileges assigned to {event.get('user')}")
    elif etype == "SERVICE_CREATED":
        parts.append(f"service installed: {event.get('file_path') or event.get('command_line')}")
    elif etype == "REMOTE_EXECUTION":
        parts.append(f"remote command executed on {event.get('host')} from {event.get('source_ip') or 'remote source'}")
    else:
        parts.append(f"{etype} on {event.get('host') or 'unknown host'}")
    if event.get("host"):
        parts.append(f"on {event['host']}")
    return " ".join(parts)


def build_timeline(
    events: list[dict[str, Any]],
    detections: list[dict[str, Any]],
    missing_steps: list[dict[str, Any]] | None = None,
    include_inferred: bool = False,
) -> list[dict[str, Any]]:
    det_by_event: dict[str, list[dict[str, Any]]] = {}
    for det in detections:
        if det.get("event_id"):
            det_by_event.setdefault(str(det["event_id"]), []).append(det)

    graph = build_attack_graph(events, detections)
    out_edges: dict[str, list[dict[str, Any]]] = {}
    for edge in graph["edges"]:
        if edge["relation"] == "PRECEDES":
            continue
        out_edges.setdefault(edge["source"], []).append(edge)

    ordered = sorted(events, key=lambda e: (e.get("timestamp") is None, e.get("timestamp") or datetime.max))
    items: list[dict[str, Any]] = []
    for index, event in enumerate(ordered, start=1):
        eid = str(event.get("event_id"))
        event_detections = det_by_event.get(eid, [])
        relationships = [
            {
                "target": edge["target"],
                "relation": edge["relation"],
                "detail": edge.get("detail"),
            }
            for edge in out_edges.get(eid, [])
        ]
        technique = None
        if event.get("technique_id") or event_detections:
            tid = event.get("technique_id") or (event_detections[0].get("technique_id"))
            technique = {
                "technique_id": tid,
                "name": event.get("technique_name") or (event_detections[0].get("technique_name") if event_detections else None)
                        or get_mapper().name_for(tid),
            }
        items.append({
            "seq": index,
            "kind": "OBSERVED",
            "inferred": False,
            "timestamp": iso(event.get("timestamp")),
            "event_id": eid,
            "event_type": event.get("event_type"),
            "severity": event.get("severity"),
            "host": event.get("host"),
            "user": event.get("user"),
            "summary": _event_summary(event),
            "command_line": event.get("command_line"),
            "entity": _primary_entity(event),
            "relationships": relationships,
            "technique": technique,
            "tactic": event.get("tactic"),
            "evidence": [
                {"type": "DETECTION", "rule_id": d.get("rule_id"), "summary": d.get("title"),
                 "severity": d.get("severity")}
                for d in event_detections
            ],
        })

    if include_inferred and missing_steps:
        # place inferred gaps after the last observed item that precedes them chronologically
        for step in missing_steps:
            items.append({
                "seq": len(items) + 1,
                "kind": "INFERRED",
                "inferred": True,
                "timestamp": None,
                "event_id": None,
                "event_type": "POSSIBLE_MISSING_STEP",
                "severity": "INFO",
                "host": None,
                "user": None,
                "summary": step.get("reason") or step.get("explanation"),
                "command_line": None,
                "entity": {"type": "TECHNIQUE", "value": step.get("technique_id"),
                           "label": step.get("technique_name")},
                "relationships": [],
                "technique": {"technique_id": step.get("technique_id"), "name": step.get("technique_name")},
                "tactic": step.get("tactic"),
                "confidence": step.get("confidence"),
                "evidence": [{"type": "INFERENCE", "summary": step.get("explanation")}],
            })
        items.sort(key=lambda i: (i["timestamp"] is None, i["timestamp"] or ""))
        for position, item in enumerate(items, start=1):
            item["seq"] = position
    return items


# --- process tree ----------------------------------------------------------


def build_process_tree(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    nodes: dict[tuple[str, str], dict[str, Any]] = {}
    ordered = sorted(events, key=lambda e: (e.get("timestamp") is None, e.get("timestamp") or datetime.max))

    for event in ordered:
        name = event.get("process_name")
        if not name:
            continue
        host = str(event.get("host") or "").lower()
        pid = str(event.get("process_id") or "unknown")
        key = (host, f"{pid}:{str(name).lower()}")
        if key in nodes:
            node = nodes[key]
            node.setdefault("event_ids", []).append(event.get("event_id"))
            if event.get("command_line") and not node.get("command_line"):
                node["command_line"] = event.get("command_line")
            continue
        nodes[key] = {
            "id": f"{host}:{pid}:{name}",
            "process_name": name,
            "pid": event.get("process_id"),
            "ppid": event.get("parent_process_id"),
            "parent_process_name": event.get("parent_process"),
            "host": host or None,
            "command_line": event.get("command_line"),
            "severity": event.get("severity"),
            "technique_id": event.get("technique_id"),
            "event_id": event.get("event_id"),
            "event_ids": [event.get("event_id")],
            "event_type": event.get("event_type"),
            "children": [],
        }

    # link children to parents
    by_pid = {(host, str(node["pid"])): node for (host, _), node in nodes.items()
              if node.get("pid") is not None}
    roots: list[dict[str, Any]] = []
    for key, node in nodes.items():
        host, _ = key
        parent = None
        if node.get("ppid") is not None:
            parent = by_pid.get((host, str(node["ppid"])))
        if parent is None and node.get("parent_process_name"):
            parent = next(
                (n for (h, _), n in nodes.items()
                 if h == host and str(n["process_name"]).lower() == str(node["parent_process_name"]).lower()),
                None,
            )
        if parent is not None and parent is not node:
            parent["children"].append(node)
        else:
            roots.append(node)
    return roots


# --- network view ----------------------------------------------------------


def build_network_view(events: list[dict[str, Any]]) -> dict[str, Any]:
    connections: list[dict[str, Any]] = []
    dns: list[dict[str, Any]] = []
    for event in sorted(events, key=lambda e: (e.get("timestamp") is None, e.get("timestamp") or datetime.max)):
        if event.get("event_type") == "NETWORK_CONNECTION":
            connections.append({
                "event_id": event.get("event_id"),
                "timestamp": iso(event.get("timestamp")),
                "source_ip": event.get("source_ip"),
                "destination_ip": event.get("destination_ip"),
                "destination_port": event.get("destination_port"),
                "protocol": event.get("protocol"),
                "process": event.get("process_name"),
                "host": event.get("host"),
                "severity": event.get("severity"),
            })
        elif event.get("event_type") == "DNS_QUERY":
            dns.append({
                "event_id": event.get("event_id"),
                "timestamp": iso(event.get("timestamp")),
                "query": event.get("domain"),
                "process": event.get("process_name"),
                "host": event.get("host"),
            })

    graph = build_attack_graph(events, [])
    keep_types = {"IP", "DOMAIN", "PROCESS", "HOST"}
    nodes = [n for n in graph["nodes"] if n["type"] in keep_types or n["type"] == "EVENT"]
    interesting = {"CONNECTED", "PRECEDES"}
    edges = [e for e in graph["edges"] if e["relation"] in interesting
             or (graph["nodes"] and any(n["id"] == e["target"] and n["type"] in {"IP", "DOMAIN"} for n in graph["nodes"]))]
    external = sorted({c["destination_ip"] for c in connections if c.get("destination_ip")})
    return {
        "connections": connections,
        "dns_queries": dns,
        "external_destinations": external,
        "graph": {"nodes": nodes, "edges": edges},
        "counts": {"connections": len(connections), "dns_queries": len(dns), "external_destinations": len(external)},
    }


# --- summary service (future LLM hook) -------------------------------------


class InvestigationSummaryService(ABC):
    """Interface for AI-assisted investigation summaries.

    Version 1 ships a deterministic rule-based implementation. A future
    LLMInvestigationSummary can be registered without changing callers.
    """

    name: str = "abstract"

    @abstractmethod
    def summarize(
        self,
        chain: dict[str, Any],
        events: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
        techniques: list[dict[str, Any]],
        graph: dict[str, Any],
    ) -> dict[str, Any]:
        raise NotImplementedError


class RuleBasedInvestigationSummary(InvestigationSummaryService):
    name = "rule_based"

    def summarize(self, chain, events, evidence, techniques, graph) -> dict[str, Any]:
        chain_id = chain.get("chain_id", "unknown")
        hosts = chain.get("hosts") or sorted({e.get("host") for e in events if e.get("host")})
        users = chain.get("users") or sorted({e.get("user") for e in events if e.get("user")})
        tactics = chain.get("tactics") or []
        risk = chain.get("risk", {})
        confidence = chain.get("confidence", {})

        story: list[str] = []
        start = chain.get("start_time")
        end = chain.get("end_time")
        story.append(
            f"Between {start or 'unknown time'} and {end or 'unknown time'}, {len(events)} telemetry events "
            f"were correlated into chain {chain_id}"
            + (f" across host(s) {', '.join(hosts)}" if hosts else "")
            + (f" for account(s) {', '.join(users)}" if users else "") + "."
        )
        if tactics:
            story.append("Observed tactics progressed as: " + " -> ".join(tactics) + ".")
        if techniques:
            tech_names = [t.get("name") or t.get("technique_id") for t in techniques[:6]]
            story.append("Techniques identified: " + ", ".join(tech_names) + ".")
        if chain.get("possible_missing_steps"):
            gaps = [s.get("technique_id") for s in chain["possible_missing_steps"]]
            story.append(f"Possible missing steps (inferred, not observed): {', '.join(gaps)}.")

        findings: list[dict[str, Any]] = []
        for det in evidence[:6]:
            if det.get("type") == "DETECTION":
                findings.append({
                    "finding": det.get("summary"),
                    "severity": det.get("severity"),
                    "technique_id": det.get("technique_id"),
                    "kind": "OBSERVED",
                })
        if confidence.get("score") is not None:
            top_reasons = [r.get("label") for r in (confidence.get("reasons") or [])[:3] if r.get("label")]
            findings.append({
                "finding": f"Correlation confidence {confidence.get('score')}% driven by: {', '.join(top_reasons)}",
                "severity": "INFO",
                "kind": "ANALYSIS",
            })
        findings.append({
            "finding": f"Risk assessed as {risk.get('level')} ({risk.get('score')}/100)",
            "severity": "INFO",
            "kind": "ANALYSIS",
        })

        steps: list[str] = []
        if any(t for t in tactics if t in {"CREDENTIAL ACCESS", "PRIVILEGE ESCALATION"}):
            steps.append("Reset credentials for affected accounts and review authentication logs for the source IP.")
        if any(t for t in tactics if t in {"PERSISTENCE"}):
            steps.append("Audit autostart registry keys, services and scheduled tasks on affected hosts.")
        if any(t for t in tactics if t in {"COMMAND AND CONTROL"}):
            steps.append("Block observed C2 destinations at the perimeter and hunt for beaconing.")
        if any(t for t in tactics if t in {"LATERAL MOVEMENT"}):
            steps.append("Review remote service usage (SMB/WinRM) and isolate affected hosts.")
        steps.append("Validate each observed detection against raw telemetry before closing the case.")
        steps.append("Compare the reconstructed path against the ATT&CK coverage to prioritize controls.")

        return {
            "provider": self.name,
            "summary": chain.get("summary") or " ".join(story),
            "attack_story": story,
            "key_findings": findings,
            "recommended_investigation_steps": steps,
            "graph_stats": graph.get("metadata", {}) if graph else {},
        }


def get_summary_service() -> InvestigationSummaryService:
    return RuleBasedInvestigationSummary()


def investigate_chain(chain: dict[str, Any], events: list[dict[str, Any]],
                      detections: list[dict[str, Any]],
                      settings: Settings | None = None) -> dict[str, Any]:
    cfg = settings or default_settings
    _ = cfg
    graph = build_attack_graph(events, detections, {"chain_id": chain.get("chain_id")})
    timeline = build_timeline(events, detections, chain.get("possible_missing_steps") or [], include_inferred=False)
    summary = get_summary_service().summarize(chain, events, chain.get("evidence") or [],
                                              chain.get("techniques") or [], graph)
    return {
        "chain_id": chain.get("chain_id"),
        "timeline": timeline,
        "process_tree": build_process_tree(events),
        "network": build_network_view(events),
        "summary": summary,
    }
