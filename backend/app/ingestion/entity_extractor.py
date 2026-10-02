"""Entity and relationship extraction from normalized events.

Entities are the join points of the correlation engine: two events that share
at least one indexed entity key become correlation candidates.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

PROCESS_LIKE = {"PROCESS_CREATED", "REMOTE_EXECUTION"}


@dataclass(frozen=True)
class EntityRef:
    entity_type: str  # USER | HOST | PROCESS | FILE | IP | DOMAIN | TECHNIQUE
    value: str
    role: str = ""


@dataclass(frozen=True)
class RelSpec:
    source_type: str
    source_value: str
    target_type: str
    target_value: str
    relation_type: str


def process_entity_value(host: Optional[str], process_name: Optional[str]) -> Optional[str]:
    """Process identity is scoped by host so identical binaries on different
    hosts never merge (a deliberate design choice documented in tests)."""
    if not process_name:
        return None
    name = process_name.strip().lower()
    if not name:
        return None
    return f"{host}:{name}" if host else name


def display_entity(entity_type: str, value: str) -> str:
    if entity_type == "PROCESS" and ":" in value:
        return value.split(":", 1)[1]
    return value


def extract_entities(event: dict[str, Any]) -> list[EntityRef]:
    refs: list[EntityRef] = []
    seen: set[tuple[str, str]] = set()

    def add(etype: str, value: Optional[str], role: str) -> None:
        if not value:
            return
        text = str(value).strip()
        if not text:
            return
        key = (etype, text)
        if key in seen:
            return
        seen.add(key)
        refs.append(EntityRef(etype, text, role))

    add("HOST", event.get("host"), "host")
    add("USER", event.get("user"), "user")
    for ip_field, role in (("source_ip", "src"), ("destination_ip", "dst")):
        add("IP", event.get(ip_field), role)
    add("DOMAIN", event.get("domain"), "domain")
    add("FILE", event.get("file_path"), "path")

    host = event.get("host")
    process = process_entity_value(host, event.get("process_name"))
    add("PROCESS", process, "actor")
    parent = process_entity_value(host, event.get("parent_process"))
    add("PROCESS", parent, "parent")

    tech = event.get("technique_id")
    if tech:
        add("TECHNIQUE", str(tech).upper(), "technique")
    return refs


def extract_relationships(event: dict[str, Any]) -> list[RelSpec]:
    rels: list[RelSpec] = []
    host = event.get("host")
    user = event.get("user")
    etype = event.get("event_type")
    proc = process_entity_value(host, event.get("process_name"))
    parent = process_entity_value(host, event.get("parent_process"))
    file_path = event.get("file_path")
    dst_ip = event.get("destination_ip")
    domain = event.get("domain")

    if etype in {"LOGIN_SUCCESS", "LOGIN_ATTEMPT", "AUTHENTICATION", "PRIVILEGE_CHANGE"} and user and host:
        rels.append(RelSpec("USER", user, "HOST", host, "AUTHENTICATED"))
    if etype in PROCESS_LIKE and proc:
        if host:
            rels.append(RelSpec("HOST", host, "PROCESS", proc, "RUNS"))
        if parent and parent != proc:
            rels.append(RelSpec("PROCESS", parent, "PROCESS", proc, "SPAWNED"))
    if etype in {"FILE_CREATED", "FILE_MODIFIED"} and proc and file_path:
        relation = "CREATED" if etype == "FILE_CREATED" else "MODIFIED"
        rels.append(RelSpec("PROCESS", proc, "FILE", file_path, relation))
    if etype == "REGISTRY_MODIFIED" and proc and file_path:
        rels.append(RelSpec("PROCESS", proc, "FILE", file_path, "MODIFIED"))
    if etype == "NETWORK_CONNECTION" and proc and dst_ip:
        rels.append(RelSpec("PROCESS", proc, "IP", dst_ip, "CONNECTED"))
    if etype == "DNS_QUERY" and proc and domain:
        rels.append(RelSpec("PROCESS", proc, "DOMAIN", domain, "QUERIED"))
    if etype == "DNS_QUERY" and domain and dst_ip:
        rels.append(RelSpec("DOMAIN", domain, "IP", dst_ip, "RESOLVES_TO"))
    if etype == "REMOTE_EXECUTION" and user and host:
        rels.append(RelSpec("USER", user, "HOST", host, "REMOTELY_EXECUTED"))
    if etype == "SERVICE_CREATED" and proc and file_path:
        rels.append(RelSpec("PROCESS", proc, "FILE", file_path, "INSTALLED"))
    return rels


def entity_index_keys(event: dict[str, Any]) -> list[str]:
    """Compact keys used by the correlation candidate index."""
    keys: list[str] = []
    if event.get("host"):
        keys.append(f"h:{event['host']}")
    if event.get("user"):
        keys.append(f"u:{event['user']}")
    if event.get("source_ip"):
        keys.append(f"sip:{event['source_ip']}")
    if event.get("destination_ip"):
        keys.append(f"dip:{event['destination_ip']}")
    if event.get("domain"):
        keys.append(f"dom:{event['domain']}")
    if event.get("file_path"):
        keys.append(f"f:{str(event['file_path']).lower()}")
    proc = process_entity_value(event.get("host"), event.get("process_name"))
    if proc:
        keys.append(f"p:{proc}")
    if event.get("parent_process"):
        parent = process_entity_value(event.get("host"), event.get("parent_process"))
        if parent:
            keys.append(f"p:{parent}")
    return keys
