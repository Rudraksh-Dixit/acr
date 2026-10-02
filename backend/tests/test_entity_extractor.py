"""Entity + relationship extraction tests (the correlation join points)."""
from __future__ import annotations

from app.ingestion.entity_extractor import (
    display_entity,
    entity_index_keys,
    extract_entities,
    extract_relationships,
    process_entity_value,
)
from app.ingestion.normalizer import normalize_records


def test_process_entity_value_is_host_scoped():
    assert process_entity_value("win-01", "PowerShell.EXE") == "win-01:powershell.exe"
    assert process_entity_value(None, "bash") == "bash"
    assert process_entity_value("win-01", "  ") is None
    assert process_entity_value("win-01", None) is None


def test_display_entity_strips_host_scope():
    assert display_entity("PROCESS", "win-01:powershell.exe") == "powershell.exe"
    assert display_entity("USER", "alice") == "alice"


def test_extract_entities_from_process_event():
    event = {
        "event_type": "PROCESS_CREATED",
        "host": "win-01",
        "user": "alice",
        "process_name": "powershell.exe",
        "parent_process": "cmd.exe",
        "technique_id": "T1059.001",
    }
    refs = {(r.entity_type, r.value) for r in extract_entities(event)}
    assert ("HOST", "win-01") in refs
    assert ("USER", "alice") in refs
    assert ("PROCESS", "win-01:powershell.exe") in refs
    assert ("PROCESS", "win-01:cmd.exe") in refs
    assert ("TECHNIQUE", "T1059.001") in refs


def test_extract_entities_deduplicates_repeated_values():
    event = {"source_ip": "10.0.0.5", "destination_ip": "10.0.0.5"}
    ip_refs = [r for r in extract_entities(event) if r.entity_type == "IP"]
    assert len(ip_refs) == 1


def test_entities_align_with_normalizer_output():
    batch = normalize_records(
        [{
            "timestamp": "2026-01-01T10:00:00Z",
            "event_type": "LOGIN_SUCCESS",
            "host": "win-01",
            "user": "alice",
        }],
        source="test",
    )
    refs = {(r.entity_type, r.value) for r in extract_entities(batch.events[0])}
    assert ("HOST", "win-01") in refs
    assert ("USER", "alice") in refs


def test_relationship_login_and_process_spawn():
    login = {"event_type": "LOGIN_SUCCESS", "host": "win-01", "user": "alice"}
    rels = {(r.source_type, r.source_value, r.target_type, r.target_value, r.relation_type)
            for r in extract_relationships(login)}
    assert ("USER", "alice", "HOST", "win-01", "AUTHENTICATED") in rels

    proc = {
        "event_type": "PROCESS_CREATED",
        "host": "win-01",
        "process_name": "cmd.exe",
        "parent_process": "powershell.exe",
    }
    rels = {(r.source_type, r.source_value, r.target_type, r.target_value, r.relation_type)
            for r in extract_relationships(proc)}
    assert ("HOST", "win-01", "PROCESS", "win-01:cmd.exe", "RUNS") in rels
    assert ("PROCESS", "win-01:powershell.exe", "PROCESS", "win-01:cmd.exe", "SPAWNED") in rels


def test_relationship_network_and_dns():
    net = {
        "event_type": "NETWORK_CONNECTION",
        "host": "win-01",
        "process_name": "svchost.exe",
        "destination_ip": "203.0.113.10",
    }
    rels = {(r.source_type, r.source_value, r.target_type, r.target_value, r.relation_type)
            for r in extract_relationships(net)}
    assert ("PROCESS", "win-01:svchost.exe", "IP", "203.0.113.10", "CONNECTED") in rels

    dns = {
        "event_type": "DNS_QUERY",
        "host": "win-01",
        "process_name": "chrome.exe",
        "domain": "cdn.example",
        "destination_ip": "203.0.113.10",
    }
    rels = {(r.source_type, r.source_value, r.target_type, r.target_value, r.relation_type)
            for r in extract_relationships(dns)}
    assert ("PROCESS", "win-01:chrome.exe", "DOMAIN", "cdn.example", "QUERIED") in rels
    assert ("DOMAIN", "cdn.example", "IP", "203.0.113.10", "RESOLVES_TO") in rels


def test_relationship_skips_same_process_as_parent():
    proc = {
        "event_type": "PROCESS_CREATED",
        "host": "win-01",
        "process_name": "cmd.exe",
        "parent_process": "cmd.exe",
    }
    spawn = [r for r in extract_relationships(proc) if r.relation_type == "SPAWNED"]
    assert spawn == []


def test_entity_index_keys_cover_join_points():
    event = {
        "host": "win-01",
        "user": "alice",
        "source_ip": "10.0.0.5",
        "destination_ip": "10.0.0.9",
        "domain": "evil.example",
        "file_path": "C:\\Temp\\payload.exe",
        "process_name": "powershell.exe",
        "parent_process": "cmd.exe",
    }
    keys = entity_index_keys(event)
    assert "h:win-01" in keys
    assert "u:alice" in keys
    assert "sip:10.0.0.5" in keys
    assert "dip:10.0.0.9" in keys
    assert "dom:evil.example" in keys
    assert "f:c:\\temp\\payload.exe" in keys
    assert "p:win-01:powershell.exe" in keys
    assert "p:win-01:cmd.exe" in keys
