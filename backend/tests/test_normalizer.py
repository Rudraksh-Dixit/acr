"""Normalization tests: aliases, event ids, timestamps, malformed input."""
from __future__ import annotations

from app.ingestion.normalizer import normalize_record, normalize_records


def test_aliases_map_to_canonical_fields():
    event, issues = normalize_record({
        "EventTime": "2026-01-02T10:00:00Z",
        "Type": "process_create",
        "Computer": "HOST-A.Example",
        "Account_Name": "CORP\\alice",
        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
        "ProcessCommandLine": "cmd.exe /c whoami",
        "SrcIP": "10.1.2.3",
    })
    assert event is not None
    assert event["event_type"] == "PROCESS_CREATED"
    assert event["host"] == "host-a.example"
    assert event["user"] == "alice"
    assert event["process_name"] == "cmd.exe"
    assert event["command_line"] == "cmd.exe /c whoami"
    assert event["source_ip"] == "10.1.2.3"
    assert event["timestamp"].year == 2026


def test_event_id_key_not_confused_with_windows_eventid():
    # Windows EventID must map to event *type*, not become the event id
    a, _ = normalize_record({"EventID": 4688, "timestamp": "2026-01-01T00:00:00Z", "computer": "h1"})
    b, _ = normalize_record({"EventID": 1, "timestamp": "2026-01-01T00:00:01Z", "computer": "h1"})
    assert a is not None and b is not None
    assert a["event_type"] == "PROCESS_CREATED"
    assert b["event_type"] == "PROCESS_CREATED"
    assert a["event_id"] != b["event_id"]

    # an explicit event id is honored
    explicit, _ = normalize_record(
        {"event_id": "sensor-42", "timestamp": "2026-01-01T00:00:00Z", "type": "dns_query"}
    )
    assert explicit["event_id"] == "EVT-sensor-42"
    assert explicit["event_type"] == "DNS_QUERY"


def test_timestamp_parsing_formats():
    for value in ("2026-03-04T05:06:07Z", "2026-03-04 05:06:07", 1772600767, 1772600767000):
        event, _ = normalize_record({"timestamp": value, "type": "login_success", "user": "u"})
        assert event is not None and event["timestamp"] is not None, value


def test_malformed_records_are_skipped_not_fatal():
    batch = normalize_records([
        "not-a-dict",
        {},
        {"timestamp": "yesterday", "type": "????"},          # unparseable type
        {"timestamp": "2026-01-01T00:00:00Z", "type": "dns_query", "host": "h1"},
    ])
    assert len(batch.events) == 1
    assert batch.skipped == 3
    assert batch.issues


def test_gt_id_survives_normalization():
    event, _ = normalize_record(
        {"timestamp": "2026-01-01T00:00:00Z", "type": "login_success", "user": "u", "gt_id": "E7"}
    )
    assert event["gt_id"] == "E7"
    assert "gt_id" not in event["metadata"]


def test_leftover_fields_land_in_metadata():
    event, _ = normalize_record({
        "timestamp": "2026-01-01T00:00:00Z", "type": "dns_query",
        "host": "h1", "query": "evil.example", "FieldX": "kept",
    })
    assert event["metadata"].get("FieldX") == "kept"


def test_severity_defaults_and_aliases():
    event, _ = normalize_record(
        {"timestamp": "2026-01-01T00:00:00Z", "type": "remote_execution", "host": "h1"}
    )
    assert event["severity"] == "HIGH"
    event, _ = normalize_record(
        {"timestamp": "2026-01-01T00:00:00Z", "type": "dns_query", "host": "h1", "level": "warning"}
    )
    assert event["severity"] == "MEDIUM"
