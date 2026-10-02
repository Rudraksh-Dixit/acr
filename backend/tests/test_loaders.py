"""Telemetry loader tests (JSON + CSV): shapes, dialects, error handling."""
from __future__ import annotations

import pytest

from app.ingestion.csv_loader import load_csv, parse_csv_text
from app.ingestion.json_loader import LoaderError, load_json, parse_json_text


# --- JSON ------------------------------------------------------------------

def test_parse_json_list_root():
    records = parse_json_text('[{"event_type": "LOGIN_SUCCESS"}, {"event_type": "PROCESS_CREATED"}]')
    assert len(records) == 2


def test_parse_json_wrapped_events_key():
    records = parse_json_text('{"events": [{"event_type": "A"}, {"event_type": "B"}]}')
    assert [r["event_type"] for r in records] == ["A", "B"]


def test_parse_json_single_event_object():
    records = parse_json_text('{"event_type": "DNS_QUERY", "timestamp": "2026-01-01T00:00:00Z"}')
    assert len(records) == 1
    assert records[0]["event_type"] == "DNS_QUERY"


def test_parse_json_object_without_event_keys_rejected():
    with pytest.raises(LoaderError):
        parse_json_text('{"foo": 1, "bar": 2}')


def test_parse_json_invalid_text_rejected():
    with pytest.raises(LoaderError):
        parse_json_text("{not json")


def test_parse_json_non_object_root_rejected():
    with pytest.raises(LoaderError):
        parse_json_text('"just a string"')


def test_load_json_roundtrip(tmp_path):
    path = tmp_path / "batch.json"
    path.write_text('[{"event_type": "LOGIN_SUCCESS", "host": "win-01"}]', encoding="utf-8")
    records = load_json(path)
    assert records[0]["host"] == "win-01"


def test_load_json_missing_file():
    with pytest.raises(LoaderError):
        load_json("does/not/exist.json")


def test_load_json_invalid_utf8(tmp_path):
    path = tmp_path / "bad.json"
    path.write_bytes(b"\xff\xfe\x00broken")
    with pytest.raises(LoaderError):
        load_json(path)


# --- CSV -------------------------------------------------------------------

CSV_BASIC = "timestamp,host,user,event_type\n2026-01-01T00:00:00Z,win-01,alice,LOGIN_SUCCESS\n2026-01-01T00:00:05Z,win-01,alice,LOGOUT\n"


def test_parse_csv_basic():
    rows = parse_csv_text(CSV_BASIC)
    assert len(rows) == 2
    assert rows[0]["host"] == "win-01"
    assert rows[1]["event_type"] == "LOGOUT"


def test_parse_csv_semicolon_dialect_sniffed():
    rows = parse_csv_text("host;user;event_type\nwin-01;alice;LOGIN_SUCCESS\n")
    assert rows[0] == {"host": "win-01", "user": "alice", "event_type": "LOGIN_SUCCESS"}


def test_parse_csv_blank_rows_skipped():
    rows = parse_csv_text("host,event_type\nwin-01,LOGIN_SUCCESS\n,\n")
    assert len(rows) == 1


def test_parse_csv_empty_rejected():
    with pytest.raises(LoaderError):
        parse_csv_text("   ")


def test_parse_csv_header_only_rejected():
    with pytest.raises(LoaderError):
        parse_csv_text("host,event_type,user\n")


def test_load_csv_roundtrip(tmp_path):
    path = tmp_path / "batch.csv"
    path.write_text(CSV_BASIC, encoding="utf-8")
    rows = load_csv(path)
    assert len(rows) == 2
    assert rows[0]["user"] == "alice"


def test_load_csv_missing_file():
    with pytest.raises(LoaderError):
        load_csv("does/not/exist.csv")
