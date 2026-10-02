"""IOC parsing, matching and the /api/ioc/import endpoint."""
from __future__ import annotations

import json

from app.ioc import infer_type, match_events, parse_ioc_payload, parse_json_indicators
from app.ioc import Indicator


# ---------------------------------------------------------------- unit: types
def test_infer_type():
    assert infer_type("1.2.3.4") == "ip"
    assert infer_type("255.255.999.1") is None  # octet out of range -> not ip
    assert infer_type("::1") == "ip"
    assert infer_type("a" * 32) == "hash"
    assert infer_type("A" * 64) == "hash"
    assert infer_type("evil.example.com") == "domain"
    assert infer_type("not a value") is None


# ---------------------------------------------------------------- unit: CSV
def test_parse_csv_with_header_and_source_column():
    payload = "type,indicator,source\nip,1.2.3.4,alienvault\ndomain,evil.example.com,otrf\n"
    res = parse_ioc_payload(payload, fmt="csv")
    assert res.format == "csv"
    assert [(i.type, i.value, i.source) for i in res.indicators] == [
        ("ip", "1.2.3.4", "alienvault"),
        ("domain", "evil.example.com", "otrf"),
    ]
    assert res.issues == []


def test_parse_csv_headerless_single_column_and_issues():
    res = parse_ioc_payload("10.0.0.22\n" + "b" * 64 + "\nnot a value\n")
    assert [i.type for i in res.indicators] == ["ip", "hash"]
    assert len(res.issues) == 1
    assert "cannot determine indicator type" in res.issues[0]["message"]
    assert res.issues[0]["scope"] == "ioc"


def test_parse_csv_header_without_value_column_is_an_issue():
    res = parse_ioc_payload("type,kind\nip,ipv4\n", fmt="csv")
    assert res.indicators == []
    assert any("no value column" in i["message"] for i in res.issues)


def test_parse_csv_two_column_value_source():
    res = parse_ioc_payload("8.8.8.8,threat-feed\n", fmt="csv")
    assert res.indicators[0].source == "threat-feed"


def test_parse_csv_duplicate_rows_reported():
    res = parse_ioc_payload("type,value\nip,1.2.3.4\nip,1.2.3.4\n")
    assert len(res.indicators) == 1
    assert any("duplicate" in i["message"] for i in res.issues)


def test_parse_csv_filename_seeds_source():
    res = parse_ioc_payload("1.2.3.4\n", fmt="csv", filename="mordor_iocs.csv")
    assert res.indicators[0].source == "mordor_iocs.csv"


# ---------------------------------------------------------------- unit: STIX
def test_parse_stix_bundle():
    bundle = {
        "type": "bundle",
        "id": "bundle--1",
        "objects": [
            {"type": "indicator", "name": "c2-ip",
             "pattern": "[ipv4-addr:value = '45.155.205.23']"},
            {"type": "indicator", "name": "payload-hash",
             "pattern": "[file:HASHES.'SHA-256' = '" + "c" * 64 + "']"},
            {"type": "indicator", "pattern": "[domain-name:value = 'bad.example.com']"},
            {"type": "malware"},  # non-indicator objects are skipped silently
        ],
    }
    res = parse_ioc_payload(json.dumps(bundle), fmt="auto")
    assert res.format == "stix"
    assert [(i.type, i.value) for i in res.indicators] == [
        ("ip", "45.155.205.23"),
        ("hash", "c" * 64),
        ("domain", "bad.example.com"),
    ]
    assert res.issues == []


def test_parse_stix_bare_pattern():
    res = parse_ioc_payload("[ipv4-addr:value = '9.9.9.9']", fmt="auto")
    assert len(res.indicators) == 1
    ind = res.indicators[0]
    assert (ind.type, ind.value, ind.source) == ("ip", "9.9.9.9", "stix")


def test_parse_stix_unparseable_pattern_is_issue():
    bundle = {"type": "bundle", "objects": [{"type": "indicator", "pattern": "nope"}]}
    res = parse_ioc_payload(json.dumps(bundle))
    assert res.indicators == []
    assert any("no recognisable value" in i["message"] for i in res.issues)


def test_parse_invalid_json_reported_not_raised():
    res = parse_ioc_payload("{not json", fmt="stix")
    assert res.indicators == []
    assert any("invalid JSON" in i["message"] for i in res.issues)


# ---------------------------------------------------------------- unit: JSON
def test_parse_json_indicators_inline():
    res = parse_json_indicators([
        {"type": "ip", "value": "7.7.7.7", "source": "unit"},
        {"value": "9.9.9.9"},
        "1.1.1.1",
    ])
    assert [i.value for i in res.indicators] == ["7.7.7.7", "9.9.9.9", "1.1.1.1"]
    assert res.indicators[1].type == "ip"  # inferred


# ---------------------------------------------------------------- unit: matching
def test_match_events_fields():
    events = [
        {"event_id": "E1", "source_ip": "1.2.3.4", "destination_ip": "10.0.0.5",
         "domain": "Evil.Example.com", "file_hash": None, "host": "h1", "scenario_id": None},
        {"event_id": "E2", "source_ip": "5.5.5.5", "file_hash": "A" * 64,
         "domain": None, "destination_ip": None, "host": "h2", "scenario_id": None},
    ]
    indicators = [
        Indicator(type="ip", value="1.2.3.4", source="s"),
        Indicator(type="domain", value="evil.example.com", source="s"),  # case-insensitive
        Indicator(type="hash", value="a" * 64, source="s"),
        Indicator(type="ip", value="9.9.9.9", source="s"),
    ]
    matches = match_events(events, indicators)
    assert {(m["event_id"], m["field"], m["indicator_type"]) for m in matches} == {
        ("E1", "source_ip", "ip"),
        ("E1", "domain", "domain"),
        ("E2", "file_hash", "hash"),
    }
    assert all(m["indicator_source"] == "s" for m in matches)


# ---------------------------------------------------------------- API endpoint
def test_ioc_import_endpoint_csv_and_event_detail(client, generate_all_scenarios):
    generate_all_scenarios(seed=42)
    # pick a real ip from the store so the match is genuine
    events = client.get("/api/events", params={"limit": 50}).json()["items"]
    target = next(e for e in events if e.get("destination_ip"))
    ip = target["destination_ip"]

    body = {"content": f"type,indicator,source\nip,{ip},unit-test-feed\n",
            "format": "csv", "source": "unit"}
    res = client.post("/api/ioc/import", json=body)
    assert res.status_code == 200, res.text
    report = res.json()
    assert report["indicators_parsed"] == 1
    assert report["by_type"] == {"ip": 1}
    assert report["events_scanned"] > 0
    assert report["matches_found"] >= 1
    assert report["detections_created"] >= 1
    assert report["duration_seconds"] > 0

    detail = client.get(f"/api/events/{target['event_id']}").json()
    ioc_dets = [d for d in detail["detections"] if d["rule_id"] == "IOC_MATCH"]
    assert ioc_dets, "event detail must show the ioc_match detection"
    evidence = ioc_dets[0]["evidence"][0]
    assert evidence["type"] == "ioc_match"
    assert evidence["indicator_value"] == ip
    assert evidence["indicator_source"] == "unit-test-feed"

    # re-import is idempotent
    again = client.post("/api/ioc/import", json=body).json()
    assert again["detections_created"] == 0
    assert again["duplicates_skipped"] == report["matches_found"]
    assert again["matches_found"] == report["matches_found"]


def test_ioc_import_endpoint_stix_reaches_chain_evidence(client, generate_all_scenarios):
    generate_all_scenarios(seed=42)
    chains = client.get("/api/chains").json()["items"]
    assert chains
    chain = client.get(f"/api/chains/{chains[0]['chain_id']}").json()
    ev = next(e for e in chain["events"] if e.get("source_ip") or e.get("destination_ip"))
    ip = ev.get("source_ip") or ev.get("destination_ip")

    bundle = {"type": "bundle", "objects": [
        {"type": "indicator", "name": "unit-stix", "pattern": f"[ipv4-addr:value = '{ip}']"},
    ]}
    res = client.post("/api/ioc/import", json={"content": json.dumps(bundle), "source": "unit"})
    assert res.status_code == 200, res.text
    report = res.json()
    assert report["format"] == "stix"
    assert report["detections_created"] >= 1
    assert report["evidence_created"] >= 1  # chain evidence rows written

    evidence = client.get(f"/api/chains/{chains[0]['chain_id']}/evidence").json()
    ioc_items = [e for e in evidence["observed"] if e["type"] == "ioc_match"]
    assert ioc_items, "chain evidence panel must show the ioc_match"
    assert "unit-stix" in ioc_items[0]["summary"]
    assert ioc_items[0]["inferred"] is False


def test_ioc_import_inline_and_validation(client, generate_all_scenarios):
    generate_all_scenarios(seed=42)
    res = client.post("/api/ioc/import", json={"indicators": [
        {"type": "domain", "value": "nothing.matches.this", "source": "unit"},
    ]})
    assert res.status_code == 200
    report = res.json()
    assert report["format"] == "inline"
    assert report["indicators_parsed"] == 1
    assert report["matches_found"] == 0
    assert report["detections_created"] == 0

    missing = client.post("/api/ioc/import", json={})
    assert missing.status_code == 400
    assert "provide" in missing.json()["detail"]


def test_ioc_import_bad_rows_reported_not_fatal(client):
    body = {"content": "type,indicator\nwat,!!!\nip,300.1.1.1\n", "format": "csv", "source": "unit"}
    res = client.post("/api/ioc/import", json=body)
    # '300.1.1.1' still parses (declared type) but '!!!' with type 'wat' is an issue
    assert res.status_code == 200
    report = res.json()
    assert report["indicators_invalid"] >= 1
    assert any(i["scope"] == "ioc" for i in report["issues"])
