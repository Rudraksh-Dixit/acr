"""REST API contract tests."""
from __future__ import annotations

import json


def test_health_and_config(client):
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    config = client.get("/api/config").json()
    assert config["time_windows"] == {"STRICT": 30, "NORMAL": 120, "BROAD": 600}
    assert sum(config["weights"].values()) == 100
    assert config["engine"] == "rule_based"


def test_scenario_catalog(client):
    body = client.get("/api/scenarios").json()
    assert body["total"] >= 6
    ids = {item["scenario_id"] for item in body["items"]}
    assert {"CRED-001", "PHISH-001", "LAT-001", "PERS-001"} <= ids
    assert any(item["is_benign"] for item in body["items"])


def test_scenario_generate_flow(client, generate_all_scenarios):
    result = generate_all_scenarios(seed=42)
    assert result["events_stored"] > 0
    assert result["detections"] > 0
    assert result["chains"] >= 1
    assert result["attack_chains"] >= 4
    # benign scenarios must not create chains
    benign_chains = sum(s["chains"] for s in result["scenarios"] if s["is_benign"])
    assert benign_chains == 0

    # regeneration is idempotent (no duplicated events)
    again = generate_all_scenarios(seed=42)
    assert again["events_replaced"] > 0
    assert again["events_stored"] == result["events_stored"]

    stats = client.get("/api/stats").json()["counts"]
    assert stats["events"] == result["events_stored"]
    assert stats["chains"] == result["chains"]


def test_event_endpoints(client, generate_all_scenarios):
    generate_all_scenarios(seed=42)

    listing = client.get("/api/events", params={"limit": 5}).json()
    assert listing["total"] > 5
    assert len(listing["items"]) == 5
    assert listing["limit"] == 5 and listing["offset"] == 0
    assert "raw" not in listing["items"][0]

    filtered = client.get("/api/events", params={"scenario_id": "CRED-001"}).json()
    assert filtered["total"] == 14
    assert all(e["scenario_id"] == "CRED-001" for e in filtered["items"])

    event_id = listing["items"][0]["event_id"]
    detail = client.get(f"/api/events/{event_id}").json()
    assert detail["event_id"] == event_id
    assert "detections" in detail and "entities" in detail

    assert client.get("/api/events/NOPE").status_code == 404
    bad = client.post("/api/events", json={"events": []})
    assert bad.status_code == 400


def test_chain_endpoints(client, generate_all_scenarios):
    generate_all_scenarios(seed=42)

    listing = client.get("/api/chains").json()
    assert listing["total"] >= 4
    chain_id = listing["items"][0]["chain_id"]

    detail = client.get(f"/api/chains/{chain_id}").json()
    assert detail["confidence"]["reasons"]
    assert detail["risk"]["factors"]
    assert detail["events"] and detail["techniques"]
    assert detail["evidence_summary"]["observed"] >= 1
    assert isinstance(detail["possible_missing_steps"], list)

    timeline = client.get(f"/api/chains/{chain_id}/timeline", params={"include_inferred": "true"})
    assert timeline.status_code == 200
    items = timeline.json()["items"]
    assert items and items[0]["seq"] == 1
    assert any(i["kind"] == "INFERRED" for i in items) == bool(detail["possible_missing_steps"])

    evidence = client.get(f"/api/chains/{chain_id}/evidence").json()
    assert evidence["observed_count"] == len(evidence["observed"])
    assert evidence["inferred_count"] == len(evidence["inferred"])

    tree = client.get(f"/api/chains/{chain_id}/process-tree")
    assert tree.status_code == 200
    assert isinstance(tree.json(), list)

    network = client.get(f"/api/chains/{chain_id}/network").json()
    assert "connections" in network and "counts" in network

    graph = client.get(f"/api/chains/{chain_id}/graph").json()
    assert graph["nodes"] and graph["edges"]
    assert graph["metadata"]["node_count"] == len(graph["nodes"])

    investigation = client.get(f"/api/investigation/{chain_id}").json()
    assert investigation["timeline"] and investigation["summary"]["summary"]

    assert client.get("/api/chains/NOPE").status_code == 404
    assert client.get("/api/chains/NOPE/timeline").status_code == 404


def test_feedback_endpoints(client, generate_all_scenarios):
    generate_all_scenarios(seed=42)
    chain_id = client.get("/api/chains").json()["items"][0]["chain_id"]

    confirmed = client.post(f"/api/chains/{chain_id}/confirm", json={"analyst": "alice"})
    assert confirmed.status_code == 200
    assert confirmed.json()["status"] == "CONFIRMED"

    dismissed = client.post(f"/api/chains/{chain_id}/dismiss", json={"reason": "expected activity"})
    assert dismissed.json()["status"] == "DISMISSED"

    invalid = client.post(f"/api/chains/{chain_id}/feedback", json={"status": "NOT_A_STATUS"})
    assert invalid.status_code == 400


def test_mitre_endpoints(client, generate_all_scenarios):
    generate_all_scenarios(seed=42)

    techniques = client.get("/api/mitre/techniques").json()
    assert techniques["total"] >= 40
    one = client.get("/api/mitre/techniques/T1059.001").json()
    assert one["tactic"] == "EXECUTION"

    execution = client.get("/api/mitre/techniques", params={"tactic": "EXECUTION"}).json()
    assert execution["items"] and all(t["tactic"] == "EXECUTION" for t in execution["items"])

    assert client.get("/api/mitre/techniques/T9999").status_code == 404

    tactics = client.get("/api/mitre/tactics").json()
    assert tactics["total"] >= 10

    coverage = client.get("/api/mitre/coverage").json()
    assert coverage["unique_techniques"] >= 10
    assert coverage["unique_tactics"] >= 4
    assert {t["tactic"] for t in coverage["tactics"]} >= {"EXECUTION", "PERSISTENCE"}


def test_evaluation_endpoints(client, generate_all_scenarios):
    generate_all_scenarios(seed=42)
    run = client.post("/api/evaluation/run", json={"seed": 42, "persist": True})
    assert run.status_code == 200
    payload = run.json()
    assert payload["run_id"] is not None
    assert payload["metrics"]["reconstruction"]["chain_accuracy"] == 1.0
    assert payload["metrics"]["attack_detection"]["raw_detection"]["false_positive_rate"] == 0.0

    runs = client.get("/api/evaluation/runs").json()
    assert runs["total"] >= 1

    detail = client.get(f"/api/evaluation/runs/{payload['run_id']}")
    assert detail.status_code == 200
    assert detail.json()["per_scenario"]

    stages = client.get("/api/evaluation/stages").json()
    assert set(stages["technique_level"]) == {"raw_detection", "correlation", "reconstruction"}
    assert stages["delta"]["chain_accuracy"] == 1.0

    assert client.get("/api/evaluation/runs/99999").status_code == 404


def test_graphs_and_pipeline_endpoints(client, generate_all_scenarios):
    generate_all_scenarios(seed=42)

    global_graph = client.get("/api/graphs", params={"limit": 100}).json()
    assert global_graph["nodes"] and global_graph["edges"]

    pipeline = client.get("/api/pipeline").json()
    stages = {s["stage"] for s in pipeline["stages"]}
    assert {"ingestion", "detection", "correlation", "reconstruction", "mitre", "evaluation"} <= stages
    counts = {s["stage"]: s["count"] for s in pipeline["stages"]}
    assert counts["ingestion"] > 0
    assert counts["detection"] > 0
    assert counts["reconstruction"] >= 4

    stats = client.get("/api/stats").json()
    assert stats["counts"]["events"] > 0
    assert stats["chains_by_risk_level"]


def test_upload_and_error_handling(client, generate_all_scenarios):
    generate_all_scenarios(seed=42)

    records = [{
        "timestamp": "2026-01-01T12:00:00Z", "event_type": "DNS_QUERY",
        "host": "upload-host", "query": "a" * 70 + ".example",
    }]
    ok = client.post(
        "/api/events/upload",
        files={"file": ("events.json", json.dumps(records).encode(), "application/json")},
        params={"source": "unit-test"},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["stored"] == 1

    bad = client.post(
        "/api/events/upload",
        files={"file": ("broken.json", b"{not json", "application/json")},
    )
    assert bad.status_code == 400

    bad_scenario = client.post("/api/scenarios/generate", json={"scenario_ids": ["NOPE-1"]})
    assert bad_scenario.status_code == 400

    unconfirmed = client.post("/api/scenarios/reset", json={"confirm": False})
    assert unconfirmed.status_code == 400

    reset = client.post("/api/scenarios/reset", json={"confirm": True})
    assert reset.status_code == 200
    assert reset.json()["cleared"]["events"] > 0
    assert reset.json()["remaining"]["events"] == 0
    assert client.get("/api/chains").json()["total"] == 0
