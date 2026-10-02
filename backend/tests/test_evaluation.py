"""Evaluation engine tests: stage metrics vs synthetic ground truth."""
from __future__ import annotations

from app.services.evaluation_service import evaluate_scenario, run_evaluation


def test_full_evaluation_metrics(db_session):
    payload = run_evaluation(session=db_session, persist=True, seed=42)
    metrics = payload["metrics"]

    assert metrics["scenarios_evaluated"] >= 6

    tech = metrics["technique_level"]
    assert tech["raw_detection"]["f1"] >= 0.85
    assert tech["reconstruction"]["f1"] >= 0.85
    assert tech["reconstruction"]["precision"] >= 0.9

    verdict = metrics["attack_detection"]
    for stage in ("raw_detection", "correlation", "reconstruction"):
        assert verdict[stage]["false_positive_rate"] == 0.0, f"{stage} flagged a benign scenario"
        assert verdict[stage]["recall"] == 1.0, f"{stage} missed an attack scenario"

    assert metrics["reconstruction"]["chain_accuracy"] == 1.0
    assert metrics["performance"]["events_processed"] > 0

    # per-scenario correctness: benign stays benign at every stage
    for scenario in payload["per_scenario"]:
        for stage in ("raw_detection", "correlation", "reconstruction"):
            assert scenario["stages"][stage]["correct"], (
                f"{scenario['scenario_id']} misclassified at {stage}"
            )

    # run persisted
    assert payload.get("run_id") is not None


def test_event_level_correlation_beats_raw_detection(db_session):
    payload = run_evaluation(session=None, persist=False, seed=42)
    events = payload["metrics"]["event_level"]
    # raw detection only flags individual events; correlation/reconstruction
    # recover the full chain, so event-level recall must improve
    assert events["correlation"]["recall"] >= events["raw_detection"]["recall"]
    assert events["correlation"]["f1"] == 1.0


def test_evaluate_scenario_reports_latencies_and_techniques(db_session):
    result = evaluate_scenario("CRED-001", seed=42)
    assert result.is_benign is False
    assert result.detections > 0
    assert result.attack_chains == 1
    assert result.reconstructed_chain_f1 is not None and result.reconstructed_chain_f1 >= 0.8
    assert result.detection_latency_seconds is not None and result.detection_latency_seconds >= 0
    assert "T1078" in result.predicted_techniques


def test_benign_scenario_evaluation(db_session):
    result = evaluate_scenario("BENIGN-OFFICE-001", seed=42)
    assert result.is_benign is True
    assert result.chains == 0
    assert result.attack_chains == 0
    assert result.stages["correlation"]["attack_detected"] is False
    assert result.stages["correlation"]["correct"] is True
