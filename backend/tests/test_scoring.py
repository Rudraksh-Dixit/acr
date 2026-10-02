"""Scoring unit tests: confidence aggregation, risk levels, missing-step inference."""
from __future__ import annotations

from app.correlation.signals import PairScore, SignalContribution
from app.scoring.confidence import compute_confidence, confidence_from_pair
from app.scoring.missing_steps import infer_missing_steps
from app.scoring.risk import compute_risk, risk_level


def _edge(a: str, b: str, contributions: list[SignalContribution], total: float) -> PairScore:
    return PairScore(event_a=a, event_b=b, total=total, contributions=contributions, window="STRICT")


# --- risk levels -----------------------------------------------------------

def test_risk_level_boundaries():
    assert risk_level(0) == "LOW"
    assert risk_level(29.9) == "LOW"
    assert risk_level(30) == "MEDIUM"
    assert risk_level(55.9) == "MEDIUM"
    assert risk_level(56) == "HIGH"
    assert risk_level(89.9) == "HIGH"
    assert risk_level(90) == "CRITICAL"
    assert risk_level(100) == "CRITICAL"


def test_benign_session_is_low_risk():
    result = compute_risk(
        events=[{"severity": "INFO", "host": "win-01", "user": "alice"}],
        detections=[],
        tactics=[],
    )
    assert result.score == 0.0
    assert result.level == "LOW"
    assert result.factors == []


def test_attack_chain_scores_high_with_explained_factors():
    events = [
        {"severity": "HIGH", "host": "win-01", "user": "alice", "technique_id": "T1003"},
        {"severity": "HIGH", "host": "win-02", "user": "bob", "technique_id": "T1071.001"},
    ]
    detections = [{"severity": "CRITICAL", "technique_id": "T1003"}]
    tactics = ["CREDENTIAL ACCESS", "LATERAL MOVEMENT", "COMMAND AND CONTROL"]
    result = compute_risk(events, detections, tactics)

    assert result.level == "HIGH"
    assert 56 <= result.score <= 89
    assert result.factors, "risk must explain itself"
    points = [f["points"] for f in result.factors]
    assert points == sorted(points, reverse=True)
    factor_names = {f["factor"] for f in result.factors}
    assert "peak_severity" in factor_names
    assert "tactic_credential_access" in factor_names
    assert "multiple_hosts" in factor_names
    assert result.to_dict()["level"] == "HIGH"


# --- confidence ------------------------------------------------------------

def _strong_edge(a: str = "e1", b: str = "e2") -> PairScore:
    return _edge(a, b, [
        SignalContribution("temporal", "temporal", 20, 20, "12s apart"),
        SignalContribution("same_host", "same_host", 20, 20, "shared host win-01"),
        SignalContribution("same_user", "same_user", 11, 11, "shared user alice"),
    ], total=51.0)


def test_confidence_sums_internal_link_groups():
    result = compute_confidence(["e1", "e2"], [_strong_edge()])
    assert result.score == 51.0
    assert result.links_analyzed == 1
    assert [r["signal"] for r in result.reasons] == ["temporal", "same_host", "same_user"]
    for reason in result.reasons:
        assert {"signal", "label", "points", "explanation"} <= set(reason)
        assert reason["points"] > 0


def test_confidence_ignores_links_outside_chain():
    result = compute_confidence(["e1", "e2"], [_strong_edge("e1", "e9")])
    assert result.score == 0.0
    assert result.reasons == []
    assert result.links_analyzed == 0


def test_confidence_skips_zero_point_groups():
    edge = _edge("e1", "e2", [
        SignalContribution("shared_file", "shared_file", 4, 0, "no shared file"),
        SignalContribution("same_host", "same_host", 20, 20, "shared host"),
    ], total=20.0)
    result = compute_confidence(["e1", "e2"], [edge])
    assert [r["signal"] for r in result.reasons] == ["same_host"]


def test_confidence_from_single_pair():
    result = confidence_from_pair(_strong_edge())
    assert result.score == 51.0
    assert result.links_analyzed == 1
    assert len(result.reasons) == 3


# --- missing steps ---------------------------------------------------------

def test_unknown_tactics_yield_no_steps():
    assert infer_missing_steps([], ["NOT A TACTIC"], [], 60.0) == []


def test_no_gap_single_tactic_yields_no_steps():
    # RECONNAISSANCE is first in TACTIC_ORDER: no gaps before it, no pre-chain
    assert infer_missing_steps([], ["RECONNAISSANCE"], [], 60.0) == []


def test_tactic_span_gaps_are_suggested():
    steps = infer_missing_steps(
        events=[],
        tactics=["EXECUTION", "CREDENTIAL ACCESS"],
        techniques=[],
        chain_confidence=50.0,
    )
    assert len(steps) <= 4
    by_tactic = {s["tactic"]: s for s in steps}

    # span skips PERSISTENCE / PRIVILEGE ESCALATION / DEFENSE EVASION
    assert "PERSISTENCE" in by_tactic
    assert "PRIVILEGE ESCALATION" in by_tactic
    assert "DEFENSE EVASION" in by_tactic
    assert by_tactic["DEFENSE EVASION"]["technique_id"] == "T1027"
    assert by_tactic["PRIVILEGE ESCALATION"]["technique_id"] == "T1548.002"

    # CREDENTIAL ACCESS counts as early-stage telemetry: no pre-chain claim
    assert "INITIAL ACCESS" not in by_tactic

    for step in steps:
        assert step["inferred"] is True
        assert step["observed"] is False
        assert step["confidence"] >= 45
        assert step["technique_id"]
        assert step["reason"]


def test_pre_chain_inferred_when_no_access_stage_observed():
    # telemetry starts at EXECUTION with no access/cred/persistence at all
    steps = infer_missing_steps(
        events=[],
        tactics=["EXECUTION", "DISCOVERY"],
        techniques=[],
        chain_confidence=50.0,
    )
    pre_chain = [s for s in steps if s["kind"] == "MISSING_PRE_CHAIN"]
    assert len(pre_chain) == 1
    assert pre_chain[0]["technique_id"] == "T1566"
    assert pre_chain[0]["tactic"] == "INITIAL ACCESS"
    assert pre_chain[0]["confidence"] >= 45
    assert pre_chain[0]["inferred"] is True
    assert len(steps) <= 4


def test_low_chain_confidence_applies_penalty_and_floor():
    steps = infer_missing_steps(
        events=[],
        tactics=["EXECUTION", "CREDENTIAL ACCESS"],
        techniques=[],
        chain_confidence=40.0,  # triggers -8 penalty on gap steps
    )
    technique_ids = {s["technique_id"] for s in steps}
    # PERSISTENCE gap: 47 - 8 = 39 -> below the 45 floor, must be dropped
    assert "T1547.001" not in technique_ids
    assert "T1027" in technique_ids          # 66 - 8 = 58, still reportable
    assert "T1548.002" in technique_ids      # 56 - 8 = 48, still reportable
    for step in steps:
        assert step["confidence"] >= 45


def test_file_write_then_execute_suggests_missing_execution_step():
    events = [
        {"event_type": "FILE_CREATED", "file_path": "C:\\Temp\\payload.exe", "host": "win-01"},
        {
            "event_type": "PROCESS_CREATED",
            "process_name": "payload.exe",
            "host": "win-01",
            "command_line": "payload.exe -enc AAAA",
        },
    ]
    steps = infer_missing_steps(events, ["EXECUTION"], [], chain_confidence=50.0)
    exec_steps = [s for s in steps if s["kind"] == "MISSING_EXECUTION_STEP"]
    assert len(exec_steps) == 1
    assert exec_steps[0]["technique_id"] == "T1204.002"
    assert exec_steps[0]["confidence"] == 61.0
    assert exec_steps[0]["inferred"] is True


def test_execution_step_suppressed_when_user_execution_observed():
    events = [
        {"event_type": "FILE_CREATED", "file_path": "C:\\Temp\\payload.exe", "host": "win-01"},
        {"event_type": "PROCESS_CREATED", "process_name": "payload.exe", "host": "win-01"},
    ]
    steps = infer_missing_steps(events, ["EXECUTION"], ["T1204.001"], chain_confidence=50.0)
    assert all(s["kind"] != "MISSING_EXECUTION_STEP" for s in steps)
