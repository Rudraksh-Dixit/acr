"""End-to-end reconstruction tests (ingest -> detect -> correlate -> chains)."""
from __future__ import annotations

from app.scenarios import generate_scenario
from app.services.chain_service import apply_feedback, get_chain_full, list_chains, reconstruct
from app.services.event_service import ingest_records, run_detection_pass_


def _build(db, scenario_ids: list[str], seed: int = 42):
    for scenario_id in scenario_ids:
        scenario = generate_scenario(scenario_id, seed=seed)
        ingest_records(db, scenario.events, source="test", scenario_id=scenario_id,
                       run_detection_pass=False)
        yield scenario


def _full_setup(db, scenario_ids, seed=42):
    scenarios = list(_build(db, scenario_ids, seed))
    run_detection_pass_(db)
    report = reconstruct(db)
    return scenarios, report


def test_attack_scenario_produces_scoring_chain(db_session):
    scenarios, report = _full_setup(db_session, ["CRED-001"])
    gt = scenarios[0].ground_truth

    chains, total = list_chains(db_session, is_attack=True)
    assert total >= 1
    chain = get_chain_full(db_session, chains[0].chain_id)
    assert chain is not None

    # multi-event chain with observed + inferred evidence
    assert chain["event_count"] > 3
    assert chain["evidence_summary"]["observed"] >= 1
    assert chain["confidence"]["score"] > 0
    assert chain["confidence"]["reasons"], "confidence must expose contributing signals"
    assert chain["risk"]["level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert 0 <= chain["risk"]["score"] <= 100
    assert chain["attack_path"], "attack path must be reconstructed"

    # technique prediction vs ground truth
    predicted = {t["technique_id"] for t in chain["techniques"]}
    expected = {str(t).upper() for t in gt["techniques"]}
    assert expected <= predicted, f"missing GT techniques: {expected - predicted}"

    # missing steps are always inferred and above the confidence floor
    for step in chain["possible_missing_steps"]:
        assert step["inferred"] is True
        assert step["confidence"] >= 45
    assert len(chain["possible_missing_steps"]) <= 4


def test_benign_scenarios_produce_no_chains(db_session):
    _, report = _full_setup(db_session, ["PS-BENIGN-001", "BENIGN-OFFICE-001"])
    assert report.chains == 0
    _, total = list_chains(db_session)
    assert total == 0


def test_scenarios_do_not_merge_across_time_bases(db_session):
    _, report = _full_setup(db_session, ["CRED-001", "PHISH-001", "LAT-001", "PERS-001"])
    assert report.chains == 4
    assert report.attacks == 4
    chains, total = list_chains(db_session)
    assert total == 4
    event_counts = [c.event_count for c in chains]
    assert max(event_counts) < 20, "chains must not absorb unrelated scenarios"


def test_timeline_and_feedback_workflow(db_session):
    _full_setup(db_session, ["CRED-001"])
    chains, _ = list_chains(db_session, is_attack=True)
    chain_id = chains[0].chain_id

    updated = apply_feedback(db_session, chain_id, "CONFIRMED", comment="looks right", analyst="tester")
    assert updated["status"] == "CONFIRMED"
    assert updated["analyst_feedback"][0]["analyst"] == "tester"

    updated = apply_feedback(db_session, chain_id, "DISMISSED", reason="false positive")
    assert updated["status"] == "DISMISSED"


def test_reconstruction_is_deterministic_for_same_input(db_session):
    _full_setup(db_session, ["CRED-001", "PHISH-001"])
    first, _ = list_chains(db_session)
    first_shape = [(c.event_count, round(c.confidence_score, 2), c.is_attack) for c in first]

    report = reconstruct(db_session)
    second, _ = list_chains(db_session)
    second_shape = [(c.event_count, round(c.confidence_score, 2), c.is_attack) for c in second]
    assert first_shape == second_shape
    assert report.chains == len(second)
