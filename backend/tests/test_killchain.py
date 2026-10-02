"""Kill chain mapping (tactic -> stage) unit + API contract tests."""
from __future__ import annotations

from app.core.killchain import (
    KILL_CHAIN_STAGES,
    TACTIC_TO_STAGE,
    covered_stages,
    furthest_stage,
    stage_for_tactic,
    stage_name,
)


def test_stage_for_tactic_known_and_unknown():
    assert stage_for_tactic("INITIAL ACCESS") == 3
    assert stage_for_tactic("initial access") == 3  # case-insensitive
    assert stage_for_tactic("  PERSISTENCE  ") == 5
    assert stage_for_tactic("COMMAND AND CONTROL") == 6
    assert stage_for_tactic("EXFILTRATION") == 7
    assert stage_for_tactic("NOT A REAL TACTIC") is None
    assert stage_for_tactic(None) is None
    assert stage_for_tactic("") is None


def test_every_mapped_stage_is_valid():
    assert len(KILL_CHAIN_STAGES) == 7
    for tactic, stage in TACTIC_TO_STAGE.items():
        assert 1 <= stage <= len(KILL_CHAIN_STAGES), tactic
        assert stage_name(stage) in KILL_CHAIN_STAGES


def test_furthest_stage_and_covered_stages():
    assert furthest_stage(["INITIAL ACCESS", "EXECUTION"]) == 4
    assert furthest_stage(["EXECUTION", "PERSISTENCE", "COMMAND AND CONTROL"]) == 6
    assert furthest_stage(["CREDENTIAL ACCESS"]) == 7
    assert furthest_stage([]) is None
    assert furthest_stage(None) is None
    assert covered_stages(["EXECUTION", "PERSISTENCE", "COMMAND AND CONTROL"]) == [4, 5, 6]
    # unknown tactics are ignored, not guessed
    assert furthest_stage(["WAT"]) is None
    assert covered_stages(["INITIAL ACCESS", "WAT"]) == [3]


def test_stage_name_bounds():
    assert stage_name(1) == "Recon"
    assert stage_name(7) == "Actions on Objectives"
    assert stage_name(0) is None
    assert stage_name(8) is None
    assert stage_name(None) is None


def test_config_exposes_kill_chain_mapping(client):
    config = client.get("/api/config").json()["kill_chain"]
    assert config["stages"] == list(KILL_CHAIN_STAGES)
    assert config["tactic_to_stage"]["INITIAL ACCESS"] == 3
    assert config["tactic_to_stage"]["COMMAND AND CONTROL"] == 6


def test_chains_carry_derived_kill_chain_stage(client, generate_all_scenarios):
    generate_all_scenarios(seed=42)
    items = client.get("/api/chains").json()["items"]
    assert items
    for chain in items:
        stage = chain["kill_chain_stage"]
        assert stage is not None
        assert chain["kill_chain_stage_name"] == KILL_CHAIN_STAGES[stage - 1]
        # covered stages must equal the tactic-derived set, ascending + unique
        tactics = chain["tactics"]
        assert chain["kill_chain_stages"] == sorted({TACTIC_TO_STAGE[t] for t in tactics})
        assert stage == max(chain["kill_chain_stages"])
        for tech in chain["techniques"]:
            assert tech["kill_chain_stage"] == TACTIC_TO_STAGE[tech["tactic"]]

    by_id = {c["chain_id"]: c for c in items}
    assert by_id["ACR-0001"]["kill_chain_stage"] == 6
    assert by_id["ACR-0001"]["kill_chain_stage_name"] == "C2"
    assert by_id["ACR-0002"]["kill_chain_stage"] == 7
    assert by_id["ACR-0004"]["kill_chain_stages"] == [4, 5, 6, 7]


def test_chain_detail_and_technique_endpoints_expose_stage(client, generate_all_scenarios):
    generate_all_scenarios(seed=42)
    detail = client.get("/api/chains/ACR-0001").json()
    assert detail["kill_chain_stage"] == 6
    assert detail["kill_chain_stage_name"] == "C2"

    techs = client.get("/api/mitre/techniques").json()["items"]
    assert techs and all("kill_chain_stage" in t for t in techs)
    cred = next(t for t in techs if t["technique_id"] == "T1003")
    assert cred["kill_chain_stage"] == 7  # CREDENTIAL ACCESS -> Actions on Objectives

    single = client.get("/api/mitre/techniques/T1059").json()
    assert single["kill_chain_stage"] == 4  # EXECUTION -> Exploitation
