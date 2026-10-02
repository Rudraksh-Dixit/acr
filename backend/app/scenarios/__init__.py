"""Scenario package: importing this module registers every built-in scenario."""
from __future__ import annotations

# side-effect import: each module registers its definition at import time
from app.scenarios import (  # noqa: F401
    benign,
    credential_attack,
    lateral_movement,
    persistence,
    phishing,
    powershell,
)
from app.scenarios.base import (
    ScenarioResult,
    generate_all,
    generate_scenario,
    get_definition,
    scenario_catalog,
)

__all__ = [
    "ScenarioResult",
    "generate_scenario",
    "generate_all",
    "scenario_catalog",
    "get_definition",
]
