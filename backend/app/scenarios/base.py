"""Scenario registry and shared helpers.

Each scenario emits *raw* telemetry (source-shaped records, not the canonical
schema) so the full normalization pipeline is exercised before correlation.
Ground truth accompanies every scenario for evaluation.
"""
from __future__ import annotations

import random
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional


@dataclass
class ScenarioResult:
    scenario_id: str
    name: str
    description: str
    is_benign: bool
    events: list[dict[str, Any]]
    ground_truth: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "description": self.description,
            "is_benign": self.is_benign,
            "event_count": len(self.events),
            "ground_truth": self.ground_truth,
            "events": self.events,
        }


@dataclass
class Ctx:
    base: datetime
    seed: int = 42
    rng: random.Random = field(init=False)

    def __post_init__(self) -> None:
        self.rng = random.Random(self.seed)

    def ts(self, offset_seconds: float) -> str:
        moment = self.base + timedelta(seconds=offset_seconds)
        return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"

    def ev(self, gt_id: str, offset_seconds: float, **fields: Any) -> dict[str, Any]:
        return {"gt_id": gt_id, "timestamp": self.ts(offset_seconds), **fields}


GeneratorFn = Callable[[Ctx], tuple[list[dict[str, Any]], dict[str, Any]]]

_SCENARIOS: dict[str, dict[str, Any]] = {}


def register(scenario_id: str, name: str, description: str, is_benign: bool, fn: GeneratorFn) -> None:
    _SCENARIOS[scenario_id] = {
        "scenario_id": scenario_id,
        "name": name,
        "description": description,
        "is_benign": is_benign,
        "generate": fn,
    }


def scenario_catalog() -> list[dict[str, Any]]:
    return [
        {"scenario_id": meta["scenario_id"], "name": meta["name"],
         "description": meta["description"], "is_benign": meta["is_benign"]}
        for meta in _SCENARIOS.values()
    ]


def get_definition(scenario_id: str) -> Optional[dict[str, Any]]:
    if scenario_id in _SCENARIOS:
        return _SCENARIOS[scenario_id]
    lowered = scenario_id.lower()
    for key, meta in _SCENARIOS.items():
        if key.lower() == lowered or meta["name"].lower().replace(" ", "-") == lowered:
            return meta
    return None


def _scenario_hour_offset(scenario_id: str) -> int:
    """Deterministically spread scenarios across the previous 24h so that a
    global reconstruction never merges two unrelated scenarios."""
    return zlib.crc32(scenario_id.encode("utf-8")) % 24


def generate_scenario(
    scenario_id: str,
    base: Optional[datetime] = None,
    seed: int = 42,
) -> ScenarioResult:
    meta = get_definition(scenario_id)
    if meta is None:
        known = ", ".join(sorted(_SCENARIOS))
        raise KeyError(f"unknown scenario '{scenario_id}'. Available: {known}")
    if base is None:
        base = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0) - timedelta(
            hours=_scenario_hour_offset(scenario_id)
        )
    ctx = Ctx(base=base, seed=seed)
    events, ground_truth = meta["generate"](ctx)
    ground_truth = {
        "scenario_id": meta["scenario_id"],
        "name": meta["name"],
        "is_benign": meta["is_benign"],
        **ground_truth,
    }
    return ScenarioResult(
        scenario_id=meta["scenario_id"],
        name=meta["name"],
        description=meta["description"],
        is_benign=meta["is_benign"],
        events=events,
        ground_truth=ground_truth,
    )


def generate_all(base: Optional[datetime] = None, seed: int = 42) -> list[ScenarioResult]:
    return [generate_scenario(meta["scenario_id"], base=base, seed=seed) for meta in _SCENARIOS.values()]
