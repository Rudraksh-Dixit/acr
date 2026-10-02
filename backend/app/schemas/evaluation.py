"""Schemas for evaluation runs."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class EvaluationRunRequest(BaseModel):
    model_config = {"extra": "forbid"}

    scenario_ids: Optional[list[str]] = None
    seed: int = 42
    persist: bool = True


class EvaluationOut(BaseModel):
    model_config = {"extra": "allow"}

    created_at: str
    config: dict[str, Any]
    metrics: dict[str, Any]
    per_scenario: list[dict[str, Any]]
    duration_seconds: float
    run_id: Optional[int] = None


class EvaluationRunSummary(BaseModel):
    model_config = {"extra": "allow"}

    id: int
    created_at: str
    events_processed: int
    duration_seconds: float
    metrics: dict[str, Any]


class EvaluationRunListOut(BaseModel):
    items: list[EvaluationRunSummary]
    total: int
    limit: int
    offset: int = 0


class EvaluationRunDetail(BaseModel):
    model_config = {"extra": "allow"}

    id: int
    created_at: str
    config: dict[str, Any]
    metrics: dict[str, Any]
    per_scenario: list[dict[str, Any]]
    events_processed: int
    duration_seconds: float


class StageComparisonOut(BaseModel):
    """Side-by-side comparison of the three evaluated pipeline stages."""

    technique_level: dict[str, dict[str, Any]]
    event_level: dict[str, dict[str, Any]]
    attack_detection: dict[str, dict[str, Any]]
    delta: dict[str, Any] = Field(default_factory=dict)
