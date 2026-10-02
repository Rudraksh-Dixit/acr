"""Schemas for scenario catalog, generation and demo-data reset."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from app.schemas.events import IngestIssue


class ScenarioCatalogItem(BaseModel):
    scenario_id: str
    name: str
    description: str
    is_benign: bool


class ScenarioCatalogOut(BaseModel):
    items: list[ScenarioCatalogItem]
    total: int


class ScenarioGenerateRequest(BaseModel):
    model_config = {"extra": "forbid"}

    scenario_ids: Optional[list[str]] = Field(
        default=None, description="Subset of scenario ids; all scenarios when omitted"
    )
    seed: int = 42
    ingest: bool = True
    reconstruct: bool = True
    include_ground_truth: bool = False
    replace_duplicates: bool = False


class ScenarioGenerateItem(BaseModel):
    scenario_id: str
    name: str = ""
    is_benign: bool = False
    events_emitted: int = 0
    events_received: int = 0
    events_stored: int = 0
    duplicates: int = 0
    skipped: int = 0
    detections: int = 0
    chains: int = 0
    attack_chains: int = 0
    chain_ids: list[str] = Field(default_factory=list)
    issues: list[IngestIssue] = Field(default_factory=list)
    ground_truth: Optional[dict[str, Any]] = None


class ScenarioGenerateOut(BaseModel):
    scenarios: list[ScenarioGenerateItem]
    events_stored: int
    events_replaced: int = 0
    detections: int
    chains: int
    attack_chains: int
    reconstruction: Optional[dict[str, Any]] = None
    duration_seconds: float


class ScenarioResetRequest(BaseModel):
    model_config = {"extra": "forbid"}

    confirm: bool = True
    reconstruct: bool = False


class ScenarioResetOut(BaseModel):
    cleared: dict[str, int]
    remaining: dict[str, int]
    reconstruction: Optional[dict[str, Any]] = None
