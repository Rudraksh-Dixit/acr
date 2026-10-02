"""Schemas for dataset catalog, dataset runs and dataset run history."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from app.schemas.events import IngestIssue


class DatasetCatalogItem(BaseModel):
    id: str
    name: str
    kind: str
    label: str
    source_name: str
    adapter: str
    ground_truth: bool
    description: str = ""
    available: bool = True
    path: Optional[str] = None
    fetch_hint: Optional[str] = None
    origin_url: Optional[str] = None
    rows: Optional[int] = None


class DatasetCatalogOut(BaseModel):
    items: list[DatasetCatalogItem]
    total: int


class DatasetRunRequest(BaseModel):
    model_config = {"extra": "forbid"}

    seed: int = 42
    ingest: bool = True
    reconstruct: bool = True
    replace_existing: bool = True


class DatasetAdapterOut(BaseModel):
    adapter: str = ""
    rows_read: int = 0
    issues: list[IngestIssue] = Field(default_factory=list)


class DatasetEvaluationOut(BaseModel):
    ground_truth: bool
    note: Optional[str] = None
    metrics: Optional[dict[str, Any]] = None
    per_scenario: Optional[list[dict[str, Any]]] = None


class DatasetRunOut(BaseModel):
    run_id: Optional[int] = None
    dataset: DatasetCatalogItem
    adapter: DatasetAdapterOut
    events_received: int = 0
    events_stored: int = 0
    events_replaced: int = 0
    events_skipped: int = 0
    duplicates: int = 0
    ingest_issues: list[IngestIssue] = Field(default_factory=list)
    detections: int = 0
    chains: int = 0
    attack_chains: int = 0
    reconstruction: Optional[dict[str, Any]] = None
    evaluation: DatasetEvaluationOut
    duration_seconds: float = 0.0


class DatasetRunHistoryItem(BaseModel):
    id: int
    created_at: str
    dataset_id: str
    label: str
    kind: str
    ground_truth: bool
    seed: int
    counts: dict[str, Any] = Field(default_factory=dict)
    evaluation: dict[str, Any] = Field(default_factory=dict)
    events_processed: int = 0
    duration_seconds: Optional[float] = None


class DatasetRunListOut(BaseModel):
    items: list[DatasetRunHistoryItem]
    total: int
    limit: int
    offset: int


class DatasetRunDetail(DatasetRunHistoryItem):
    config: dict[str, Any] = Field(default_factory=dict)
    notes: Optional[str] = None
