"""Pydantic response/request schemas for events and ingestion."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class EventOut(BaseModel):
    model_config = ConfigDict(extra="ignore")

    event_id: str
    timestamp: Optional[datetime] = None
    event_type: str
    host: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process: Optional[str] = None
    parent_process_id: Optional[int] = None
    command_line: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    domain: Optional[str] = None
    severity: str = "INFO"
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactic: Optional[str] = None
    source: str = "unknown"
    metadata: dict[str, Any] = Field(default_factory=dict)
    scenario_id: Optional[str] = None
    chain_id: Optional[str] = None
    gt_id: Optional[str] = None


class DetectionOut(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: Optional[int] = None
    rule_id: str
    rule_name: str
    event_id: Optional[str] = None
    related_event_ids: list[str] = Field(default_factory=list)
    severity: str
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactic: Optional[str] = None
    title: str
    description: str = ""
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    host: Optional[str] = None
    scenario_id: Optional[str] = None
    created_at: Optional[datetime] = None


class EntityLinkOut(BaseModel):
    entity_type: str
    value: str
    role: Optional[str] = None


class EventDetailOut(EventOut):
    raw: Optional[dict[str, Any]] = None
    detections: list[DetectionOut] = Field(default_factory=list)
    entities: list[EntityLinkOut] = Field(default_factory=list)


class EventListOut(BaseModel):
    items: list[EventOut]
    total: int
    limit: int
    offset: int


class IngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[Any] = Field(default_factory=list, description="Raw telemetry records (JSON objects)")
    source: str = Field(default="api", max_length=64)
    scenario_id: Optional[str] = Field(default=None, max_length=64)
    reconstruct: bool = Field(default=False, description="Run correlation/reconstruction after ingestion")
    replace_duplicates: bool = False


class IngestIssue(BaseModel):
    index: Optional[int] = None
    scope: str
    field: Optional[str] = None
    message: str
    source: str = "unknown"


class IngestReportOut(BaseModel):
    received: int
    stored: int
    duplicates: int
    skipped: int
    detections: int
    issues: list[IngestIssue]
    issue_count: int
    duration_seconds: float
    source: str
    scenario_id: Optional[str] = None
    events_per_second: Optional[float] = None
    reconstruction: Optional[dict[str, Any]] = None
