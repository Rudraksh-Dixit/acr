"""Schemas for IOC import."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class InlineIndicator(BaseModel):
    model_config = {"extra": "forbid"}

    type: Optional[str] = Field(default=None, description="ip | domain | hash (inferred if omitted)")
    value: str = Field(max_length=512)
    source: Optional[str] = Field(default=None, max_length=200)


class IocImportRequest(BaseModel):
    """Either raw indicator content (CSV / STIX / JSON) or inline indicators."""

    model_config = {"extra": "forbid"}

    content: Optional[str] = Field(default=None, description="Raw CSV / STIX / JSON indicator text")
    filename: Optional[str] = Field(default=None, max_length=255)
    format: str = Field(default="auto", pattern="^(auto|csv|stix|json)$")
    source: str = Field(default="ioc_upload", max_length=120)
    indicators: Optional[list[InlineIndicator]] = Field(
        default=None, description="Alternative to content: typed indicators directly"
    )


class IocMatchOut(BaseModel):
    model_config = {"extra": "allow"}

    event_id: Optional[str] = None
    field: str
    indicator_type: str
    indicator_value: str
    indicator_source: str
    observed_value: Optional[str] = None
    host: Optional[str] = None
    scenario_id: Optional[str] = None
    detection_id: Optional[int] = None


class IocImportOut(BaseModel):
    model_config = {"extra": "allow"}

    format: str
    source: str
    indicators_received: int
    indicators_parsed: int
    indicators_invalid: int
    issues: list[dict[str, Any]] = Field(default_factory=list)
    by_type: dict[str, int] = Field(default_factory=dict)
    events_scanned: int
    matches_found: int
    detections_created: int
    evidence_created: int
    duplicates_skipped: int
    matched_by_type: dict[str, int] = Field(default_factory=dict)
    matches: list[IocMatchOut] = Field(default_factory=list)
    matches_truncated: bool = False
    duration_seconds: float
