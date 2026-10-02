"""Synthetic scenario registry and evaluation run records."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from app.core.timeutils import utcnow

from app.models import Base


class Scenario(Base):
    __tablename__ = "scenarios"

    scenario_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    is_benign: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    ground_truth: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    per_scenario: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    stages: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    events_processed: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[Optional[float]] = mapped_column(default=None, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
