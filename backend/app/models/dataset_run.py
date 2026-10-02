"""Dataset run history: one row per executed catalog dataset run."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutils import utcnow
from app.models import Base


class DatasetRun(Base):
    __tablename__ = "dataset_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    dataset_id: Mapped[str] = mapped_column(String(128), index=True)
    label: Mapped[str] = mapped_column(String(128), default="")
    kind: Mapped[str] = mapped_column(String(32), default="real")
    ground_truth: Mapped[bool] = mapped_column(default=False)
    seed: Mapped[int] = mapped_column(Integer, default=42)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    counts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    evaluation: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    events_processed: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, default=None, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
