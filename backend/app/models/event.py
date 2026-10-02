"""Normalized telemetry events and raw detection alerts."""
from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.core.timeutils import utcnow

from app.models import Base

if TYPE_CHECKING:
    from app.models.entity import EventEntity


class Event(Base):
    """Canonical normalized event (the single source of truth for telemetry)."""

    __tablename__ = "events"

    event_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    user: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    source_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    process_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    process_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    parent_process: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    parent_process_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    command_line: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True, index=True)
    file_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(16), default="INFO", index=True)
    technique_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    technique_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    tactic: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    metadata_json: Mapped[Optional[dict[str, Any]]] = mapped_column("metadata", JSON, nullable=True)
    raw: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    scenario_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    gt_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)  # ground-truth tag
    ingested_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    detections: Mapped[list["Detection"]] = relationship(
        back_populates="event", cascade="all, delete-orphan"
    )
    entities: Mapped[list["EventEntity"]] = relationship(
        back_populates="event", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_events_ts_host", "timestamp", "host"),
        Index("ix_events_src_dst", "source_ip", "destination_ip"),
    )


class Detection(Base):
    """A single rule match produced by the detection engine."""

    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_name: Mapped[str] = mapped_column(String(255))
    event_id: Mapped[Optional[str]] = mapped_column(
        String(40), ForeignKey("events.event_id", ondelete="CASCADE"), nullable=True, index=True
    )
    related_event_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="INFO", index=True)
    technique_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    technique_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    tactic: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    evidence_json: Mapped[list] = mapped_column("evidence", JSON, default=list)
    host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    scenario_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)

    event: Mapped[Optional[Event]] = relationship(back_populates="detections")
