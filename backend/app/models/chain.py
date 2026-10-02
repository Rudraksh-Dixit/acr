"""Reconstructed attack chains, membership links and analyst feedback."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.core.timeutils import utcnow

from app.models import Base
from app.models.event import Event  # noqa: F401  (needed for type resolution)

CHAIN_STATUSES = (
    "RECONSTRUCTED",
    "INVESTIGATING",
    "CONFIRMED",
    "DISMISSED",
    "BENIGN",
)

FEEDBACK_STATUSES = ("CONFIRMED", "DISMISSED", "BENIGN", "INVESTIGATING")


class AttackChain(Base):
    __tablename__ = "attack_chains"

    chain_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    start_time: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True, index=True)
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(default=None, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="RECONSTRUCTED", index=True)

    confidence_score: Mapped[float] = mapped_column(default=0.0, index=True)
    confidence_reasons: Mapped[list] = mapped_column(JSON, default=list)
    risk_score: Mapped[float] = mapped_column(default=0.0, index=True)
    risk_level: Mapped[str] = mapped_column(String(16), default="LOW", index=True)
    risk_factors: Mapped[list] = mapped_column(JSON, default=list)

    attack_path: Mapped[list] = mapped_column(JSON, default=list)
    techniques: Mapped[list] = mapped_column(JSON, default=list)
    tactics: Mapped[list] = mapped_column(JSON, default=list)
    hosts: Mapped[list] = mapped_column(JSON, default=list)
    users: Mapped[list] = mapped_column(JSON, default=list)
    processes: Mapped[list] = mapped_column(JSON, default=list)
    entities: Mapped[list] = mapped_column(JSON, default=list)
    possible_missing_steps: Mapped[list] = mapped_column(JSON, default=list)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    event_count: Mapped[int] = mapped_column(Integer, default=0)
    is_attack: Mapped[bool] = mapped_column(default=False, index=True)
    scenario_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow
    )

    events: Mapped[list["ChainEvent"]] = relationship(
        back_populates="chain", cascade="all, delete-orphan", order_by="ChainEvent.position"
    )
    feedback: Mapped[list["AnalystFeedback"]] = relationship(
        back_populates="chain", cascade="all, delete-orphan"
    )


class ChainEvent(Base):
    __tablename__ = "chain_events"

    chain_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("attack_chains.chain_id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("events.event_id", ondelete="CASCADE"), primary_key=True
    )
    position: Mapped[int] = mapped_column(Integer, default=0)
    link_score: Mapped[Optional[float]] = mapped_column(default=None, nullable=True)

    chain: Mapped[AttackChain] = relationship(back_populates="events")
    event: Mapped["Event"] = relationship()  # noqa: F821


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    chain_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("attack_chains.chain_id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(24))
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    analyst: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)

    chain: Mapped[AttackChain] = relationship(back_populates="feedback")
