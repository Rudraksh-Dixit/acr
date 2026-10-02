"""Entities (users, hosts, processes, files, IPs, domains) and their links."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.models import Base
from app.models.event import Event  # noqa: F401  (needed for type resolution)

ENTITY_TYPES = ("USER", "HOST", "PROCESS", "FILE", "IP", "DOMAIN", "TECHNIQUE")


class Entity(Base):
    __tablename__ = "entities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entity_type: Mapped[str] = mapped_column(String(24), index=True)
    value: Mapped[str] = mapped_column(String(512), index=True)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    metadata_json: Mapped[Optional[dict[str, Any]]] = mapped_column("metadata", JSON, nullable=True)

    __table_args__ = (UniqueConstraint("entity_type", "value", name="uq_entity_type_value"),)


class EventEntity(Base):
    __tablename__ = "event_entities"

    event_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("events.event_id", ondelete="CASCADE"), primary_key=True
    )
    entity_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("entities.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    event: Mapped[Event] = relationship(back_populates="entities")  # noqa: F821
    entity: Mapped[Entity] = relationship()


class Relationship(Base):
    """Directed relationship between two entities observed in telemetry."""

    __tablename__ = "relationships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_entity_id: Mapped[int] = mapped_column(Integer, ForeignKey("entities.id"), index=True)
    target_entity_id: Mapped[int] = mapped_column(Integer, ForeignKey("entities.id"), index=True)
    relation_type: Mapped[str] = mapped_column(String(48), index=True)  # USES, RUNS, SPAWNED, CREATED...
    event_id: Mapped[Optional[str]] = mapped_column(
        String(40), ForeignKey("events.event_id", ondelete="CASCADE"), nullable=True, index=True
    )
    host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True, index=True)
    confidence: Mapped[float] = mapped_column(default=1.0)

    __table_args__ = (
        Index("ix_rel_src_tgt_type", "source_entity_id", "target_entity_id", "relation_type"),
    )


Relationship.source_entity = relationship(  # type: ignore[attr-defined]
    Entity, foreign_keys=[Relationship.source_entity_id]
)
Relationship.target_entity = relationship(  # type: ignore[attr-defined]
    Entity, foreign_keys=[Relationship.target_entity_id]
)
