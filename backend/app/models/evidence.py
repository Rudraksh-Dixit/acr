"""Evidence records attached to chains (observed) or inferences."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.core.timeutils import utcnow

from app.models import Base
from app.models.chain import AttackChain  # noqa: F401  (needed for type resolution)


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    chain_id: Mapped[Optional[str]] = mapped_column(
        String(40), ForeignKey("attack_chains.chain_id", ondelete="CASCADE"), nullable=True, index=True
    )
    event_id: Mapped[Optional[str]] = mapped_column(
        String(40), ForeignKey("events.event_id", ondelete="CASCADE"), nullable=True, index=True
    )
    detection_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    kind: Mapped[str] = mapped_column(String(48), index=True)  # OBSERVED | INFERRED
    category: Mapped[str] = mapped_column(String(48), default="generic", index=True)
    summary: Mapped[str] = mapped_column(Text)
    details: Mapped[list | dict | None] = mapped_column(JSON, nullable=True)
    inferred: Mapped[bool] = mapped_column(default=False)
    confidence: Mapped[Optional[float]] = mapped_column(default=None, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    chain: Mapped[Optional["AttackChain"]] = relationship()  # noqa: F821
