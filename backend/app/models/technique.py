"""Locally stored MITRE ATT&CK technique metadata (populated from techniques.json)."""
from __future__ import annotations

from typing import Optional

from sqlalchemy import Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class Technique(Base):
    __tablename__ = "techniques"

    technique_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    tactic: Mapped[str] = mapped_column(String(64), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    subtechnique_of: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    detection_hint: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
