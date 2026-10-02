from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


from app.models.event import Event, Detection  # noqa: E402,F401
from app.models.entity import Entity, EventEntity, Relationship  # noqa: E402,F401
from app.models.chain import AttackChain, ChainEvent, AnalystFeedback  # noqa: E402,F401
from app.models.evidence import Evidence  # noqa: E402,F401
from app.models.technique import Technique  # noqa: E402,F401
from app.models.scenario import Scenario, EvaluationRun  # noqa: E402,F401
from app.models.dataset_run import DatasetRun  # noqa: E402,F401

__all__ = [
    "Base",
    "Event",
    "Detection",
    "Entity",
    "EventEntity",
    "Relationship",
    "AttackChain",
    "ChainEvent",
    "AnalystFeedback",
    "Evidence",
    "Technique",
    "Scenario",
    "EvaluationRun",
    "DatasetRun",
]
