"""Schemas for MITRE ATT&CK techniques and coverage."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class TechniqueOut(BaseModel):
    model_config = ConfigDict(extra="ignore")

    technique_id: str
    name: str
    tactic: str
    description: str = ""
    subtechnique_of: Optional[str] = None
    detection_hint: Optional[str] = None
    is_subtechnique: bool = False


class TechniqueListOut(BaseModel):
    items: list[TechniqueOut]
    total: int
    tactic: Optional[str] = None


class TacticOut(BaseModel):
    name: str
    techniques: int = 0


class TacticListOut(BaseModel):
    items: list[TacticOut]
    total: int


class CoverageTechnique(BaseModel):
    technique_id: str
    name: str


class CoverageTactic(BaseModel):
    tactic: str
    techniques: list[CoverageTechnique]
    count: int


class CoverageOut(BaseModel):
    tactics: list[CoverageTactic]
    unique_techniques: int
    unique_tactics: int
    sources: list[str] = Field(default_factory=list)
    chain_id: Optional[str] = None
    scenario_id: Optional[str] = None
