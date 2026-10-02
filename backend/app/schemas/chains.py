"""Pydantic schemas for attack chains, graphs and investigation views."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.events import DetectionOut, EventOut


class ConfidenceReason(BaseModel):
    signal: str
    label: str
    points: float
    explanation: str = ""


class ConfidenceOut(BaseModel):
    score: float
    reasons: list[ConfidenceReason] = Field(default_factory=list)
    links_analyzed: Optional[int] = None


class RiskFactor(BaseModel):
    factor: str
    points: float
    detail: str


class RiskOut(BaseModel):
    score: float
    level: str
    factors: list[RiskFactor] = Field(default_factory=list)


class TechniqueRef(BaseModel):
    technique_id: str
    name: str = ""
    tactic: str = ""
    observed: bool = True
    kill_chain_stage: Optional[int] = None


class EntityRefOut(BaseModel):
    type: str
    value: str
    label: str = ""
    role: str = ""


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    kind: str = "OBSERVED"
    type: str = "generic"
    summary: str = ""
    inferred: bool = False
    confidence: Optional[float] = None
    event_id: Optional[str] = None
    event_ids: Optional[list[str]] = None
    rule_id: Optional[str] = None
    severity: Optional[str] = None
    technique_id: Optional[str] = None
    description: Optional[str] = None
    details: Optional[Any] = None
    points: Optional[float] = None
    window: Optional[str] = None


class MissingStep(BaseModel):
    model_config = ConfigDict(extra="allow")

    technique_id: str
    technique_name: str = ""
    tactic: str = ""
    confidence: float
    inferred: bool = True
    observed: bool = False
    kind: str = "MISSING_TACTIC_GAP"
    reason: str = ""
    explanation: str = ""


class AttackStage(BaseModel):
    model_config = ConfigDict(extra="allow")

    stage: int
    kind: str = "OBSERVED"
    inferred: bool = False
    tactic: Optional[str] = None
    technique_id: Optional[str] = None
    confidence: Optional[float] = None
    timestamp: Optional[str] = None
    event_ids: list[str] = Field(default_factory=list)


class AnalystFeedbackOut(BaseModel):
    status: str
    comment: Optional[str] = None
    reason: Optional[str] = None
    analyst: Optional[str] = None
    created_at: Optional[str] = None


class ChainSummary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    chain_id: str
    status: str
    is_attack: bool = False
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: Optional[float] = None
    event_count: int = 0
    confidence: ConfidenceOut
    risk: RiskOut
    tactics: list[str] = Field(default_factory=list)
    techniques: list[TechniqueRef] = Field(default_factory=list)
    kill_chain_stage: Optional[int] = None
    kill_chain_stage_name: Optional[str] = None
    kill_chain_stages: list[int] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    summary: Optional[str] = None
    scenario_id: Optional[str] = None
    created_at: Optional[str] = None


class ChainDetail(ChainSummary):
    events: list[EventOut] = Field(default_factory=list)
    detections: list[DetectionOut] = Field(default_factory=list)
    entities: list[EntityRefOut] = Field(default_factory=list)
    processes: list[str] = Field(default_factory=list)
    attack_path: list[AttackStage] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    evidence_summary: dict[str, int] = Field(default_factory=dict)
    possible_missing_steps: list[MissingStep] = Field(default_factory=list)
    updated_at: Optional[str] = None
    analyst_feedback: list[AnalystFeedbackOut] = Field(default_factory=list)


class ChainListOut(BaseModel):
    items: list[ChainSummary]
    total: int
    limit: int
    offset: int


class TimelineItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    seq: int
    kind: str = "OBSERVED"
    inferred: bool = False
    timestamp: Optional[str] = None
    event_id: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None
    summary: str = ""
    command_line: Optional[str] = None
    entity: Optional[dict[str, Any]] = None
    relationships: list[dict[str, Any]] = Field(default_factory=list)
    technique: Optional[dict[str, Any]] = None
    tactic: Optional[str] = None
    confidence: Optional[float] = None
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class TimelineOut(BaseModel):
    chain_id: str
    include_inferred: bool = False
    items: list[TimelineItem]
    event_count: int
    inferred_count: int = 0


class GraphNode(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    type: str
    label: str = ""


class GraphEdge(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    source: str
    target: str
    relation: str


class GraphOut(BaseModel):
    chain_id: Optional[str] = None
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    relationships: list[GraphEdge] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProcessTreeNode(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    process_name: str
    pid: Optional[int] = None
    ppid: Optional[int] = None
    parent_process_name: Optional[str] = None
    host: Optional[str] = None
    command_line: Optional[str] = None
    severity: Optional[str] = None
    technique_id: Optional[str] = None
    event_id: Optional[str] = None
    children: list["ProcessTreeNode"] = Field(default_factory=list)


class NetworkViewOut(BaseModel):
    connections: list[dict[str, Any]] = Field(default_factory=list)
    dns_queries: list[dict[str, Any]] = Field(default_factory=list)
    external_destinations: list[str] = Field(default_factory=list)
    graph: dict[str, Any] = Field(default_factory=dict)
    counts: dict[str, int] = Field(default_factory=dict)


class InvestigationOut(BaseModel):
    chain_id: Optional[str] = None
    timeline: list[TimelineItem]
    process_tree: list[ProcessTreeNode]
    network: NetworkViewOut
    summary: dict[str, Any]


class EvidenceBlock(BaseModel):
    chain_id: str
    observed: list[EvidenceItem]
    inferred: list[EvidenceItem]
    observed_count: int
    inferred_count: int


class FeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    comment: Optional[str] = Field(default=None, max_length=4000)
    reason: Optional[str] = Field(default=None, max_length=4000)
    analyst: Optional[str] = Field(default=None, max_length=120)


class FeedbackComment(BaseModel):
    """Optional payload for the shorthand confirm/dismiss endpoints."""

    model_config = ConfigDict(extra="forbid")

    comment: Optional[str] = Field(default=None, max_length=4000)
    reason: Optional[str] = Field(default=None, max_length=4000)
    analyst: Optional[str] = Field(default=None, max_length=120)
