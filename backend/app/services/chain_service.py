"""Chain reconstruction orchestration, persistence and analyst feedback."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.config import Settings, settings as default_settings
from app.core.killchain import covered_stages, furthest_stage, stage_for_tactic, stage_name
from app.core.logging import get_logger, log_event
from app.correlation.engine import get_engine
from app.models import AnalystFeedback, AttackChain, ChainEvent, Detection, Evidence, Event
from app.reconstruction.chain_builder import ChainDraft, build_chains
from app.services.event_service import detection_to_dict, event_to_dict, load_all_events, run_detection_pass_

logger = get_logger("chain")

VALID_STATUSES = ("CONFIRMED", "DISMISSED", "BENIGN", "INVESTIGATING")


@dataclass
class ReconstructionReport:
    events: int = 0
    detections: int = 0
    edges: int = 0
    clusters: int = 0
    chains: int = 0
    attacks: int = 0
    duration_seconds: float = 0.0
    correlation_stats: dict[str, Any] = field(default_factory=dict)
    chain_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "events": self.events,
            "detections": self.detections,
            "edges": self.edges,
            "clusters": self.clusters,
            "chains": self.chains,
            "attacks": self.attacks,
            "chain_ids": self.chain_ids,
            "duration_seconds": round(self.duration_seconds, 4),
            "correlation_stats": self.correlation_stats,
        }


def iso(value: Optional[datetime]) -> Optional[str]:
    return (value.isoformat() + "Z") if isinstance(value, datetime) else None


def _chain_tactics(chain: AttackChain) -> list[str]:
    """Tactics of a chain, falling back to its technique records."""
    if chain.tactics:
        return list(chain.tactics)
    return [
        t.get("tactic") or ""
        for t in (chain.techniques or [])
        if isinstance(t, dict) and (t.get("tactic") or "")
    ]


def kill_chain_fields(chain: AttackChain) -> dict[str, Any]:
    """Derived kill chain stage fields (never stored, always computed)."""
    tactics = _chain_tactics(chain)
    stage = furthest_stage(tactics)
    return {
        "kill_chain_stage": stage,
        "kill_chain_stage_name": stage_name(stage),
        "kill_chain_stages": covered_stages(tactics),
    }


def techniques_with_stage(techniques: Optional[list[Any]]) -> list[Any]:
    """Attach the derived kill_chain_stage to each technique dict."""
    enriched: list[Any] = []
    for t in techniques or []:
        if isinstance(t, dict):
            enriched.append({**t, "kill_chain_stage": stage_for_tactic(t.get("tactic"))})
        else:
            enriched.append(t)
    return enriched


def reconstruct(session: Session, settings: Settings | None = None,
                scenario_id: Optional[str] = None) -> ReconstructionReport:
    """correlation -> reconstruction -> scoring -> persistence."""
    cfg = settings or default_settings
    started = time.perf_counter()
    report = ReconstructionReport()

    events = load_all_events(session)
    if scenario_id:
        events = [e for e in events if e.get("scenario_id") == scenario_id]
    report.events = len(events)

    det_rows = session.scalars(select(Detection)).all()
    detections = [detection_to_dict(d) for d in det_rows]
    if events and not detections:
        run_detection_pass_(session, cfg)
        detections = [detection_to_dict(d) for d in session.scalars(select(Detection)).all()]
    if scenario_id:
        detections = [d for d in detections if d.get("scenario_id") == scenario_id]
    report.detections = len(detections)

    correlation = get_engine().correlate(events, cfg)
    report.edges = len(correlation.edges)
    report.clusters = len(correlation.clusters)
    report.correlation_stats = correlation.stats

    drafts = build_chains(events, correlation, detections, cfg)
    _persist_chains(session, drafts)

    report.chains = len(drafts)
    report.attacks = sum(1 for d in drafts if d.is_attack)
    report.chain_ids = [d.chain_id for d in drafts]
    report.duration_seconds = time.perf_counter() - started
    log_event(logger, "reconstruct_complete", **report.to_dict())
    return report


def _clear_chains(session: Session) -> None:
    session.execute(delete(ChainEvent))
    session.execute(delete(Evidence))
    session.execute(delete(AnalystFeedback))
    session.execute(delete(AttackChain))
    session.flush()


def _persist_chains(session: Session, drafts: list[ChainDraft]) -> None:
    _clear_chains(session)
    for draft in drafts:
        chain = AttackChain(
            chain_id=draft.chain_id,
            start_time=draft.start_time,
            end_time=draft.end_time,
            duration_seconds=draft.duration_seconds,
            status=draft.status,
            confidence_score=draft.confidence.score,
            confidence_reasons=[r for r in draft.confidence.to_dict()["reasons"]],
            risk_score=draft.risk.score,
            risk_level=draft.risk.level,
            risk_factors=draft.risk.factors,
            attack_path=draft.attack_path,
            techniques=draft.techniques,
            tactics=draft.tactics,
            hosts=draft.hosts,
            users=draft.users,
            processes=draft.processes,
            entities=draft.entities,
            possible_missing_steps=draft.possible_missing_steps,
            summary=draft.summary,
            event_count=len(draft.event_ids),
            is_attack=draft.is_attack,
            scenario_id=draft.events[0].get("scenario_id") if draft.events else None,
        )
        session.add(chain)
        session.flush()
        for position, event_id in enumerate(draft.event_ids):
            session.add(ChainEvent(chain_id=draft.chain_id, event_id=event_id, position=position))
        for item in draft.evidence:
            session.add(Evidence(
                chain_id=draft.chain_id,
                event_id=(item.get("event_id") if item.get("event_id") else
                          (item.get("event_ids") or [None])[0]),
                kind=item.get("kind", "OBSERVED"),
                category=item.get("type", "generic"),
                summary=item.get("summary", ""),
                details=item.get("details"),
                inferred=item.get("kind") == "INFERRED",
                confidence=item.get("confidence"),
            ))
        for step in draft.possible_missing_steps:
            session.add(Evidence(
                chain_id=draft.chain_id,
                kind="INFERRED",
                category="POSSIBLE_MISSING_STEP",
                summary=f"Possible missing step: {step.get('technique_id')} ({step.get('tactic')})",
                details=step,
                inferred=True,
                confidence=step.get("confidence"),
            ))
    session.commit()


# --- queries ---------------------------------------------------------------

def chain_summary_dict(chain: AttackChain) -> dict[str, Any]:
    return {
        "chain_id": chain.chain_id,
        "status": chain.status,
        "is_attack": chain.is_attack,
        "start_time": iso(chain.start_time),
        "end_time": iso(chain.end_time),
        "duration_seconds": chain.duration_seconds,
        "event_count": chain.event_count,
        "confidence": {"score": chain.confidence_score, "reasons": chain.confidence_reasons or []},
        "risk": {"score": chain.risk_score, "level": chain.risk_level, "factors": chain.risk_factors or []},
        "tactics": chain.tactics or [],
        "techniques": techniques_with_stage(chain.techniques),
        **kill_chain_fields(chain),
        "hosts": chain.hosts or [],
        "users": chain.users or [],
        "summary": chain.summary,
        "scenario_id": chain.scenario_id,
        "created_at": iso(chain.created_at),
    }


def list_chains(
    session: Session,
    status: Optional[str] = None,
    is_attack: Optional[bool] = None,
    scenario_id: Optional[str] = None,
    host: Optional[str] = None,
    min_confidence: Optional[float] = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[AttackChain], int]:
    stmt = select(AttackChain)
    if status:
        stmt = stmt.where(AttackChain.status == status.upper())
    if is_attack is not None:
        stmt = stmt.where(AttackChain.is_attack == is_attack)
    if scenario_id:
        stmt = stmt.where(AttackChain.scenario_id == scenario_id)
    if host:
        stmt = stmt.where(AttackChain.hosts.like(f'%"{host.lower()}"%'))
    if min_confidence is not None:
        stmt = stmt.where(AttackChain.confidence_score >= min_confidence)
    total = int(session.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0)
    rows = session.scalars(
        stmt.order_by(AttackChain.start_time.asc().nulls_last()).limit(limit).offset(offset)
    ).all()
    return rows, total


def get_chain_events(session: Session, chain_id: str) -> list[dict[str, Any]]:
    rows = session.execute(
        select(Event, ChainEvent.position)
        .join(ChainEvent, ChainEvent.event_id == Event.event_id)
        .where(ChainEvent.chain_id == chain_id)
        .order_by(ChainEvent.position)
    ).all()
    return [event_to_dict(event) for event, _ in rows]


def get_chain_detections(session: Session, chain_id: str) -> list[dict[str, Any]]:
    event_ids = [e["event_id"] for e in get_chain_events(session, chain_id)]
    if not event_ids:
        return []
    rows = session.scalars(select(Detection).where(Detection.event_id.in_(event_ids))).all()
    return [detection_to_dict(r) for r in rows]


def get_chain_full(session: Session, chain_id: str) -> Optional[dict[str, Any]]:
    chain = session.get(AttackChain, chain_id)
    if chain is None:
        return None
    events = get_chain_events(session, chain_id)
    detections = get_chain_detections(session, chain_id)
    evidence_block = get_chain_evidence(session, chain_id)
    feedback = session.scalars(
        select(AnalystFeedback).where(AnalystFeedback.chain_id == chain_id)
        .order_by(AnalystFeedback.created_at.desc())
    ).all()
    return {
        "chain_id": chain.chain_id,
        "status": chain.status,
        "is_attack": chain.is_attack,
        "start_time": iso(chain.start_time),
        "end_time": iso(chain.end_time),
        "duration_seconds": chain.duration_seconds,
        "confidence": {"score": chain.confidence_score, "reasons": chain.confidence_reasons or [],
                       "links_analyzed": None},
        "risk": {"score": chain.risk_score, "level": chain.risk_level, "factors": chain.risk_factors or []},
        "events": events,
        "detections": detections,
        "entities": chain.entities or [],
        "techniques": techniques_with_stage(chain.techniques),
        "tactics": chain.tactics or [],
        **kill_chain_fields(chain),
        "hosts": chain.hosts or [],
        "users": chain.users or [],
        "processes": chain.processes or [],
        "attack_path": chain.attack_path or [],
        "evidence": evidence_block["observed"],
        "evidence_summary": {
            "observed": evidence_block["observed_count"],
            "inferred": evidence_block["inferred_count"],
        },
        "possible_missing_steps": chain.possible_missing_steps or [],
        "summary": chain.summary,
        "event_count": chain.event_count,
        "scenario_id": chain.scenario_id,
        "created_at": iso(chain.created_at),
        "updated_at": iso(chain.updated_at),
        "analyst_feedback": [
            {
                "status": f.status,
                "comment": f.comment,
                "reason": f.reason,
                "analyst": f.analyst,
                "created_at": iso(f.created_at),
            }
            for f in feedback
        ],
    }


def get_chain_evidence(session: Session, chain_id: str) -> dict[str, Any]:
    rows = session.scalars(
        select(Evidence).where(Evidence.chain_id == chain_id).order_by(Evidence.id)
    ).all()
    observed: list[dict[str, Any]] = []
    inferred: list[dict[str, Any]] = []
    for row in rows:
        item = {
            "id": row.id,
            "kind": row.kind,
            "type": row.category,
            "event_id": row.event_id,
            "summary": row.summary,
            "details": row.details,
            "inferred": bool(row.inferred),
            "confidence": row.confidence,
        }
        (inferred if row.inferred else observed).append(item)
    return {"chain_id": chain_id, "observed": observed, "inferred": inferred,
            "observed_count": len(observed), "inferred_count": len(inferred)}


def apply_feedback(
    session: Session,
    chain_id: str,
    status: str,
    comment: Optional[str] = None,
    reason: Optional[str] = None,
    analyst: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    chain = session.get(AttackChain, chain_id)
    if chain is None:
        return None
    status_upper = status.upper()
    if status_upper not in VALID_STATUSES:
        raise ValueError(f"status must be one of {', '.join(VALID_STATUSES)}")
    chain.status = status_upper
    session.add(AnalystFeedback(
        chain_id=chain_id,
        status=status_upper,
        comment=(comment or "")[:4000] or None,
        reason=(reason or "")[:4000] or None,
        analyst=(analyst or "anonymous")[:120],
    ))
    session.commit()
    log_event(logger, "analyst_feedback", chain_id=chain_id, status=status_upper)
    return get_chain_full(session, chain_id)
