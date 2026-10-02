"""Investigation endpoints: bundle, summary, global stats, pipeline stages."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api import state
from app.core.config import settings
from app.core.database import get_db
from app.models import AttackChain, Detection, Entity, Event, EvaluationRun, Technique
from app.schemas.chains import InvestigationOut
from app.services.chain_service import get_chain_detections, get_chain_events, get_chain_full
from app.services.investigation_service import (
    build_network_view,
    build_process_tree,
    build_timeline,
    get_summary_service,
)
from app.reconstruction.graph_builder import build_attack_graph

router = APIRouter(prefix="/api", tags=["investigation"])


@router.get("/investigation/{chain_id}", response_model=InvestigationOut)
def investigate(
    chain_id: str,
    include_inferred: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> dict:
    full = get_chain_full(db, chain_id)
    if full is None:
        raise HTTPException(status_code=404, detail=f"chain '{chain_id}' not found")
    events = get_chain_events(db, chain_id)
    detections = get_chain_detections(db, chain_id)
    graph = build_attack_graph(events, detections, {"chain_id": chain_id})
    summary = get_summary_service().summarize(
        full, events, full.get("evidence") or [], full.get("techniques") or [], graph
    )
    return {
        "chain_id": chain_id,
        "timeline": build_timeline(
            events, detections,
            missing_steps=full.get("possible_missing_steps") or [],
            include_inferred=include_inferred,
        ),
        "process_tree": build_process_tree(events),
        "network": build_network_view(events),
        "summary": summary,
    }


@router.get("/investigation/{chain_id}/summary")
def investigation_summary(chain_id: str, db: Session = Depends(get_db)) -> dict:
    full = get_chain_full(db, chain_id)
    if full is None:
        raise HTTPException(status_code=404, detail=f"chain '{chain_id}' not found")
    events = get_chain_events(db, chain_id)
    detections = get_chain_detections(db, chain_id)
    graph = build_attack_graph(events, detections, {"chain_id": chain_id})
    return get_summary_service().summarize(
        full, events, full.get("evidence") or [], full.get("techniques") or [], graph
    )


@router.get("/stats")
def stats(db: Session = Depends(get_db)) -> dict:
    """Global counts for the frontend landing/dashboard."""
    def count(model) -> int:
        return int(db.scalar(select(func.count()).select_from(model)) or 0)

    severities = dict(db.execute(
        select(Event.severity, func.count()).group_by(Event.severity)
    ).all())
    risk_levels = dict(db.execute(
        select(AttackChain.risk_level, func.count()).group_by(AttackChain.risk_level)
    ).all())
    statuses = dict(db.execute(
        select(AttackChain.status, func.count()).group_by(AttackChain.status)
    ).all())
    return {
        "app": settings.app_name,
        "version": settings.version,
        "counts": {
            "events": count(Event),
            "detections": count(Detection),
            "chains": count(AttackChain),
            "attack_chains": int(db.scalar(
                select(func.count()).select_from(AttackChain).where(AttackChain.is_attack.is_(True))
            ) or 0),
            "entities": count(Entity),
            "techniques": count(Technique),
            "evaluation_runs": count(EvaluationRun),
        },
        "events_by_severity": severities,
        "chains_by_risk_level": risk_levels,
        "chains_by_status": statuses,
        "last_ingest": state.last_ingest(),
        "last_reconstruction": state.last_reconstruction(),
    }


@router.get("/pipeline")
def pipeline(db: Session = Depends(get_db)) -> dict:
    """Counts + last-run stats for every pipeline stage (ingest -> evaluate)."""
    def count(model) -> int:
        return int(db.scalar(select(func.count()).select_from(model)) or 0)

    last_recon = state.last_reconstruction()
    last_ingest = state.last_ingest()
    last_run_id = state.last_evaluation_run_id()
    stages = [
        {
            "stage": "ingestion",
            "description": "validate -> normalize -> persist -> extract entities",
            "count": count(Event),
            "last_run_at": last_ingest.get("at") if last_ingest else None,
            "last_run_detail": last_ingest,
        },
        {
            "stage": "detection",
            "description": "rule-based detection + ATT&CK enrichment",
            "count": count(Detection),
            "last_run_at": last_ingest.get("at") if last_ingest else None,
            "last_run_detail": {"detections": last_ingest.get("detections") if last_ingest else None},
        },
        {
            "stage": "correlation",
            "description": "multi-signal pairwise scoring + cluster formation",
            "count": (last_recon or {}).get("edges"),
            "last_run_at": last_recon.get("at") if last_recon else None,
            "last_run_detail": {
                k: (last_recon or {}).get(k)
                for k in ("edges", "clusters", "correlation_stats")
            } if last_recon else None,
        },
        {
            "stage": "reconstruction",
            "description": "seeded chain building + confidence/risk/missing steps",
            "count": count(AttackChain),
            "last_run_at": last_recon.get("at") if last_recon else None,
            "last_run_detail": {
                k: (last_recon or {}).get(k)
                for k in ("chains", "attacks", "chain_ids", "duration_seconds")
            } if last_recon else None,
        },
        {
            "stage": "mitre",
            "description": "ATT&CK annotation, coverage and progression",
            "count": count(Technique),
            "last_run_at": None,
            "last_run_detail": None,
        },
        {
            "stage": "evaluation",
            "description": "ground-truth comparison of the three stages",
            "count": count(EvaluationRun),
            "last_run_at": None,
            "last_run_detail": {"last_run_id": last_run_id},
        },
    ]
    return {
        "stages": stages,
        "config": {
            "time_windows": settings.time_windows(),
            "weights": settings.weights,
            "min_edge_score": settings.min_edge_score,
            "attack_confidence_threshold": settings.attack_confidence_threshold,
            "attack_risk_threshold": settings.attack_risk_threshold,
        },
    }
