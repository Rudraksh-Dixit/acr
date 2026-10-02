"""Attack chain endpoints: list, detail, timeline, evidence, views, feedback."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.chains import (
    ChainDetail,
    ChainListOut,
    EvidenceBlock,
    FeedbackComment,
    FeedbackRequest,
    InvestigationOut,
    NetworkViewOut,
    ProcessTreeNode,
    TimelineOut,
)
from app.services import chain_service
from app.services.investigation_service import (
    build_network_view,
    build_process_tree,
    build_timeline,
    get_summary_service,
)
from app.reconstruction.graph_builder import build_attack_graph

router = APIRouter(prefix="/api/chains", tags=["chains"])


def _load_chain(db: Session, chain_id: str) -> dict:
    full = chain_service.get_chain_full(db, chain_id)
    if full is None:
        raise HTTPException(status_code=404, detail=f"chain '{chain_id}' not found")
    return full


@router.get("", response_model=ChainListOut)
def list_chains(
    status: Optional[str] = None,
    is_attack: Optional[bool] = None,
    scenario_id: Optional[str] = None,
    host: Optional[str] = None,
    min_confidence: Optional[float] = Query(default=None, ge=0, le=100),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> ChainListOut:
    rows, total = chain_service.list_chains(
        db, status=status, is_attack=is_attack, scenario_id=scenario_id,
        host=host, min_confidence=min_confidence, limit=limit, offset=offset,
    )
    return {
        "items": [chain_service.chain_summary_dict(c) for c in rows],
        "total": total, "limit": limit, "offset": offset,
    }


@router.get("/{chain_id}", response_model=ChainDetail)
def get_chain(chain_id: str, db: Session = Depends(get_db)) -> dict:
    return _load_chain(db, chain_id)


@router.get("/{chain_id}/timeline", response_model=TimelineOut)
def chain_timeline(
    chain_id: str,
    include_inferred: bool = Query(default=False, description="Include inferred missing steps"),
    db: Session = Depends(get_db),
) -> dict:
    full = _load_chain(db, chain_id)
    events = chain_service.get_chain_events(db, chain_id)
    detections = chain_service.get_chain_detections(db, chain_id)
    items = build_timeline(
        events, detections,
        missing_steps=full.get("possible_missing_steps") or [],
        include_inferred=include_inferred,
    )
    inferred = sum(1 for i in items if i.get("inferred"))
    return {
        "chain_id": chain_id, "include_inferred": include_inferred, "items": items,
        "event_count": len(events), "inferred_count": inferred,
    }


@router.get("/{chain_id}/evidence", response_model=EvidenceBlock)
def chain_evidence(chain_id: str, db: Session = Depends(get_db)) -> dict:
    _load_chain(db, chain_id)
    return chain_service.get_chain_evidence(db, chain_id)


@router.get("/{chain_id}/process-tree", response_model=list[ProcessTreeNode])
def chain_process_tree(chain_id: str, db: Session = Depends(get_db)) -> list[dict]:
    _load_chain(db, chain_id)
    return build_process_tree(chain_service.get_chain_events(db, chain_id))


@router.get("/{chain_id}/network", response_model=NetworkViewOut)
def chain_network(chain_id: str, db: Session = Depends(get_db)) -> dict:
    _load_chain(db, chain_id)
    return build_network_view(chain_service.get_chain_events(db, chain_id))


@router.get("/{chain_id}/investigation", response_model=InvestigationOut)
def chain_investigation(
    chain_id: str,
    include_inferred: bool = False,
    db: Session = Depends(get_db),
) -> dict:
    full = _load_chain(db, chain_id)
    events = chain_service.get_chain_events(db, chain_id)
    detections = chain_service.get_chain_detections(db, chain_id)
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


def _feedback(db: Session, chain_id: str, status: str,
              body: Optional[FeedbackComment | FeedbackRequest]) -> dict:
    _load_chain(db, chain_id)
    comment = getattr(body, "comment", None)
    reason = getattr(body, "reason", None)
    analyst = getattr(body, "analyst", None)
    try:
        result = chain_service.apply_feedback(
            db, chain_id, status, comment=comment, reason=reason, analyst=analyst,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result


@router.post("/{chain_id}/feedback", response_model=ChainDetail)
def post_feedback(chain_id: str, body: FeedbackRequest, db: Session = Depends(get_db)) -> dict:
    return _feedback(db, chain_id, body.status, body)


@router.post("/{chain_id}/confirm", response_model=ChainDetail)
def confirm_chain(chain_id: str, body: Optional[FeedbackComment] = None,
                  db: Session = Depends(get_db)) -> dict:
    return _feedback(db, chain_id, "CONFIRMED", body)


@router.post("/{chain_id}/dismiss", response_model=ChainDetail)
def dismiss_chain(chain_id: str, body: Optional[FeedbackComment] = None,
                  db: Session = Depends(get_db)) -> dict:
    return _feedback(db, chain_id, "DISMISSED", body)
