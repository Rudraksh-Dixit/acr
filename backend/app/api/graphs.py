"""Attack-graph endpoints (NetworkX-derived node/edge payloads)."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Detection, Event
from app.reconstruction.graph_builder import build_attack_graph
from app.schemas.chains import GraphOut
from app.services.chain_service import get_chain_detections, get_chain_events, get_chain_full

router = APIRouter(prefix="/api", tags=["graphs"])


def _chain_graph(db: Session, chain_id: str) -> dict:
    if get_chain_full(db, chain_id) is None:
        raise HTTPException(status_code=404, detail=f"chain '{chain_id}' not found")
    events = get_chain_events(db, chain_id)
    detections = get_chain_detections(db, chain_id)
    graph = build_attack_graph(events, detections, {"chain_id": chain_id})
    graph["chain_id"] = chain_id
    return graph


@router.get("/chains/{chain_id}/graph", response_model=GraphOut)
def chain_graph(chain_id: str, db: Session = Depends(get_db)) -> dict:
    return _chain_graph(db, chain_id)


@router.get("/graphs/{chain_id}", response_model=GraphOut, include_in_schema=False)
def graph_alias(chain_id: str, db: Session = Depends(get_db)) -> dict:
    return _chain_graph(db, chain_id)


@router.get("/graphs", response_model=GraphOut)
def global_graph(
    scenario_id: Optional[str] = None,
    limit: int = Query(default=2000, ge=1, le=20000),
    db: Session = Depends(get_db),
) -> dict:
    """Whole-store attack graph (optionally scoped to one scenario)."""
    from sqlalchemy import select

    stmt = select(Event).order_by(Event.timestamp.asc().nulls_last()).limit(limit)
    if scenario_id:
        stmt = stmt.where(Event.scenario_id == scenario_id)
    events = list(db.scalars(stmt).all())
    if not events:
        return {
            "chain_id": None,
            "nodes": [], "edges": [], "relationships": [],
            "metadata": {"node_count": 0, "edge_count": 0, "node_type_counts": {}, "relation_counts": {}},
        }
    from app.services.event_service import event_to_dict, detection_to_dict

    event_dicts = [event_to_dict(e) for e in events]
    ids = [e["event_id"] for e in event_dicts]
    detections = [detection_to_dict(d) for d in db.scalars(select(Detection).where(Detection.event_id.in_(ids))).all()]
    graph = build_attack_graph(event_dicts, detections, {"scope": scenario_id or "global"})
    graph["chain_id"] = None
    return graph
