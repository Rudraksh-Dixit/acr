"""Evaluation endpoints: run stage comparisons, list persisted runs."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api import state
from app.core.database import get_db
from app.models import EvaluationRun
from app.schemas.evaluation import (
    EvaluationOut,
    EvaluationRunDetail,
    EvaluationRunListOut,
    EvaluationRunRequest,
    StageComparisonOut,
)
from app.services.evaluation_service import get_run, list_runs, run_evaluation

router = APIRouter(prefix="/api/evaluation", tags=["evaluation"])


@router.post("/run", response_model=EvaluationOut)
def evaluation_run(body: EvaluationRunRequest, db: Session = Depends(get_db)) -> dict:
    payload = run_evaluation(
        scenario_ids=body.scenario_ids, seed=body.seed,
        session=db if body.persist else None, persist=body.persist,
    )
    if payload.get("run_id") is not None:
        state.record_evaluation_run(payload["run_id"])
    return payload


@router.get("/runs", response_model=EvaluationRunListOut)
def evaluation_runs(
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
    total = int(db.scalar(select(func.count()).select_from(EvaluationRun)) or 0)
    rows = list_runs(db, limit=limit)
    if offset:
        rows = rows[offset:offset + limit]
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


@router.get("/runs/{run_id}", response_model=EvaluationRunDetail)
def evaluation_run_detail(run_id: int, db: Session = Depends(get_db)) -> dict:
    row = get_run(db, run_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"evaluation run '{run_id}' not found")
    return row


@router.get("/stages", response_model=StageComparisonOut)
def stage_comparison(
    run_id: Optional[int] = Query(default=None, description="Run to compare; latest when omitted"),
    db: Session = Depends(get_db),
) -> dict:
    """raw detection vs correlation vs reconstruction, side by side."""
    if run_id is None:
        row = db.scalars(select(EvaluationRun).order_by(EvaluationRun.created_at.desc())).first()
        if row is None:
            raise HTTPException(status_code=404, detail="no evaluation runs yet; POST /api/evaluation/run first")
        payload = get_run(db, row.id)
    else:
        payload = get_run(db, run_id)
    if payload is None:
        raise HTTPException(status_code=404, detail=f"evaluation run '{run_id}' not found")

    metrics = payload["metrics"]

    def _delta(stage: str, key: str = "f1") -> Optional[float]:
        base = (metrics.get("technique_level", {}).get("raw_detection", {}) or {}).get(key)
        cur = (metrics.get("technique_level", {}).get(stage, {}) or {}).get(key)
        if base is None or cur is None:
            return None
        return round(cur - base, 4)

    return {
        "technique_level": metrics.get("technique_level", {}),
        "event_level": metrics.get("event_level", {}),
        "attack_detection": metrics.get("attack_detection", {}),
        "delta": {
            "technique_f1_correlation_vs_raw": _delta("correlation"),
            "technique_f1_reconstruction_vs_raw": _delta("reconstruction"),
            "chain_accuracy": (metrics.get("reconstruction") or {}).get("chain_accuracy"),
            "mean_detection_latency_seconds": (metrics.get("detection_latency_seconds") or {}).get("mean"),
            "events_per_second": (metrics.get("performance") or {}).get("events_per_second"),
        },
    }
