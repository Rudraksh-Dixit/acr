"""Health and service metadata."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/health")
def health(db: Session = Depends(get_db)) -> dict:
    database = settings.database_url.split("://", 1)[0]
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:  # pragma: no cover - defensive
        db_ok = False
    return {
        "status": "ok" if db_ok else "degraded",
        "app": settings.app_name,
        "version": settings.version,
        "database": database,
        "database_ok": db_ok,
        "time": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/config")
def config_dump() -> dict:
    """Effective runtime configuration (weights, windows, thresholds)."""
    return {
        "app_name": settings.app_name,
        "version": settings.version,
        "time_windows": settings.time_windows(),
        "weights": settings.weights,
        "min_edge_score": settings.min_edge_score,
        "min_chain_confidence": settings.min_chain_confidence,
        "attack_confidence_threshold": settings.attack_confidence_threshold,
        "attack_risk_threshold": settings.attack_risk_threshold,
        "brute_force_failures": settings.brute_force_failures,
        "brute_force_window": settings.brute_force_window,
        "max_upload_bytes": settings.max_upload_bytes,
        "max_events_per_ingest": settings.max_events_per_ingest,
        "engine": "rule_based",
        "confidence_engine": "additive_rule_based",
        "risk_engine": "additive_rule_based",
        "summary_provider": "rule_based",
    }
