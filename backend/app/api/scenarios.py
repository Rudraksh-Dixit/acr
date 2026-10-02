"""Scenario endpoints: catalog, generation (ingest + reconstruct), demo reset."""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.api import state
from app.core.database import get_db
from app.models import (
    AnalystFeedback,
    AttackChain,
    ChainEvent,
    Detection,
    Entity,
    Event,
    EventEntity,
    Evidence,
    Relationship,
)
from app.schemas.events import IngestIssue
from app.schemas.scenarios import (
    ScenarioCatalogOut,
    ScenarioGenerateOut,
    ScenarioGenerateRequest,
    ScenarioResetOut,
    ScenarioResetRequest,
)
from app.scenarios import generate_scenario, scenario_catalog
from app.services.chain_service import _clear_chains, reconstruct
from app.services.event_service import ingest_records, run_detection_pass_

router = APIRouter(prefix="/api/scenarios", tags=["scenarios"])


def _remove_scenario_events(db: Session, scenario_ids: list[str]) -> int:
    """Delete previous copies of the given scenarios (idempotent regeneration)."""
    event_ids = list(db.scalars(select(Event.event_id).where(Event.scenario_id.in_(scenario_ids))))
    if not event_ids:
        return 0
    db.execute(delete(ChainEvent).where(ChainEvent.event_id.in_(event_ids)))
    db.execute(delete(EventEntity).where(EventEntity.event_id.in_(event_ids)))
    db.execute(delete(Relationship).where(Relationship.event_id.in_(event_ids)))
    db.execute(delete(Detection).where(Detection.event_id.in_(event_ids)))
    db.execute(delete(Event).where(Event.event_id.in_(event_ids)))
    db.flush()
    return len(event_ids)


@router.get("", response_model=ScenarioCatalogOut)
def catalog() -> ScenarioCatalogOut:
    items = scenario_catalog()
    return {"items": items, "total": len(items)}


@router.post("/generate", response_model=ScenarioGenerateOut)
def generate(body: ScenarioGenerateRequest, db: Session = Depends(get_db)) -> dict:
    known = {s["scenario_id"] for s in scenario_catalog()}
    ids = body.scenario_ids or sorted(known)
    unknown = [i for i in ids if i not in known]
    if unknown:
        raise HTTPException(status_code=400, detail=f"unknown scenario ids: {', '.join(unknown)}")
    if not ids:
        raise HTTPException(status_code=400, detail="no scenarios to generate")

    started = time.perf_counter()
    results: list[dict] = []
    total_stored = 0
    replaced = 0

    if body.ingest:
        # chains are derived data: clear them now, rebuild at the end if requested
        _clear_chains(db)
        replaced = _remove_scenario_events(db, ids)

    for scenario_id in ids:
        scenario = generate_scenario(scenario_id, seed=body.seed)
        if not body.ingest:
            results.append({
                "scenario_id": scenario_id, "name": scenario.name,
                "is_benign": scenario.is_benign, "events_emitted": len(scenario.events),
                "events_received": 0, "events_stored": 0, "detections": 0,
                "chains": 0, "attack_chains": 0, "chain_ids": [],
                "ground_truth": scenario.ground_truth if body.include_ground_truth else None,
            })
            continue
        report = ingest_records(
            db, scenario.events, source="scenario", scenario_id=scenario_id,
            run_detection_pass=False, replace_duplicates=body.replace_duplicates,
        )
        total_stored += report.stored
        results.append({
            "scenario_id": scenario_id, "name": scenario.name,
            "is_benign": scenario.is_benign, "events_emitted": len(scenario.events),
            "events_received": report.received, "events_stored": report.stored,
            "duplicates": report.duplicates, "skipped": report.skipped,
            "issues": [IngestIssue(**i) for i in report.issues[:50]],
            "ground_truth": scenario.ground_truth if body.include_ground_truth else None,
        })

    detections = run_detection_pass_(db) if body.ingest else 0
    reconstruction = None
    if body.ingest and body.reconstruct:
        reconstruction = reconstruct(db).to_dict()
        state.record_reconstruction(reconstruction)

    chain_counts: dict[str, int] = {}
    attack_counts: dict[str, int] = {}
    chain_ids_by_scenario: dict[str, list[str]] = {}
    if body.ingest:
        for row in db.execute(
            select(AttackChain.scenario_id, AttackChain.chain_id, AttackChain.is_attack)
        ).all():
            sid, cid, is_attack = row
            key = sid or "unknown"
            chain_counts[key] = chain_counts.get(key, 0) + 1
            chain_ids_by_scenario.setdefault(key, []).append(cid)
            if is_attack:
                attack_counts[key] = attack_counts.get(key, 0) + 1
        det_counts: dict[str, int] = {}
        for sid, n in db.execute(
            select(Detection.scenario_id, func.count()).group_by(Detection.scenario_id)
        ).all():
            det_counts[sid or "unknown"] = n
    else:
        det_counts = {}

    for item in results:
        sid = item["scenario_id"]
        item["detections"] = det_counts.get(sid, 0)
        item["chains"] = chain_counts.get(sid, 0)
        item["attack_chains"] = attack_counts.get(sid, 0)
        item["chain_ids"] = chain_ids_by_scenario.get(sid, [])

    duration = round(time.perf_counter() - started, 4)
    if body.ingest:
        state.record_ingest({
            "received": sum(i["events_received"] for i in results),
            "stored": total_stored,
            "replaced": replaced,
            "detections": detections,
            "source": "scenario",
            "duration_seconds": duration,
            "scenario_ids": ids,
        })

    return {
        "scenarios": results,
        "events_stored": total_stored,
        "events_replaced": replaced,
        "detections": detections,
        "chains": (reconstruction or {}).get("chains", sum(chain_counts.values())),
        "attack_chains": (reconstruction or {}).get("attacks", sum(attack_counts.values())),
        "reconstruction": reconstruction,
        "duration_seconds": duration,
    }


@router.post("/reset", response_model=ScenarioResetOut)
def reset(body: ScenarioResetRequest, db: Session = Depends(get_db)) -> dict:
    if not body.confirm:
        raise HTTPException(status_code=400, detail="set 'confirm': true to clear demo data")
    cleared = {
        "events": db.scalar(select(func.count()).select_from(Event)) or 0,
        "detections": db.scalar(select(func.count()).select_from(Detection)) or 0,
        "chains": db.scalar(select(func.count()).select_from(AttackChain)) or 0,
        "chain_events": db.scalar(select(func.count()).select_from(ChainEvent)) or 0,
        "evidence": db.scalar(select(func.count()).select_from(Evidence)) or 0,
        "entities": db.scalar(select(func.count()).select_from(Entity)) or 0,
        "relationships": db.scalar(select(func.count()).select_from(Relationship)) or 0,
        "feedback": db.scalar(select(func.count()).select_from(AnalystFeedback)) or 0,
    }
    for model in (ChainEvent, Evidence, AnalystFeedback, AttackChain, Detection,
                  EventEntity, Relationship, Entity, Event):
        db.execute(delete(model))
    db.commit()

    reconstruction = None
    remaining = {"events": 0, "detections": 0, "chains": 0}
    if body.reconstruct:
        reconstruction = reconstruct(db).to_dict()
        state.record_reconstruction(reconstruction)
        remaining = {
            "events": db.scalar(select(func.count()).select_from(Event)) or 0,
            "detections": db.scalar(select(func.count()).select_from(Detection)) or 0,
            "chains": db.scalar(select(func.count()).select_from(AttackChain)) or 0,
        }
    return {"cleared": cleared, "remaining": remaining, "reconstruction": reconstruction}
