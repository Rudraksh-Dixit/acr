"""Event endpoints: query, detail, ingest (JSON body or file upload)."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api import state
from app.core.config import settings as cfg
from app.core.database import get_db
from app.ingestion.csv_loader import parse_csv_text
from app.ingestion.json_loader import LoaderError, parse_json_text
from app.models import ChainEvent, Detection, Entity, Event, EventEntity
from app.schemas.events import (
    EventDetailOut,
    EventListOut,
    IngestReportOut,
    IngestRequest,
)
from app.services.chain_service import reconstruct
from app.services.event_service import (
    detection_to_dict,
    event_to_dict,
    ingest_records,
    query_events,
)

router = APIRouter(prefix="/api/events", tags=["events"])


def _chain_map(db: Session, event_ids: list[str]) -> dict[str, str]:
    if not event_ids:
        return {}
    rows = db.execute(select(ChainEvent.chain_id, ChainEvent.event_id).where(ChainEvent.event_id.in_(event_ids))).all()
    return {event_id: chain_id for chain_id, event_id in rows}


@router.get("", response_model=EventListOut)
def list_events(
    event_type: Optional[str] = Query(default=None, description="Canonical event type, e.g. PROCESS_CREATED"),
    host: Optional[str] = None,
    user: Optional[str] = None,
    chain_id: Optional[str] = None,
    scenario_id: Optional[str] = None,
    severity: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    search: Optional[str] = Query(default=None, description="Substring match on command line/file/domain/user/host"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> EventListOut:
    rows, total = query_events(
        db, event_type=event_type, host=host, user=user, chain_id=chain_id,
        scenario_id=scenario_id, severity=severity, start=start, end=end,
        search=search, limit=limit, offset=offset,
    )
    items: list[dict] = []
    chain_map = _chain_map(db, [r.event_id for r in rows])
    for row in rows:
        item = event_to_dict(row)
        item.pop("raw", None)
        item["chain_id"] = chain_map.get(row.event_id)
        items.append(item)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/{event_id}", response_model=EventDetailOut)
def get_event(event_id: str, db: Session = Depends(get_db)) -> EventDetailOut:
    row = db.get(Event, event_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"event '{event_id}' not found")
    item = event_to_dict(row)
    chain_map = _chain_map(db, [event_id])
    item["chain_id"] = chain_map.get(event_id)
    detections = [detection_to_dict(d) for d in db.scalars(select(Detection).where(Detection.event_id == event_id)).all()]
    entity_rows = db.execute(
        select(Entity, EventEntity.role)
        .join(EventEntity, EventEntity.entity_id == Entity.id)
        .where(EventEntity.event_id == event_id)
    ).all()
    item["detections"] = detections
    item["entities"] = [
        {"entity_type": e.entity_type, "value": e.value, "role": role} for e, role in entity_rows
    ]
    return item


@router.post("", response_model=IngestReportOut)
@router.post("/ingest", response_model=IngestReportOut, include_in_schema=False)
def ingest_events(body: IngestRequest, db: Session = Depends(get_db)) -> dict:
    if not body.events:
        raise HTTPException(status_code=400, detail="'events' must contain at least one record")
    report = ingest_records(
        db, body.events, source=body.source, scenario_id=body.scenario_id,
        run_detection_pass=True, replace_duplicates=body.replace_duplicates,
    )
    payload = report.to_dict()
    if body.reconstruct:
        payload["reconstruction"] = reconstruct(db, scenario_id=body.scenario_id).to_dict()
        state.record_reconstruction(payload["reconstruction"])
    state.record_ingest(payload)
    return payload


@router.post("/upload", response_model=IngestReportOut)
async def ingest_upload(
    file: UploadFile = File(..., description="JSON or CSV telemetry file"),
    source: str = Query(default="upload", max_length=64),
    scenario_id: Optional[str] = Query(default=None, max_length=64),
    reconstruct_after: bool = Query(default=False, alias="reconstruct"),
    replace_duplicates: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> dict:
    content = await file.read()
    if len(content) > cfg.max_upload_bytes:
        raise HTTPException(status_code=413, detail=f"file exceeds {cfg.max_upload_bytes} bytes")
    name = (file.filename or "").lower()
    text = content.decode("utf-8-sig", errors="replace")
    try:
        if name.endswith(".csv") or (not name.endswith(".json") and "," in text.splitlines()[0]):
            records = parse_csv_text(text)
        else:
            records = parse_json_text(text)
    except LoaderError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    report = ingest_records(
        db, records, source=source, scenario_id=scenario_id,
        run_detection_pass=True, replace_duplicates=replace_duplicates,
    )
    payload = report.to_dict()
    if reconstruct_after:
        payload["reconstruction"] = reconstruct(db, scenario_id=scenario_id).to_dict()
        state.record_reconstruction(payload["reconstruction"])
    state.record_ingest(payload)
    return payload
