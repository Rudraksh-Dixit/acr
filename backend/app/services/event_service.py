"""Event ingestion, entity persistence and detection persistence."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import Settings, settings as default_settings
from app.core.logging import get_logger, log_event
from app.detection import run_detection
from app.ingestion.entity_extractor import extract_entities, extract_relationships
from app.ingestion.normalizer import NormalizationIssue, normalize_records
from app.mitre import get_mapper, sync_techniques_to_db
from app.models import Detection, Entity, Event, EventEntity, Relationship

logger = get_logger("ingestion")


@dataclass
class IngestReport:
    received: int = 0
    stored: int = 0
    duplicates: int = 0
    skipped: int = 0
    detections: int = 0
    issues: list[dict[str, Any]] = field(default_factory=list)
    duration_seconds: float = 0.0
    source: str = "unknown"
    scenario_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "received": self.received,
            "stored": self.stored,
            "duplicates": self.duplicates,
            "skipped": self.skipped,
            "detections": self.detections,
            "issues": self.issues[:100],
            "issue_count": len(self.issues),
            "duration_seconds": round(self.duration_seconds, 4),
            "source": self.source,
            "scenario_id": self.scenario_id,
            "events_per_second": round(self.stored / self.duration_seconds, 1) if self.duration_seconds > 0 else None,
        }


def issue_to_dict(issue: NormalizationIssue, source: str = "unknown") -> dict[str, Any]:
    return {
        "index": issue.index,
        "scope": issue.scope,
        "field": issue.field,
        "message": issue.message,
        "source": source,
    }


def event_to_dict(event: Event) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "host": event.host,
        "user": event.user,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "source_port": event.source_port,
        "destination_port": event.destination_port,
        "protocol": event.protocol,
        "process_name": event.process_name,
        "process_id": event.process_id,
        "parent_process": event.parent_process,
        "parent_process_id": event.parent_process_id,
        "command_line": event.command_line,
        "file_path": event.file_path,
        "file_hash": event.file_hash,
        "domain": event.domain,
        "severity": event.severity,
        "technique_id": event.technique_id,
        "technique_name": event.technique_name,
        "tactic": event.tactic,
        "source": event.source,
        "metadata": event.metadata_json or {},
        "raw": event.raw,
        "scenario_id": event.scenario_id,
        "gt_id": event.gt_id,
        "ingested_at": event.ingested_at,
    }


def detection_to_dict(det: Detection) -> dict[str, Any]:
    return {
        "id": det.id,
        "rule_id": det.rule_id,
        "rule_name": det.rule_name,
        "event_id": det.event_id,
        "related_event_ids": det.related_event_ids or [],
        "severity": det.severity,
        "technique_id": det.technique_id,
        "technique_name": det.technique_name,
        "tactic": det.tactic,
        "title": det.title,
        "description": det.description,
        "evidence": det.evidence_json or [],
        "host": det.host,
        "scenario_id": det.scenario_id,
        "created_at": det.created_at,
    }


def load_all_events(session: Session) -> list[dict[str, Any]]:
    rows = session.scalars(select(Event).order_by(Event.timestamp.asc().nulls_last())).all()
    return [event_to_dict(row) for row in rows]


def _upsert_entities(session: Session, event_obj: Event, event: dict[str, Any],
                     cache: dict[tuple[str, str], int]) -> None:
    for ref in extract_entities(event):
        key = (ref.entity_type, ref.value)
        entity_id = cache.get(key)
        if entity_id is None:
            row = session.scalar(
                select(Entity).where(Entity.entity_type == ref.entity_type, Entity.value == ref.value)
            )
            if row is None:
                row = Entity(
                    entity_type=ref.entity_type,
                    value=ref.value,
                    first_seen=event.get("timestamp"),
                    last_seen=event.get("timestamp"),
                )
                session.add(row)
                session.flush()
            entity_id = row.id
            cache[key] = entity_id
        else:
            row = session.get(Entity, entity_id)
        if row is not None:
            ts = event.get("timestamp")
            if ts:
                if row.first_seen is None or ts < row.first_seen:
                    row.first_seen = ts
                if row.last_seen is None or ts > row.last_seen:
                    row.last_seen = ts
        session.add(EventEntity(event_id=event_obj.event_id, entity_id=entity_id, role=ref.role))

    host = event.get("host")
    for rel in extract_relationships(event):
        src_key = (rel.source_type, rel.source_value)
        dst_key = (rel.target_type, rel.target_value)
        src_id = cache.get(src_key)
        if src_id is None:
            row = session.scalar(select(Entity).where(Entity.entity_type == rel.source_type,
                                                      Entity.value == rel.source_value))
            if row is None:
                row = Entity(entity_type=rel.source_type, value=rel.source_value,
                             first_seen=event.get("timestamp"), last_seen=event.get("timestamp"))
                session.add(row)
                session.flush()
            src_id = row.id
            cache[src_key] = src_id
        dst_id = cache.get(dst_key)
        if dst_id is None:
            row = session.scalar(select(Entity).where(Entity.entity_type == rel.target_type,
                                                      Entity.value == rel.target_value))
            if row is None:
                row = Entity(entity_type=rel.target_type, value=rel.target_value,
                             first_seen=event.get("timestamp"), last_seen=event.get("timestamp"))
                session.add(row)
                session.flush()
            dst_id = row.id
            cache[dst_key] = dst_id
        session.add(Relationship(
            source_entity_id=src_id,
            target_entity_id=dst_id,
            relation_type=rel.relation_type,
            event_id=event_obj.event_id,
            host=host,
            timestamp=event.get("timestamp"),
        ))


def ingest_records(
    session: Session,
    records: Iterable[Any],
    source: str = "unknown",
    scenario_id: Optional[str] = None,
    settings: Settings | None = None,
    run_detection_pass: bool = True,
    replace_duplicates: bool = False,
) -> IngestReport:
    """Full ingestion pipeline: validate -> normalize -> persist -> enrich -> detect."""
    cfg = settings or default_settings
    started = time.perf_counter()
    report = IngestReport(source=source, scenario_id=scenario_id)

    record_list = list(records)
    report.received = len(record_list)
    if report.received > cfg.max_events_per_ingest:
        report.issues.append({
            "index": None, "scope": "record", "field": None,
            "message": f"batch exceeds {cfg.max_events_per_ingest} events; extra records ignored",
        })
        record_list = record_list[: cfg.max_events_per_ingest]
        report.received = len(record_list)

    mapper = get_mapper()
    sync_techniques_to_db(session)

    batch = normalize_records(record_list, source=source, scenario_id=scenario_id,
                              max_field_length=cfg.max_field_length)
    report.skipped = batch.skipped
    report.issues.extend(issue_to_dict(i, source) for i in batch.issues)

    entity_cache: dict[tuple[str, str], int] = {}
    for event in batch.events:
        event = mapper.annotate(event)
        if event.get("event_id") and session.get(Event, event["event_id"]) is not None:
            report.duplicates += 1
            if not replace_duplicates:
                continue
            session.delete(session.get(Event, event["event_id"]))
            session.flush()
        obj = Event(
            event_id=event["event_id"],
            timestamp=event["timestamp"],
            event_type=event["event_type"],
            host=event["host"],
            user=event["user"],
            source_ip=event["source_ip"],
            destination_ip=event["destination_ip"],
            source_port=event["source_port"],
            destination_port=event["destination_port"],
            protocol=event["protocol"],
            process_name=event["process_name"],
            process_id=event["process_id"],
            parent_process=event["parent_process"],
            parent_process_id=event["parent_process_id"],
            command_line=event["command_line"],
            file_path=event["file_path"],
            file_hash=event["file_hash"],
            domain=event["domain"],
            severity=event["severity"],
            technique_id=event["technique_id"],
            technique_name=event["technique_name"],
            tactic=event["tactic"],
            source=event["source"],
            metadata_json=event["metadata"],
            raw=event["raw"],
            scenario_id=event["scenario_id"],
            gt_id=event["gt_id"],
        )
        session.add(obj)
        session.flush()
        _upsert_entities(session, obj, event, entity_cache)
        report.stored += 1

    session.commit()
    if run_detection_pass and report.stored:
        report.detections = run_detection_pass_(session, cfg)
    report.duration_seconds = time.perf_counter() - started
    log_event(logger, "ingest_complete", **{k: v for k, v in report.to_dict().items()
                                             if k not in {"issues", "source"}})
    return report


def run_detection_pass_(session: Session, settings: Settings | None = None) -> int:
    """Re-run every rule over the full event store (deterministic rebuild).

    Detection results are also written back onto the events (technique id /
    name / tactic) so downstream correlation can use ATT&CK progression as a
    signal - this is the enrichment stage of the pipeline.
    """
    cfg = settings or default_settings
    events = load_all_events(session)
    matches = run_detection(events, cfg)
    session.execute(delete(Detection))
    session.flush()
    mapper = get_mapper()
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    best_by_event: dict[str, Detection] = {}
    for match in matches:
        tid = mapper.normalize_technique_id(match.technique_id)
        det = Detection(
            rule_id=match.rule_id,
            rule_name=match.rule_name,
            event_id=match.event.get("event_id"),
            related_event_ids=[e for e in match.related_event_ids if e and e != match.event.get("event_id")],
            severity=match.severity,
            technique_id=tid,
            technique_name=match.technique_name or mapper.name_for(tid),
            tactic=mapper.tactic_for(tid) or "",
            title=match.title,
            description=match.description,
            evidence_json=match.evidence,
            host=match.event.get("host"),
            scenario_id=match.event.get("scenario_id"),
        )
        session.add(det)
        session.flush()
        eid = match.event.get("event_id")
        if eid:
            current = best_by_event.get(eid)
            if current is None or severity_rank.get(det.severity, 0) > severity_rank.get(current.severity, 0):
                best_by_event[eid] = det

    updated = 0
    for eid, det in best_by_event.items():
        row = session.get(Event, eid)
        if row is None or row.technique_id:
            continue
        row.technique_id = det.technique_id
        row.technique_name = det.technique_name
        row.tactic = det.tactic
        updated += 1
    session.commit()
    log_event(logger, "detection_persisted", detections=len(matches), events_annotated=updated)
    return len(matches)


def query_events(
    session: Session,
    event_type: Optional[str] = None,
    host: Optional[str] = None,
    user: Optional[str] = None,
    chain_id: Optional[str] = None,
    scenario_id: Optional[str] = None,
    severity: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[Event], int]:
    from app.models import ChainEvent

    stmt = select(Event)
    if event_type:
        stmt = stmt.where(Event.event_type == event_type.upper())
    if host:
        stmt = stmt.where(Event.host == host.lower())
    if user:
        stmt = stmt.where(Event.user == user.lower())
    if scenario_id:
        stmt = stmt.where(Event.scenario_id == scenario_id)
    if severity:
        stmt = stmt.where(Event.severity == severity.upper())
    if start:
        stmt = stmt.where(Event.timestamp >= start)
    if end:
        stmt = stmt.where(Event.timestamp <= end)
    if chain_id:
        stmt = stmt.where(Event.event_id.in_(select(ChainEvent.event_id).where(ChainEvent.chain_id == chain_id)))
    if search:
        pattern = f"%{search.lower()}%"
        stmt = stmt.where(
            (Event.command_line.ilike(pattern))
            | (Event.file_path.ilike(pattern))
            | (Event.process_name.ilike(pattern))
            | (Event.domain.ilike(pattern))
            | (Event.user.ilike(pattern))
            | (Event.host.ilike(pattern))
        )
    from sqlalchemy import func

    count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
    total = int(session.scalar(count_stmt) or 0)
    rows = session.scalars(
        stmt.order_by(Event.timestamp.asc().nulls_last()).limit(limit).offset(offset)
    ).all()
    return rows, total
