"""Dataset catalog + dataset run services.

A dataset run: load via adapter -> (optionally) ingest into the event store ->
detect -> reconstruct -> evaluate. Evaluation is only computed when the dataset
carries ground truth; otherwise the run records the honest note
"no ground truth, precision/recall not computed".
"""
from __future__ import annotations

import time
from typing import Any, Optional

from sqlalchemy import func, or_, select
from sqlalchemy import delete as sa_delete
from sqlalchemy.orm import Session

from app.core.config import Settings, settings as default_settings
from app.datasets import DatasetError, availability, load_dataset, read_catalog, resolve_path
from app.models import (
    AttackChain,
    ChainEvent,
    DatasetRun,
    Detection,
    Event,
    EventEntity,
    Relationship,
)
from app.schemas.events import IngestIssue
from app.services.chain_service import _clear_chains, reconstruct
from app.services.event_service import ingest_records, run_detection_pass_
from app.services.evaluation_service import run_evaluation

NO_GROUND_TRUTH_NOTE = "no ground truth, precision/recall not computed"


def catalog_items() -> list[dict[str, Any]]:
    """Every catalog entry joined with its live availability."""
    items: list[dict[str, Any]] = []
    for entry in read_catalog().get("datasets", []):
        avail = availability(entry)
        origin = entry.get("origin") or {}
        items.append({
            "id": entry["id"],
            "name": entry.get("name", entry["id"]),
            "kind": entry.get("kind", "real"),
            "label": entry.get("label", ""),
            "source_name": entry.get("source_name", ""),
            "adapter": entry.get("adapter", ""),
            "ground_truth": bool(entry.get("ground_truth")),
            "description": entry.get("description", ""),
            "available": bool(avail["available"]),
            "path": avail["path"],
            "fetch_hint": avail["fetch_hint"],
            "origin_url": origin.get("url"),
            "rows": origin.get("rows") if isinstance(origin.get("rows"), int) else None,
        })
    return items


def _remove_dataset_events(db: Session, dataset_id: str, scenario_ids: list[str]) -> int:
    """Delete previous copies of this dataset (idempotent re-runs).

    Synthetic events are keyed by scenario_id (also covers copies created via
    /api/scenarios/generate); every dataset run also stamps metadata.dataset_id.
    """
    conditions = [Event.metadata_json["dataset_id"].as_string() == dataset_id]
    if scenario_ids:
        conditions.append(Event.scenario_id.in_(scenario_ids))
    event_ids = list(db.scalars(select(Event.event_id).where(or_(*conditions))))
    if not event_ids:
        return 0
    db.execute(sa_delete(ChainEvent).where(ChainEvent.event_id.in_(event_ids)))
    db.execute(sa_delete(EventEntity).where(EventEntity.event_id.in_(event_ids)))
    db.execute(sa_delete(Relationship).where(Relationship.event_id.in_(event_ids)))
    db.execute(sa_delete(Detection).where(Detection.event_id.in_(event_ids)))
    db.execute(sa_delete(Event).where(Event.event_id.in_(event_ids)))
    db.flush()
    return len(event_ids)


def run_dataset(
    db: Session,
    entry: dict[str, Any],
    *,
    seed: int = 42,
    ingest: bool = True,
    reconstruct_chains: bool = True,
    replace_existing: bool = True,
    settings: Optional[Settings] = None,
) -> dict[str, Any]:
    cfg = settings or default_settings
    started = time.perf_counter()
    from app.api import state  # deferred: avoids app.api <-> service import cycle

    result = load_dataset(entry, seed=seed)  # raises DatasetError on missing file/bad catalog
    dataset_id = str(entry["id"])
    scenario_ids = [str(s) for s in (entry.get("scenario_ids") or [])]
    adapter_block = {
        "adapter": str(result.meta.get("adapter") or entry.get("adapter") or ""),
        "rows_read": int(result.meta.get("rows_read") or len(result.records)),
        "issues": [IngestIssue(**i) for i in result.issues[:50]],
    }

    ingest_block: dict[str, Any] = {
        "events_received": len(result.records),
        "events_stored": 0, "events_replaced": 0, "events_skipped": 0,
        "duplicates": 0, "ingest_issues": [],
    }
    detections = chains = attack_chains = 0
    reconstruction: Optional[dict[str, Any]] = None

    if ingest:
        replaced = 0
        if replace_existing:
            _clear_chains(db)  # chains are derived data; rebuilt below
            replaced = _remove_dataset_events(db, dataset_id, scenario_ids)

        stored = skipped = duplicates = 0
        issues: list[dict[str, Any]] = []
        received = len(result.records)
        if scenario_ids:
            # synthetic batches mix scenarios; ingest one scenario_id at a time
            # so each event keeps its scenario linkage (events.scenario_id)
            groups: dict[str, list[dict[str, Any]]] = {}
            for record in result.records:
                sid = str(record.get("scenario_id") or "")
                groups.setdefault(sid, []).append(record)
            ordered = [(sid, groups.pop(sid)) for sid in scenario_ids if sid in groups]
            ordered.extend(sorted(groups.items()))
            for _sid, records in ordered:
                report = ingest_records(
                    db, records, source=dataset_id, scenario_id=_sid or None,
                    run_detection_pass=False, replace_duplicates=True,
                )
                stored += report.stored
                skipped += report.skipped
                duplicates += report.duplicates
                issues.extend(report.issues)
        else:
            report = ingest_records(
                db, result.records, source=dataset_id,
                run_detection_pass=False, replace_duplicates=replace_existing,
            )
            stored = report.stored
            skipped = report.skipped
            duplicates = report.duplicates
            issues = report.issues

        detections = run_detection_pass_(db, cfg)
        if reconstruct_chains:
            reconstruction = reconstruct(db, cfg).to_dict()
            state.record_reconstruction(reconstruction)

        chains = int(db.scalar(select(func.count()).select_from(AttackChain)) or 0)
        attack_chains = int(db.scalar(
            select(func.count()).select_from(AttackChain).where(AttackChain.is_attack.is_(True))
        ) or 0)

        ingest_block = {
            "events_received": received,
            "events_stored": stored,
            "events_replaced": replaced,
            "events_skipped": skipped,
            "duplicates": duplicates,
            "ingest_issues": [IngestIssue(**i) for i in issues[:50]],
        }

    # ---- evaluation: metrics only when ground truth exists -----------------
    evaluation: dict[str, Any]
    if entry.get("ground_truth") and scenario_ids:
        eval_payload = run_evaluation(
            scenario_ids=scenario_ids, settings=cfg, seed=seed,
            session=None, persist=False,
        )
        evaluation = {
            "ground_truth": True,
            "note": None,
            "metrics": eval_payload["metrics"],
            "per_scenario": eval_payload["per_scenario"],
        }
    else:
        evaluation = {
            "ground_truth": False,
            "note": NO_GROUND_TRUTH_NOTE,
            "metrics": None,
            "per_scenario": None,
        }

    duration = round(time.perf_counter() - started, 4)
    counts = {
        "rows_read": adapter_block["rows_read"],
        "adapter_issues": len(result.issues),
        "events_received": ingest_block["events_received"],
        "events_stored": ingest_block["events_stored"],
        "events_replaced": ingest_block["events_replaced"],
        "events_skipped": ingest_block["events_skipped"],
        "duplicates": ingest_block["duplicates"],
        "detections": detections,
        "chains": chains,
        "attack_chains": attack_chains,
    }

    run_id: Optional[int] = None
    if ingest:
        row = DatasetRun(
            dataset_id=dataset_id,
            label=str(entry.get("label", "")),
            kind=str(entry.get("kind", "real")),
            ground_truth=bool(entry.get("ground_truth")),
            seed=seed,
            config={
                "seed": seed, "ingest": ingest, "reconstruct": reconstruct_chains,
                "replace_existing": replace_existing, "adapter": adapter_block["adapter"],
                "source_name": entry.get("source_name", ""),
            },
            counts=counts,
            evaluation=evaluation,
            events_processed=ingest_block["events_received"],
            duration_seconds=duration,
        )
        db.add(row)
        db.commit()
        run_id = row.id
        state.record_ingest({
            "received": ingest_block["events_received"],
            "stored": ingest_block["events_stored"],
            "replaced": ingest_block["events_replaced"],
            "detections": detections,
            "source": dataset_id,
            "dataset_label": entry.get("label", ""),
            "duration_seconds": duration,
        })

    avail = availability(entry)
    origin = entry.get("origin") or {}
    return {
        "run_id": run_id,
        "dataset": {
            "id": entry["id"], "name": entry.get("name", entry["id"]),
            "kind": entry.get("kind", "real"), "label": entry.get("label", ""),
            "source_name": entry.get("source_name", ""), "adapter": entry.get("adapter", ""),
            "ground_truth": bool(entry.get("ground_truth")),
            "description": entry.get("description", ""),
            "available": bool(avail["available"]), "path": avail["path"],
            "fetch_hint": avail["fetch_hint"], "origin_url": origin.get("url"),
            "rows": origin.get("rows") if isinstance(origin.get("rows"), int) else None,
        },
        "adapter": adapter_block,
        **ingest_block,
        "detections": detections,
        "chains": chains,
        "attack_chains": attack_chains,
        "reconstruction": reconstruction,
        "evaluation": evaluation,
        "duration_seconds": duration,
    }


def list_dataset_runs(session: Session, limit: int = 20, offset: int = 0) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(DatasetRun).order_by(DatasetRun.created_at.desc(), DatasetRun.id.desc())
        .limit(limit).offset(offset)
    ).all()
    return [
        {
            "id": r.id,
            "created_at": r.created_at.isoformat() + "Z",
            "dataset_id": r.dataset_id,
            "label": r.label,
            "kind": r.kind,
            "ground_truth": r.ground_truth,
            "seed": r.seed,
            "counts": r.counts,
            "evaluation": r.evaluation,
            "events_processed": r.events_processed,
            "duration_seconds": r.duration_seconds,
        }
        for r in rows
    ]


def count_dataset_runs(session: Session) -> int:
    return int(session.scalar(select(func.count()).select_from(DatasetRun)) or 0)


def get_dataset_run(session: Session, run_id: int) -> Optional[dict[str, Any]]:
    row = session.get(DatasetRun, run_id)
    if row is None:
        return None
    return {
        "id": row.id,
        "created_at": row.created_at.isoformat() + "Z",
        "dataset_id": row.dataset_id,
        "label": row.label,
        "kind": row.kind,
        "ground_truth": row.ground_truth,
        "seed": row.seed,
        "counts": row.counts,
        "evaluation": row.evaluation,
        "events_processed": row.events_processed,
        "duration_seconds": row.duration_seconds,
        "config": row.config,
        "notes": row.notes,
    }


def require_dataset(dataset_id: str) -> dict[str, Any]:
    """Catalog lookup with a structured DatasetError when unknown."""
    for entry in read_catalog().get("datasets", []):
        if entry.get("id") == dataset_id:
            return entry
    known = ", ".join(d.get("id", "?") for d in read_catalog().get("datasets", []))
    raise DatasetError(
        f"unknown dataset '{dataset_id}'",
        hint=f"known datasets: {known}",
    )


def dataset_path(entry: dict[str, Any]) -> Optional[str]:
    path = resolve_path(entry)
    return str(path) if path else None
