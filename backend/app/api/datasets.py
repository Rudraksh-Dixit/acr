"""Dataset endpoints: catalog, run execution, run history."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.datasets import DatasetError, DatasetMissingError
from app.schemas.datasets import (
    DatasetCatalogOut,
    DatasetRunDetail,
    DatasetRunListOut,
    DatasetRunOut,
    DatasetRunRequest,
)
from app.services.dataset_service import (
    catalog_items,
    count_dataset_runs,
    get_dataset_run,
    list_dataset_runs,
    require_dataset,
    run_dataset,
)

router = APIRouter(prefix="/api/datasets", tags=["datasets"])


def _entry_or_404(dataset_id: str) -> dict:
    try:
        return require_dataset(dataset_id)
    except DatasetError as exc:
        raise HTTPException(status_code=404, detail=f"{exc.message}; {exc.hint}") from exc


@router.get("", response_model=DatasetCatalogOut)
def dataset_catalog() -> dict:
    items = catalog_items()
    return {"items": items, "total": len(items)}


@router.post("/{dataset_id}/run", response_model=DatasetRunOut)
def dataset_run(
    dataset_id: str,
    body: Optional[DatasetRunRequest] = None,
    db: Session = Depends(get_db),
) -> dict:
    entry = _entry_or_404(dataset_id)
    req = body or DatasetRunRequest()
    try:
        return run_dataset(
            db, entry, seed=req.seed, ingest=req.ingest,
            reconstruct_chains=req.reconstruct, replace_existing=req.replace_existing,
        )
    except DatasetMissingError as exc:
        raise HTTPException(
            status_code=409, detail=f"{exc.message}; {exc.hint}"
        ) from exc
    except DatasetError as exc:
        raise HTTPException(status_code=400, detail=f"{exc.message}; {exc.hint}") from exc


@router.get("/runs", response_model=DatasetRunListOut)
def dataset_runs(
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
    total = count_dataset_runs(db)
    items = list_dataset_runs(db, limit=limit, offset=offset)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/runs/{run_id}", response_model=DatasetRunDetail)
def dataset_run_detail(run_id: int, db: Session = Depends(get_db)) -> dict:
    payload = get_dataset_run(db, run_id)
    if payload is None:
        raise HTTPException(status_code=404, detail=f"dataset run '{run_id}' not found")
    return payload
