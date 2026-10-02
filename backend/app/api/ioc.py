"""IOC import endpoint: indicators in, matched detections out."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.ioc import parse_ioc_payload, parse_json_indicators
from app.schemas.ioc import IocImportOut, IocImportRequest
from app.services.ioc_service import import_indicators

router = APIRouter(prefix="/api/ioc", tags=["ioc"])


@router.post("/import", response_model=IocImportOut)
def import_iocs(body: IocImportRequest, db: Session = Depends(get_db)) -> dict:
    """Import a CSV / STIX / JSON indicator list and match it against events.

    Unmappable rows are reported as structured issues instead of failing the
    import. Re-importing identical (indicator, source) pairs is idempotent.
    """
    if not body.content and not body.indicators:
        raise HTTPException(status_code=400, detail="provide 'content' or 'indicators'")

    if body.indicators is not None:
        items = [i.model_dump(exclude_none=True) for i in body.indicators]
        parsed = parse_json_indicators(items, source=body.source)
        for issue in parsed.issues:
            issue["source"] = body.source
        meta = {"format": "inline", "received": len(items), "issues": parsed.issues}
        indicators = parsed.indicators
    else:
        raw = body.content or ""
        parsed = parse_ioc_payload(
            raw, fmt=body.format, filename=body.filename, default_source=body.source
        )
        meta = {
            "format": parsed.format,
            "received": len(parsed.indicators),
            "issues": parsed.issues,
        }
        indicators = parsed.indicators

    if not indicators and not parsed.issues:
        raise HTTPException(status_code=400, detail="no usable indicators found in payload")

    return import_indicators(db, indicators, meta, body.source)
