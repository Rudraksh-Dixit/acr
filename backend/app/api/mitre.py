"""MITRE ATT&CK endpoints: techniques, tactics, coverage."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.killchain import stage_for_tactic
from app.mitre import get_mapper
from app.models import AttackChain, Technique
from app.schemas.mitre import (
    CoverageOut,
    CoverageTactic,
    CoverageTechnique,
    TacticListOut,
    TechniqueListOut,
    TechniqueOut,
)

router = APIRouter(prefix="/api/mitre", tags=["mitre"])


@router.get("/tactics", response_model=TacticListOut)
def list_tactics(db: Session = Depends(get_db)) -> dict:
    mapper = get_mapper()
    rows = db.scalars(select(Technique)).all()
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.tactic] = counts.get(row.tactic, 0) + 1
    items = [{"name": t, "techniques": counts.get(t, 0)} for t in mapper.tactics]
    return {"items": items, "total": len(items)}


@router.get("/techniques", response_model=TechniqueListOut)
def list_techniques(
    tactic: Optional[str] = Query(default=None, description="Filter by tactic name"),
    include_subtechniques: bool = Query(default=True),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(Technique)
    if not include_subtechniques:
        stmt = stmt.where(Technique.is_subtechnique.is_(False))
    rows = list(db.scalars(stmt.order_by(Technique.technique_id)).all())
    if tactic:
        needle = tactic.upper()
        rows = [r for r in rows if r.tactic.upper() == needle]
    items = [
        {
            "technique_id": r.technique_id, "name": r.name, "tactic": r.tactic,
            "description": r.description, "subtechnique_of": r.subtechnique_of,
            "detection_hint": r.detection_hint, "is_subtechnique": bool(r.is_subtechnique),
            "kill_chain_stage": stage_for_tactic(r.tactic),
        }
        for r in rows
    ]
    return {"items": items, "total": len(items), "tactic": tactic}


@router.get("/techniques/{technique_id}", response_model=TechniqueOut)
def get_technique(technique_id: str, db: Session = Depends(get_db)) -> dict:
    row = db.get(Technique, technique_id.upper())
    if row is None:
        meta = get_mapper().get(technique_id)
        if meta is None:
            raise HTTPException(status_code=404, detail=f"technique '{technique_id}' not found")
        return meta.to_dict()
    return {
        "technique_id": row.technique_id, "name": row.name, "tactic": row.tactic,
        "description": row.description, "subtechnique_of": row.subtechnique_of,
        "detection_hint": row.detection_hint, "is_subtechnique": bool(row.is_subtechnique),
        "kill_chain_stage": stage_for_tactic(row.tactic),
    }


@router.get("/coverage", response_model=CoverageOut)
def coverage(
    chain_id: Optional[str] = None,
    scenario_id: Optional[str] = None,
    db: Session = Depends(get_db),
) -> dict:
    """ATT&CK coverage of reconstructed chains (one chain, one scenario, or all)."""
    mapper = get_mapper()
    stmt = select(AttackChain)
    if chain_id:
        stmt = stmt.where(AttackChain.chain_id == chain_id)
    if scenario_id:
        stmt = stmt.where(AttackChain.scenario_id == scenario_id)
    chains = list(db.scalars(stmt).all())
    if chain_id and not chains:
        raise HTTPException(status_code=404, detail=f"chain '{chain_id}' not found")

    ids: list[str] = []
    sources: list[str] = []
    for chain in chains:
        if chain.scenario_id and chain.scenario_id not in sources:
            sources.append(chain.scenario_id)
        for t in chain.techniques or []:
            tid = t.get("technique_id") if isinstance(t, dict) else str(t)
            if tid:
                ids.append(tid)
    raw = mapper.coverage(ids)
    tactics = [
        CoverageTactic(
            tactic=t["tactic"],
            techniques=[CoverageTechnique(**x) for x in t["techniques"]],
            count=t["count"],
        )
        for t in raw["tactics"]
    ]
    return {
        "tactics": tactics,
        "unique_techniques": raw["unique_techniques"],
        "unique_tactics": raw["unique_tactics"],
        "sources": sources,
        "chain_id": chain_id,
        "scenario_id": scenario_id,
    }
