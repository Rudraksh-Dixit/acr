"""Ordered attack-path construction (observed stages + inferred gaps)."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from app.core.config import TACTIC_ORDER
from app.correlation.technique import tactic_index, tactic_of


def build_attack_path(
    events: list[dict[str, Any]],
    techniques: list[str],
    tactics: list[str],
    missing_steps: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return an ordered list of attack stages.

    Observed stages are ordered chronologically by first appearance. Gaps in
    the kill chain between observed tactics are inserted as INFERRED stages so
    the frontend can replay the attack and clearly distinguish what was seen
    from what the engine believes happened.
    """
    observed_tactics = {str(t).upper() for t in tactics}
    observed_tactics.intersection_update(TACTIC_ORDER)

    chron: list[tuple[Optional[datetime], str, Optional[str]]] = []
    for tactic in observed_tactics:
        best_ts: Optional[datetime] = None
        best_tech: Optional[str] = None
        for event in events:
            if tactic_of(event) != tactic:
                continue
            ts = event.get("timestamp")
            if isinstance(ts, datetime) and (best_ts is None or ts < best_ts):
                best_ts = ts
                best_tech = event.get("technique_id")
        chron.append((best_ts, tactic, best_tech))

    chron.sort(key=lambda item: (item[0] is None, item[0] or datetime.max))

    missing_by_tactic: dict[str, dict[str, Any]] = {}
    for step in (missing_steps or []):
        missing_by_tactic.setdefault(str(step.get("tactic")).upper(), step)

    stages: list[dict[str, Any]] = []
    for position, (ts, tactic, technique_id) in enumerate(chron):
        stages.append(
            {
                "stage": len(stages) + 1,
                "kind": "OBSERVED",
                "inferred": False,
                "tactic": tactic,
                "technique_id": technique_id,
                "confidence": None,
                "timestamp": (ts.isoformat() + "Z") if ts else None,
                "event_ids": [e["event_id"] for e in events if tactic_of(e) == tactic and e.get("event_id")],
            }
        )
        if position + 1 < len(chron):
            next_tactic = chron[position + 1][1]
            ti_now = tactic_index(tactic) or 0
            ti_next = tactic_index(next_tactic) or 0
            for idx in range(ti_now + 1, ti_next):
                gap = TACTIC_ORDER[idx]
                step = missing_by_tactic.get(gap)
                if step:
                    stages.append(
                        {
                            "stage": len(stages) + 1,
                            "kind": "INFERRED",
                            "inferred": True,
                            "tactic": gap,
                            "technique_id": step.get("technique_id"),
                            "confidence": step.get("confidence"),
                            "reason": step.get("reason"),
                            "timestamp": None,
                            "event_ids": [],
                        }
                    )
    return stages
