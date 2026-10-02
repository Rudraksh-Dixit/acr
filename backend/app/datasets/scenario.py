"""Adapter: built-in synthetic ACR scenarios (ground truth available)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from app.datasets.base import AdapterResult, issue


def load(
    path: Optional[Path] = None,
    entry: Optional[dict[str, Any]] = None,
    *,
    seed: int = 42,
) -> AdapterResult:
    """Generate the registered scenarios as source-shaped records.

    The scenario emitters already produce source-shaped telemetry (EventID,
    Computer, Image, ...), exactly like real logs, so they travel through the
    same normalizer path as any external dataset. Ground truth rides along as
    ``gt_id`` on each record, which is what makes P/R computable.
    """
    del path  # scenarios are generated, not read from disk
    entry = entry or {}
    wanted = entry.get("scenario_ids") or None

    from app.scenarios import generate_all, get_definition

    if not wanted:
        results = generate_all(seed=seed)
    else:
        results = []
        for sid in wanted:
            if get_definition(sid) is None:
                return AdapterResult(
                    issues=[issue(None, f"unknown scenario '{sid}'", "scenario_id")],
                    meta={"adapter": "scenario"},
                )
            from app.scenarios import generate_scenario

            results.append(generate_scenario(sid, seed=seed))

    records: list[dict[str, Any]] = []
    scenario_ids: list[str] = []
    for result in results:
        scenario_ids.append(result.scenario_id)
        records.extend(result.events)

    return AdapterResult(
        records=records,
        issues=[],
        meta={
            "adapter": "scenario",
            "scenario_ids": scenario_ids,
            "ground_truth": True,
            "rows_read": len(records),
        },
    )
