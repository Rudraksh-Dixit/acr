"""In-process cache for pipeline stage statistics (last ingest / reconstruct)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

_last_ingest: Optional[dict[str, Any]] = None
_last_reconstruction: Optional[dict[str, Any]] = None
_last_evaluation_run_id: Optional[int] = None


def record_ingest(report: dict[str, Any]) -> None:
    global _last_ingest
    _last_ingest = {**report, "at": datetime.now(timezone.utc).isoformat()}


def record_reconstruction(report: dict[str, Any]) -> None:
    global _last_reconstruction
    _last_reconstruction = {**report, "at": datetime.now(timezone.utc).isoformat()}


def record_evaluation_run(run_id: int) -> None:
    global _last_evaluation_run_id
    _last_evaluation_run_id = run_id


def last_ingest() -> Optional[dict[str, Any]]:
    return _last_ingest


def last_reconstruction() -> Optional[dict[str, Any]]:
    return _last_reconstruction


def last_evaluation_run_id() -> Optional[int]:
    return _last_evaluation_run_id
