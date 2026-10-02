"""Temporal correlation: configurable windows and decay factors."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from app.core.config import Settings

WINDOW_LABELS = ("STRICT", "NORMAL", "BROAD")

# contribution multiplier per window bucket
DECAY: dict[str, float] = {"STRICT": 1.0, "NORMAL": 0.8, "BROAD": 0.5}


def get_timestamp(event: dict[str, Any]) -> Optional[datetime]:
    ts = event.get("timestamp")
    return ts if isinstance(ts, datetime) else None


def delta_seconds(a: dict[str, Any], b: dict[str, Any]) -> Optional[float]:
    ta, tb = get_timestamp(a), get_timestamp(b)
    if ta is None or tb is None:
        return None
    return abs((tb - ta).total_seconds())


def classify_delta(delta: Optional[float], settings: Settings) -> Optional[str]:
    """Return STRICT / NORMAL / BROAD, or None when outside every window."""
    if delta is None:
        return None
    if delta <= settings.window_strict:
        return "STRICT"
    if delta <= settings.window_normal:
        return "NORMAL"
    if delta <= settings.window_broad:
        return "BROAD"
    return None


def decay_for(delta: Optional[float], settings: Settings) -> float:
    window = classify_delta(delta, settings)
    return DECAY[window] if window else 0.0


def time_sort_key(event: dict[str, Any]) -> tuple[int, float]:
    ts = get_timestamp(event)
    if ts is None:
        return (1, 0.0)  # missing timestamps always sort last
    return (0, ts.timestamp())
