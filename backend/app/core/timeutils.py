"""Time helpers shared by models and services."""
from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Naive UTC timestamp (matches the datetime columns used across ACR)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
