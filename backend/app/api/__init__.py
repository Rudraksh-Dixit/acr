"""API routers for the ACR REST API."""
from __future__ import annotations

from app.api import (
    chains, datasets, evaluation, events, graphs, investigation, ioc, mitre, scenarios, system,
)

API_ROUTER_MODULES = (
    events, chains, graphs, mitre, scenarios, investigation, evaluation, system, ioc, datasets,
)

__all__ = ["API_ROUTER_MODULES"]
