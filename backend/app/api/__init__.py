"""API routers for the ACR REST API."""
from __future__ import annotations

from app.api import chains, evaluation, events, graphs, investigation, ioc, mitre, scenarios, system

API_ROUTER_MODULES = (events, chains, graphs, mitre, scenarios, investigation, evaluation, system, ioc)

__all__ = ["API_ROUTER_MODULES"]
