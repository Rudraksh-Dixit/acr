"""FastAPI application entrypoint for ACR.

Run with:  uvicorn app.main:app --reload   (from backend/)
       or  python -m acr serve             (from project root)
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import API_ROUTER_MODULES
from app.core.config import settings
from app.core.database import init_db, session_scope
from app.core.logging import get_logger, log_event

logger = get_logger("api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    from app.mitre import sync_techniques_to_db

    with session_scope() as session:
        added = sync_techniques_to_db(session)
    log_event(logger, "startup_complete", version=settings.version, techniques_synced=added)
    yield
    log_event(logger, "shutdown")


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description=(
        "Attack Chain Reconstruction Engine: ingest telemetry, run rule-based "
        "detection, correlate events with multi-signal scoring, reconstruct "
        "attack chains, map them to MITRE ATT&CK and evaluate against "
        "synthetic ground truth."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

for router_module in API_ROUTER_MODULES:
    app.include_router(router_module.router)


@app.exception_handler(KeyError)
async def key_error_handler(request: Request, exc: KeyError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc.args[0]) if exc.args else str(exc)})


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.get("/api", include_in_schema=False)
def api_index() -> dict[str, Any]:
    return {
        "name": settings.app_name,
        "version": settings.version,
        "docs": "/docs",
        "endpoints": sorted({route.path for route in app.routes if route.path.startswith("/api")}),
    }
