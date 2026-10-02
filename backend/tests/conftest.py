"""Shared fixtures: temp database + FastAPI test client."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    from app.core.config import settings
    from app.core.database import init_db, reset_engine

    url = f"sqlite:///{(tmp_path / 'acr_test.db').as_posix()}"
    monkeypatch.setattr(settings, "database_url", url)
    reset_engine()
    init_db()
    yield url
    reset_engine()


@pytest.fixture()
def db_session(temp_db):
    from app.core.database import session_scope

    with session_scope() as session:
        yield session


@pytest.fixture()
def client(temp_db):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def generate_all_scenarios(client):
    def _generate(seed: int = 42, **kwargs):
        body = {"seed": seed, **kwargs}
        response = client.post("/api/scenarios/generate", json=body)
        assert response.status_code == 200, response.text
        return response.json()

    return _generate
