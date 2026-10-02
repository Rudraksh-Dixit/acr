"""API tests: dataset catalog, dataset runs, run history (offline, bundled files)."""
from __future__ import annotations

import pytest

from app.core.database import session_scope
from app.datasets import DatasetMissingError, dataset_entry
from app.models import Event
from app.services.dataset_service import run_dataset

NO_GT_NOTE = "no ground truth, precision/recall not computed"


# ---------------------------------------------------------------- catalog
def test_dataset_catalog_labels_and_availability(client):
    res = client.get("/api/datasets")
    assert res.status_code == 200
    payload = res.json()
    assert payload["total"] == 4
    by_id = {d["id"]: d for d in payload["items"]}
    assert by_id["synthetic-scenarios"]["label"] == "synthetic"
    assert by_id["synthetic-scenarios"]["ground_truth"] is True
    for d in payload["items"]:
        if d["kind"] == "real":
            assert d["label"].startswith("real ("), d["id"]
            assert d["ground_truth"] is False
            assert d["origin_url"].startswith("https://"), d["id"]
        assert d["available"] is True  # bundled files are committed


def test_dataset_unknown_id_404(client):
    res = client.post("/api/datasets/nope/run", json={})
    assert res.status_code == 404
    assert "unknown dataset" in res.json()["detail"]


# ---------------------------------------------------------------- runs
def test_run_real_dataset_reports_honest_evaluation(client):
    res = client.post("/api/datasets/evtx-attack-samples/run", json={"reconstruct": True})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["run_id"] is not None
    assert body["dataset"]["label"] == "real (EVTX-ATTACK-SAMPLES)"
    assert body["events_stored"] == 400
    assert body["events_skipped"] == 0
    assert body["detections"] >= 1  # real data, real rule matches
    # hard requirement: no invented metrics for unlabelled data
    ev = body["evaluation"]
    assert ev["ground_truth"] is False
    assert ev["note"] == NO_GT_NOTE
    assert ev["metrics"] is None
    assert ev["per_scenario"] is None


def test_run_splunk_dataset_detects_credential_dumping(client):
    res = client.post("/api/datasets/splunk-attack-data-windows-security/run", json={})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["events_stored"] == 4
    assert body["detections"] >= 1
    assert body["evaluation"]["note"] == NO_GT_NOTE


def test_real_dataset_run_reports_skips_with_reasons(client):
    res = client.post("/api/datasets/otrf-security-datasets-lsass/run", json={})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["events_stored"] == 58
    assert body["events_skipped"] == 60
    assert body["events_received"] == 118
    messages = [i["message"] for i in body["ingest_issues"]]
    assert messages and all("event_type" in m for m in messages)


def test_dataset_rerun_is_idempotent(client):
    first = client.post("/api/datasets/otrf-security-datasets-lsass/run", json={}).json()
    second = client.post("/api/datasets/otrf-security-datasets-lsass/run", json={}).json()
    assert second["events_replaced"] == first["events_stored"] == 58
    assert second["events_stored"] == 58
    with session_scope() as db:
        total = db.query(Event).filter(Event.metadata_json["dataset_id"].as_string()
                                       == "otrf-security-datasets-lsass").count()
    assert total == 58  # no duplicates on re-run


def test_synthetic_dataset_run_computes_real_metrics(client):
    res = client.post("/api/datasets/synthetic-scenarios/run", json={"seed": 42})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["events_stored"] == 53
    assert body["detections"] >= 1
    ev = body["evaluation"]
    assert ev["ground_truth"] is True
    assert ev["note"] is None
    metrics = ev["metrics"]
    assert metrics["technique_level"]["reconstruction"]["f1"] is not None
    assert metrics["technique_level"]["raw_detection"]["precision"] is not None
    assert len(ev["per_scenario"]) == 6
    # scenario linkage survives dataset ingestion (chains group by scenario)
    with session_scope() as db:
        linked = db.query(Event).filter(Event.scenario_id.isnot(None)).count()
    assert linked == 53


def test_dataset_run_dry_run_touches_nothing(client):
    client.post("/api/datasets/splunk-attack-data-windows-security/run", json={})
    res = client.post(
        "/api/datasets/splunk-attack-data-windows-security/run",
        json={"ingest": False},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["run_id"] is None
    assert body["events_stored"] == 0
    assert body["adapter"]["rows_read"] == 4
    with session_scope() as db:
        assert db.query(Event).count() == 4  # store untouched by dry run


# ---------------------------------------------------------------- history
def test_dataset_run_history_endpoints(client):
    client.post("/api/datasets/splunk-attack-data-windows-security/run", json={})
    client.post("/api/datasets/evtx-attack-samples/run", json={})

    res = client.get("/api/datasets/runs")
    assert res.status_code == 200
    payload = res.json()
    assert payload["total"] == 2
    assert payload["items"][0]["dataset_id"] in {
        "evtx-attack-samples", "splunk-attack-data-windows-security",
    }
    assert payload["items"][0]["evaluation"]["note"] == NO_GT_NOTE

    run_id = payload["items"][0]["id"]
    detail = client.get(f"/api/datasets/runs/{run_id}")
    assert detail.status_code == 200
    assert detail.json()["config"]["adapter"] in {"evtx_csv_json", "splunk_log"}
    assert detail.json()["counts"]["events_stored"] > 0

    missing = client.get("/api/datasets/runs/999999")
    assert missing.status_code == 404


def test_existing_evaluation_history_untouched(client):
    """dataset runs live in their own history; /api/evaluation/runs stays scenario-only."""
    client.post("/api/datasets/evtx-attack-samples/run", json={})
    res = client.get("/api/evaluation/runs")
    assert res.status_code == 200
    assert res.json()["total"] == 0  # no scenario evaluations were run


# ---------------------------------------------------------------- service errors
def test_run_dataset_missing_file_raises_structured_error(db_session, tmp_path):
    entry = dict(dataset_entry("otrf-security-datasets-lsass") or {})
    entry["path"] = str(tmp_path / "absent.json")
    with pytest.raises(DatasetMissingError) as exc:
        run_dataset(db_session, entry, ingest=False)
    assert "fetch_datasets" in exc.value.hint
