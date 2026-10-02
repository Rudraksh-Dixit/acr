"""Dataset catalog + adapter framework tests (no network, bundled files)."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.datasets import (
    DatasetMissingError,
    availability,
    load_dataset,
    read_catalog,
    resolve_path,
)
from app.datasets.evtx import load as load_evtx
from app.datasets.otrf import load as load_otrf
from app.datasets.splunk import load as load_splunk, parse_blocks
from app.ingestion.normalizer import normalize_records

ROOT = Path(__file__).resolve().parents[3]


# ---------------------------------------------------------------- catalog
def test_catalog_shape_and_labels():
    catalog = read_catalog()
    datasets = catalog["datasets"]
    assert len(datasets) >= 4
    ids = {d["id"] for d in datasets}
    assert {"synthetic-scenarios", "otrf-security-datasets-lsass",
            "evtx-attack-samples", "splunk-attack-data-windows-security"} <= ids

    for d in datasets:
        # hard requirement: label is 'synthetic' or 'real (source name)'
        if d["kind"] == "synthetic":
            assert d["label"] == "synthetic", d["id"]
        else:
            assert d["label"].startswith("real ("), d["id"]
            assert d["label"].endswith(")"), d["id"]
        assert d["source_name"], d["id"]
        if d["ground_truth"]:
            assert d["kind"] == "synthetic", "only synthetic data carries labels"
        assert d["adapter"] in {"scenario", "otrf_json", "evtx_csv_json", "splunk_log"}


def test_bundled_files_exist_and_resolve():
    catalog = read_catalog()
    for d in catalog["datasets"]:
        if d["adapter"] == "scenario":
            assert availability(d)["available"] is True
            continue
        path = resolve_path(d)
        assert path is not None and path.exists(), f"missing bundled file for {d['id']}"
        assert availability(d)["available"] is True


def test_missing_file_raises_structured_error(tmp_path):
    entry = {"id": "ghost", "adapter": "otrf_json", "path": str(tmp_path / "nope.json"),
             "label": "real (x)", "kind": "real"}
    with pytest.raises(DatasetMissingError) as exc:
        load_dataset(entry)
    payload = exc.value.to_dict()
    assert payload["code"] == "dataset_missing"
    assert "fetch_datasets" in payload["hint"]


def test_load_dataset_attaches_provenance():
    catalog = read_catalog()
    for d in catalog["datasets"]:
        result = load_dataset(d)
        assert result.meta["dataset_id"] == d["id"]
        assert result.meta["label"] == d["label"]
        assert result.meta["ground_truth"] is d["ground_truth"]
        assert result.records, f"no records from {d['id']}"
        meta = result.records[0].get("metadata", {})
        assert meta.get("dataset_label") == d["label"]


# ---------------------------------------------------------------- scenario adapter
def test_scenario_adapter_has_ground_truth_and_normalizes():
    entry = next(d for d in read_catalog()["datasets"] if d["id"] == "synthetic-scenarios")
    result = load_dataset(entry, seed=42)
    assert result.meta["ground_truth"] is True
    assert len(result.records) == 53
    assert any("gt_id" in r for r in result.records)
    assert result.issues == []
    batch = normalize_records(result.records, source="synthetic-scenarios")
    assert len(batch.events) == 53
    assert batch.skipped == 0


# ---------------------------------------------------------------- OTRF adapter
def _otrf_file(tmp_path, rows) -> Path:
    import json

    p = tmp_path / "otrf.json"
    p.write_text(json.dumps(rows), encoding="utf-8")
    return p


def test_otrf_adapter_maps_canonical_fields(tmp_path):
    rows = [{
        "EventID": 5156, "TimeCreated": "2020-10-18 10:56:18.799",
        "Hostname": "WORKSTATION5", "SourceAddress": "192.168.2.5",
        "DestAddress": "168.63.129.16", "SourcePort": "56628", "DestPort": "80",
        "Protocol": "6", "Application": "C:\\Windows\\System32\\svchost.exe",
        "Message": "The Windows Filtering Platform has permitted a connection.",
        "Channel": "Security",
    }]
    res = load_otrf(_otrf_file(tmp_path, rows), None)
    assert res.issues == [] and len(res.records) == 1
    r = res.records[0]
    assert r["timestamp"] == "2020-10-18 10:56:18.799"
    assert r["host"] == "WORKSTATION5"
    assert r["source_ip"] == "192.168.2.5"
    assert r["destination_ip"] == "168.63.129.16"
    assert r["destination_port"] == 80
    assert r["event_type"] == "NETWORK_CONNECTION"  # extras map (5156)
    assert r["process_name"].endswith("svchost.exe")
    assert r["source"] == "otrf-security-datasets"

    batch = normalize_records(res.records, source="otrf")
    assert len(batch.events) == 1
    assert batch.events[0]["event_type"] == "NETWORK_CONNECTION"


def test_otrf_adapter_bad_rows_become_issues(tmp_path):
    rows = ["not a dict", {"random": "junk"}, {"EventID": 1, "TimeCreated": "2020-01-01 00:00:00"}]
    res = load_otrf(_otrf_file(tmp_path, rows), None)
    assert len(res.issues) == 2  # string row + junk row
    assert all(i["scope"] == "dataset" for i in res.issues)
    assert len(res.records) == 1  # valid row still loads (never aborts)


def test_otrf_adapter_invalid_json_is_issue(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    res = load_otrf(p, None)
    assert res.records == []
    assert any("invalid JSON" in i["message"] for i in res.issues)


# ---------------------------------------------------------------- EVTX adapter
def test_evtx_adapter_maps_row(tmp_path):
    import json

    rows = [{
        "SystemTime": "2019-02-13 15:14:52.409735", "Computer": "PC02.example.corp",
        "EventID": "4688", "IpAddress": "10.0.0.5", "TargetUserName": "Administrator",
        "ProcessName": "rundll32.exe",
        "CommandLine": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump",
        "EVTX_Tactic": "Credential Access", "EVTX_FileName": "cred.evtx",
        "Channel": "Security",
    }]
    p = tmp_path / "evtx.json"
    p.write_text(json.dumps(rows), encoding="utf-8")
    res = load_evtx(p, None)
    assert res.issues == [] and len(res.records) == 1
    r = res.records[0]
    assert r["host"] == "PC02.example.corp"
    assert r["EventID"] == "4688"  # normalizer maps it to PROCESS_CREATED
    assert r["source_ip"] == "10.0.0.5"
    assert r["user"] == "Administrator"
    assert "comsvcs" in r["command_line"]
    assert r["tactic"] == "Credential Access"
    assert r["metadata"]["evtx_file"] == "cred.evtx"

    batch = normalize_records(res.records, source="evtx")
    assert len(batch.events) == 1
    assert batch.events[0]["event_type"] == "PROCESS_CREATED"


# ---------------------------------------------------------------- Splunk adapter
SPLUNK_TEXT = """03/23/2021 01:40:45 PM
LogName=Security
EventCode=4688
ComputerName=win-dc-811.attackrange.local
Message=A new process has been created.

Creator Subject:
\tAccount Name:\t\tAdministrator
Process Information:
\tNew Process Name:\tC:\\Windows\\System32\\rundll32.exe
\tCreator Process Name:\tC:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
\tProcess Command Line:\t"rundll32.exe" comsvcs.dll MiniDump

03/23/2021 01:41:02 PM
LogName=Security
EventCode=5156
ComputerName=win-dc-811.attackrange.local
Message=The Windows Filtering Platform has permitted a connection.
"""


def test_splunk_parse_blocks():
    blocks = parse_blocks(SPLUNK_TEXT)
    assert len(blocks) == 2
    assert blocks[0]["timestamp"] == "03/23/2021 01:40:45 PM"
    assert blocks[0]["fields"]["EventCode"] == "4688"
    assert "Account Name" in blocks[0]["message"]
    assert blocks[1]["fields"]["EventCode"] == "5156"


def test_splunk_adapter_maps_and_extracts_message_fields(tmp_path):
    p = tmp_path / "sample.log"
    p.write_text(SPLUNK_TEXT, encoding="utf-8")
    res = load_splunk(p, None)
    assert res.issues == [] and len(res.records) == 2
    first = res.records[0]
    assert first["timestamp"].startswith("2021-03-23T13:40:45")
    assert first["host"] == "win-dc-811.attackrange.local"
    assert first["EventID"] == "4688"
    assert first["process_name"].endswith("rundll32.exe")
    assert first["parent_process"].endswith("powershell.exe")
    assert "comsvcs" in first["command_line"]
    assert first["user"] == "Administrator"
    second = res.records[1]
    assert second["EventID"] == "5156"
    assert second["event_type"] == "NETWORK_CONNECTION"  # extras map (5156)

    batch = normalize_records(res.records, source="splunk")
    assert len(batch.events) == 2
    assert batch.events[0]["event_type"] == "PROCESS_CREATED"
    assert batch.events[1]["event_type"] == "NETWORK_CONNECTION"


def test_splunk_empty_file_is_issue(tmp_path):
    p = tmp_path / "empty.log"
    p.write_text("", encoding="utf-8")
    res = load_splunk(p, None)
    assert res.records == []
    assert any("no event blocks" in i["message"] for i in res.issues)


# ---------------------------------------------------------------- bundled end-to-end
@pytest.mark.parametrize("dataset_id", [
    "otrf-security-datasets-lsass",
    "evtx-attack-samples",
    "splunk-attack-data-windows-security",
])
def test_bundled_real_datasets_flow_through_pipeline(dataset_id):
    from app.core.config import settings
    from app.detection import run_detection

    entry = next(d for d in read_catalog()["datasets"] if d["id"] == dataset_id)
    result = load_dataset(entry)
    batch = normalize_records(result.records, source=dataset_id)
    # every bundled dataset must yield events (no total loss)
    assert len(batch.events) > 0
    matches = run_detection(batch.events, settings)
    assert isinstance(matches, list)
    if dataset_id == "splunk-attack-data-windows-security":
        # the sample's comsvcs.dll MiniDump command must be detected
        assert any(m.rule_id == "CREDENTIAL_DUMPING_TOOL" for m in matches)
    if dataset_id == "evtx-attack-samples":
        assert len(matches) >= 1


def test_unmappable_real_rows_are_reported_not_dropped_silently():
    entry = next(d for d in read_catalog()["datasets"] if d["id"] == "otrf-security-datasets-lsass")
    result = load_dataset(entry)
    batch = normalize_records(result.records, source=entry["id"])
    # this sample contains event ids ACR deliberately does not map (10, 4658...)
    assert batch.skipped > 0
    assert all("event_type" in i.message for i in batch.issues)
