"""Adapter: EVTX-ATTACK-SAMPLES converted to JSON (one object per row).

Source shape: rows exported from the repository's ``evtx_data.csv``
(``SystemTime``, ``Computer``, ``EventID``, ``IpAddress``, ``TargetUserName``,
``ProcessName``, ``CommandLine``, ``EVTX_Tactic``, ``EVTX_FileName``, ...).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from app.datasets.base import (
    AdapterResult,
    apply_event_id,
    clean,
    issue,
    looks_like_record,
)

_SOURCE = "evtx-attack-samples"


def _map_row(row: dict[str, Any], index: int) -> Optional[dict[str, Any]]:
    record: dict[str, Any] = {}

    ts = clean(row.get("SystemTime") or row.get("timestamp"))
    if ts:
        record["timestamp"] = ts

    host = clean(row.get("Computer") or row.get("Hostname"))
    if host:
        record["host"] = host

    apply_event_id(record, row.get("EventID"))

    src = clean(row.get("IpAddress") or row.get("SourceAddress"))
    if src:
        record["source_ip"] = src
    sport = clean(row.get("IpPort") or row.get("SourcePort"))
    if sport and str(sport).isdigit():
        record["source_port"] = int(sport)
    dst = clean(row.get("DestAddress"))
    if dst:
        record["destination_ip"] = dst
    dport = clean(row.get("DestPort"))
    if dport and str(dport).isdigit():
        record["destination_port"] = int(dport)

    user = clean(row.get("TargetUserName") or row.get("SubjectUserName"))
    if user:
        record["user"] = user
    proc = clean(row.get("ProcessName"))
    if proc:
        record["process_name"] = proc
    parent = clean(row.get("ParentProcessName") or row.get("CreatorProcessName"))
    if parent:
        record["parent_process"] = parent
    cmd = clean(row.get("CommandLine"))
    if cmd:
        record["command_line"] = cmd
    app = clean(row.get("Application"))
    if app and not proc:
        record["process_name"] = app
    proto = clean(row.get("Protocol"))
    if proto:
        record["protocol"] = {"6": "tcp", "17": "udp"}.get(str(proto), str(proto).lower())

    tactic = clean(row.get("EVTX_Tactic"))
    if tactic:
        record["tactic"] = tactic

    record["source"] = _SOURCE
    record["metadata"] = {
        "dataset": _SOURCE,
        "evtx_file": clean(row.get("EVTX_FileName")),
        "channel": clean(row.get("Channel")),
        "event_id_raw": clean(row.get("EventID")),
        "row_index": index,
    }
    return record if looks_like_record(record) else None


def load(path: Optional[Path] = None, entry: Optional[dict[str, Any]] = None) -> AdapterResult:
    del entry
    result = AdapterResult(meta={"adapter": "evtx_csv_json", "source": _SOURCE})
    if path is None or not path.exists():
        from app.datasets.base import DatasetMissingError

        raise DatasetMissingError(
            f"dataset file not found: {path}",
            hint="run python scripts/fetch_datasets.py (see data/datasets/README.md)",
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        result.issues.append(issue(None, f"invalid JSON in {path.name}: {exc}"))
        return result

    rows = payload if isinstance(payload, list) else payload.get("events", [])
    if not isinstance(rows, list):
        result.issues.append(issue(None, f"unexpected JSON structure in {path.name}"))
        return result

    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            result.issues.append(issue(index, f"row is not a JSON object ({type(row).__name__})"))
            continue
        if not looks_like_record(row):
            result.issues.append(issue(index, "row has no recognisable timestamp/host/event id fields"))
            continue
        mapped = _map_row(row, index)
        if mapped is None:
            result.issues.append(issue(index, "row could not be mapped to the canonical schema"))
            continue
        result.records.append(mapped)

    result.meta.update({"path": str(path), "rows_read": len(rows), "source": _SOURCE})
    return result
