"""Adapter: OTRF Security Datasets (Mordor) JSON samples.

Source shape (one JSON object per row): Windows event fields such as
``EventID`` / ``TimeCreated`` / ``Hostname`` / ``SourceAddress`` /
``DestAddress`` / ``Application`` / ``Message``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from app.datasets.base import (
    AdapterResult,
    apply_event_id,
    apply_message_fields,
    clean,
    issue,
    looks_like_record,
)

_SOURCE = "otrf-security-datasets"


def _map_row(row: dict[str, Any], index: int) -> Optional[dict[str, Any]]:
    record: dict[str, Any] = {}

    ts = clean(row.get("TimeCreated") or row.get("timestamp") or row.get("@timestamp"))
    if ts:
        record["timestamp"] = ts  # "2020-10-18 10:56:18.799" is a normalizer pattern

    host = clean(row.get("Hostname") or row.get("Computer") or row.get("host"))
    if host:
        record["host"] = host

    apply_event_id(record, row.get("EventID"))

    src = clean(row.get("SourceAddress") or row.get("src_ip"))
    if src:
        record["source_ip"] = src
    dst = clean(row.get("DestAddress") or row.get("DestinationIp") or row.get("dst_ip"))
    if dst:
        record["destination_ip"] = dst
    sport = clean(row.get("SourcePort"))
    if sport and str(sport).isdigit():
        record["source_port"] = int(sport)
    dport = clean(row.get("DestPort") or row.get("DestinationPort"))
    if dport and str(dport).isdigit():
        record["destination_port"] = int(dport)
    proto = clean(row.get("Protocol"))
    if proto:
        record["protocol"] = "tcp" if proto in {"6", "TCP"} else ("udp" if proto in {"17", "UDP"} else proto.lower())

    app = clean(row.get("Application") or row.get("Image"))
    if app:
        record["process_name"] = app
    user = clean(row.get("TargetUserName") or row.get("UserName") or row.get("AccountName"))
    if user:
        record["user"] = user
    query = clean(row.get("QueryName"))
    if query:
        record["domain"] = query

    apply_message_fields(record, row.get("Message"))

    record["source"] = _SOURCE
    record["metadata"] = {
        "dataset": _SOURCE,
        "channel": clean(row.get("Channel")),
        "event_id_raw": clean(row.get("EventID")),
        "row_index": index,
    }
    message = clean(row.get("Message"))
    if message:
        record["metadata"]["message"] = message[:1000]
    return record if looks_like_record(record) else None


def load(path: Optional[Path] = None, entry: Optional[dict[str, Any]] = None) -> AdapterResult:
    del entry
    result = AdapterResult(meta={"adapter": "otrf_json", "source": _SOURCE})
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
