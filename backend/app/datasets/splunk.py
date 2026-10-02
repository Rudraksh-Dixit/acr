"""Adapter: Splunk attack_data Windows logs (wevtutil ``Key=Value`` text).

Source shape: blocks separated by a bare timestamp line::

    03/23/2021 01:40:45 PM
    LogName=Security
    EventCode=4688
    ComputerName=win-dc-811.attackrange.local
    Message=A new process has been created.
            <indented continuation lines belong to Message>
"""
from __future__ import annotations

import re
from datetime import datetime
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

_SOURCE = "splunk-attack-data"

# `03/23/2021 01:40:45 PM` starts a new event block
_TS_RE = re.compile(r"^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} (?:AM|PM)$")
# column-0 `Key=Value` starts a new field
_KV_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_]*)=(.*)$")

_FIELD_TO_META = ("SourceName", "EventType", "Type", "TaskCategory", "OpCode",
                  "RecordNumber", "Keywords", "LogName")


def parse_blocks(text: str) -> list[dict[str, Any]]:
    """Split wevtutil-style text into {timestamp, fields, message} blocks."""
    blocks: list[dict[str, Any]] = []
    current: Optional[dict[str, Any]] = None

    def flush() -> None:
        nonlocal current
        if current is not None:
            blocks.append(current)
            current = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        if _TS_RE.match(line.strip()):
            flush()
            current = {"timestamp": line.strip(), "fields": {}, "message": ""}
            continue
        if current is None:
            # tolerate a leading blank/garbage line before the first block
            continue
        m = _KV_RE.match(line)
        if m:
            key, value = m.group(1), m.group(2)
            current["fields"][key] = value
            current["_msg_key"] = key if key == "Message" else None
            continue
        # continuation line: belongs to Message when we are inside it
        if current.get("_msg_key") == "Message" and line.strip():
            current["message"] += "\n" + line.strip()
    flush()
    return blocks


def _map_block(block: dict[str, Any], index: int) -> Optional[dict[str, Any]]:
    fields: dict[str, Any] = block.get("fields", {})
    record: dict[str, Any] = {}

    ts = block.get("timestamp")
    if ts:
        try:
            record["timestamp"] = datetime.strptime(ts, "%m/%d/%Y %I:%M:%S %p").isoformat()
        except ValueError:
            record["timestamp"] = ts  # let the normalizer judge / report

    apply_event_id(record, fields.get("EventCode"))
    host = clean(fields.get("ComputerName") or fields.get("Computer"))
    if host:
        record["host"] = host

    message = clean(block.get("message") or fields.get("Message"))
    if message:
        apply_message_fields(record, message)

    record["source"] = _SOURCE
    meta: dict[str, Any] = {"dataset": _SOURCE, "row_index": index}
    for key in _FIELD_TO_META:
        value = clean(fields.get(key))
        if value:
            meta[key.lower()] = value
    if message:
        meta["message"] = message[:1000]
    record["metadata"] = meta
    return record if looks_like_record(record) else None


def load(path: Optional[Path] = None, entry: Optional[dict[str, Any]] = None) -> AdapterResult:
    del entry
    result = AdapterResult(meta={"adapter": "splunk_log", "source": _SOURCE})
    if path is None or not path.exists():
        from app.datasets.base import DatasetMissingError

        raise DatasetMissingError(
            f"dataset file not found: {path}",
            hint="run python scripts/fetch_datasets.py (see data/datasets/README.md)",
        )
    text = path.read_text(encoding="utf-8", errors="replace")
    blocks = parse_blocks(text)
    if not blocks:
        result.issues.append(issue(None, f"no event blocks found in {path.name}"))
        return result

    for index, block in enumerate(blocks):
        if not block.get("fields") and not block.get("message"):
            result.issues.append(issue(index, "block has no fields or message"))
            continue
        mapped = _map_block(block, index)
        if mapped is None:
            result.issues.append(issue(index, "block could not be mapped to the canonical schema"))
            continue
        result.records.append(mapped)

    result.meta.update({"path": str(path), "rows_read": len(blocks), "source": _SOURCE})
    return result
