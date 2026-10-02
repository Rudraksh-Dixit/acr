"""JSON telemetry loader with size and shape validation."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 50_000_000


class LoaderError(ValueError):
    """Raised when a file cannot be interpreted as a telemetry batch."""


def _extract_list(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("events", "records", "data", "items", "telemetry", "logs"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
        # single event object
        if any(k for k in payload if k in {"event_type", "type", "timestamp", "EventID", "computer"}):
            return [payload]
        raise LoaderError("JSON object does not contain an event array")
    raise LoaderError(f"unsupported JSON root type: {type(payload).__name__}")


def load_json(path: str | Path) -> list[Any]:
    file_path = Path(path)
    if not file_path.exists():
        raise LoaderError(f"file not found: {file_path}")
    if file_path.stat().st_size > MAX_FILE_BYTES:
        raise LoaderError(f"file exceeds {MAX_FILE_BYTES} bytes limit")
    try:
        text = file_path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise LoaderError(f"file is not valid UTF-8: {exc}") from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LoaderError(f"invalid JSON: {exc}") from exc
    return _extract_list(payload)


def parse_json_text(text: str) -> list[Any]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LoaderError(f"invalid JSON: {exc}") from exc
    return _extract_list(payload)
