"""CSV telemetry loader."""
from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any

from app.ingestion.json_loader import MAX_FILE_BYTES, LoaderError


def load_csv(path: str | Path) -> list[dict[str, Any]]:
    file_path = Path(path)
    if not file_path.exists():
        raise LoaderError(f"file not found: {file_path}")
    if file_path.stat().st_size > MAX_FILE_BYTES:
        raise LoaderError(f"file exceeds {MAX_FILE_BYTES} bytes limit")
    try:
        text = file_path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise LoaderError(f"file is not valid UTF-8: {exc}") from exc
    return parse_csv_text(text)


def parse_csv_text(text: str) -> list[dict[str, Any]]:
    if not text.strip():
        raise LoaderError("empty CSV content")
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    if not reader.fieldnames:
        raise LoaderError("CSV has no header row")
    rows: list[dict[str, Any]] = []
    for row in reader:
        if row is None:
            continue
        cleaned = {str(k).strip(): (v if isinstance(v, str) else v) for k, v in row.items() if k is not None}
        if any((v or "").strip() for v in cleaned.values()):
            rows.append(cleaned)
    if not rows:
        raise LoaderError("CSV contains no data rows")
    return rows
