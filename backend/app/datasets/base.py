"""Dataset loader framework: one adapter per source.

Every adapter converts its source into *source-shaped* records (the same
style as the built-in scenarios) that then flow through the existing
normalizer/alias layer - adapters never bypass normalization.

Failure policy: a bad row never aborts a load. Rows that cannot be mapped
become structured issues (scope="dataset") so the UI can show
"N ingested, M skipped, reasons".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


class DatasetError(Exception):
    """Base class for dataset-level failures (file missing, bad catalog...)."""

    code = "dataset_error"

    def __init__(self, message: str, hint: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def to_dict(self) -> dict[str, Any]:
        return {"error": self.message, "code": self.code, "hint": self.hint}


class DatasetMissingError(DatasetError):
    code = "dataset_missing"


@dataclass
class AdapterResult:
    records: list[dict[str, Any]] = field(default_factory=list)
    issues: list[dict[str, Any]] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


def issue(index: Optional[int], message: str, field_name: Optional[str] = None) -> dict[str, Any]:
    return {
        "index": index,
        "scope": "dataset",
        "field": field_name,
        "message": message,
        "source": "dataset",
    }


# Windows event ids the canonical EVENT_ID_MAP does not cover. Kept small and
# unambiguous - anything else is reported as skipped instead of guessed.
EVENT_TYPE_EXTRAS: dict[str, str] = {
    "5156": "NETWORK_CONNECTION",   # WFP permitted connection
    "5158": "NETWORK_CONNECTION",   # WFP blocked connection
    "4648": "AUTHENTICATION",       # logon with explicit credentials
    "4663": "FILE_MODIFIED",        # object access (file)
}

_BARE_DASHES = {"", "-", "n/a", "none", "null"}


def clean(value: Any) -> Optional[str]:
    """Trimmed string or None for empty/dash placeholders."""
    if value is None:
        return None
    text = str(value).strip()
    if text.lower() in _BARE_DASHES:
        return None
    return text or None


def apply_event_id(record: dict[str, Any], event_id: Any) -> None:
    """Attach a numeric Windows/Sysmon event id (normalizer maps it)."""
    text = clean(event_id)
    if not text:
        return
    record["EventID"] = text
    extra = EVENT_TYPE_EXTRAS.get(text)
    if extra and "event_type" not in record:
        record["event_type"] = extra


# `Key: value` lines inside Windows Message blobs -> canonical field names
_MESSAGE_FIELDS: tuple[tuple[str, str], ...] = (
    ("Process Command Line", "command_line"),
    ("New Process Name", "process_name"),
    ("Creator Process Name", "parent_process"),
    ("Process Name", "process_name"),
    ("Image Name", "process_name"),
    ("Account Name", "user"),
    ("Destination Address", "destination_ip"),
    ("Source Address", "source_ip"),
    ("Destination Port", "destination_port"),
    ("Source Port", "source_port"),
    ("New Process ID", "process_id"),
)

_MESSAGE_RES: dict[str, re.Pattern[str]] = {
    label: re.compile(rf"^\s*{re.escape(label)}\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
    for label, _ in _MESSAGE_FIELDS
}


def apply_message_fields(record: dict[str, Any], message: Any) -> None:
    """Fill canonical fields from a Windows Event Log Message blob.

    Only fills fields the record does not already carry, and only with
    values the normalizer would accept (dashes and empties are dropped).
    """
    if not message:
        return
    text = str(message)
    for label, canonical in _MESSAGE_FIELDS:
        if canonical in record and clean(record.get(canonical)):
            continue
        m = _MESSAGE_RES[label].search(text)
        if not m:
            continue
        value = clean(m.group(1))
        if value is None:
            continue
        if canonical == "process_id":
            digits = re.search(r"0x[0-9a-fA-F]+|\d+", value)
            if digits:
                record["process_id"] = int(digits.group(0), 0)
        else:
            record[canonical] = value


def looks_like_record(row: Any) -> bool:
    """A row is mappable when it carries at least one identifying signal."""
    if not isinstance(row, dict):
        return False
    identity_keys = (
        "EventID", "event_id", "TimeCreated", "timestamp", "time", "SystemTime",
        "Hostname", "Computer", "host", "SourceAddress", "IpAddress", "source_ip",
        "EventCode", "EventCodeName",
    )
    return any(clean(row.get(k)) for k in identity_keys)


AdapterLoad = Callable[..., AdapterResult]
