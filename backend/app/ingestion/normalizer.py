"""Normalization: map heterogeneous raw telemetry into the canonical ACR event schema.

The normalizer is deliberately defensive: one malformed record never aborts a
batch. Field-level problems are reported as structured errors while the record
is salvaged as much as possible.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

EVENT_TYPES: tuple[str, ...] = (
    "LOGIN_ATTEMPT",
    "LOGIN_SUCCESS",
    "PROCESS_CREATED",
    "FILE_CREATED",
    "FILE_MODIFIED",
    "REGISTRY_MODIFIED",
    "NETWORK_CONNECTION",
    "DNS_QUERY",
    "AUTHENTICATION",
    "PRIVILEGE_CHANGE",
    "SERVICE_CREATED",
    "REMOTE_EXECUTION",
)

SEVERITIES: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# canonical field <- accepted aliases (lower-cased keys)
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timestamp", "time", "event_time", "eventtime", "@timestamp", "date", "created", "utc_time", "datetime"),
    "event_type": ("event_type", "eventtype", "type", "event", "action", "category", "log_type", "kind"),
    "host": ("host", "hostname", "computer", "machine", "device", "endpoint", "agent", "computername"),
    "user": ("user", "username", "account", "account_name", "subjectusername", "targetusername", "user_name", "principal"),
    "source_ip": ("source_ip", "src_ip", "srcip", "sourceip", "saddr", "src", "client_ip", "ip_address"),
    "destination_ip": ("destination_ip", "dst_ip", "dstip", "destinationip", "daddr", "dst", "server_ip", "remote_ip"),
    "source_port": ("source_port", "src_port", "sport", "sourceport"),
    "destination_port": ("destination_port", "dst_port", "dport", "destinationport"),
    "protocol": ("protocol", "proto", "l4_proto"),
    "process_name": ("process_name", "process", "image", "image_name", "imagename", "newprocessname", "proc"),
    "process_id": ("process_id", "pid", "processid", "newprocessid"),
    "parent_process": ("parent_process", "parent_image", "parentimage", "parent_name", "parentprocessname", "ppid_name"),
    "parent_process_id": ("parent_process_id", "ppid", "parentprocessid", "parent_pid"),
    "command_line": ("command_line", "commandline", "cmdline", "cmd", "command", "process_command_line"),
    "file_path": ("file_path", "filepath", "path", "targetfilename", "filename", "file_name", "target_path",
                  "service_path", "binary_path", "imagepath"),
    "file_hash": ("file_hash", "hash", "hashes", "sha256", "md5", "sha1"),
    "domain": ("domain", "query", "dns_query", "queryname", "dns_name", "qname", "remote_host"),
    "severity": ("severity", "level", "risk", "priority"),
    "technique_id": ("technique_id", "techniqueid", "technique", "mitre_id", "attack_id"),
    "technique_name": ("technique_name", "techniquename", "mitre_name"),
    "tactic": ("tactic", "mitre_tactic"),
    "source": ("source", "sensor", "product", "log_source", "sourcetype", "provider"),
    "metadata": ("metadata", "extra", "fields", "additional", "properties"),
}

# raw event-type values (lower-cased) -> canonical type
TYPE_ALIASES: dict[str, str] = {
    "login_attempt": "LOGIN_ATTEMPT",
    "logon_attempt": "LOGIN_ATTEMPT",
    "failed_logon": "LOGIN_ATTEMPT",
    "login_failure": "LOGIN_ATTEMPT",
    "failed_login": "LOGIN_ATTEMPT",
    "auth_failure": "LOGIN_ATTEMPT",
    "login_success": "LOGIN_SUCCESS",
    "logon_success": "LOGIN_SUCCESS",
    "successful_logon": "LOGIN_SUCCESS",
    "process_created": "PROCESS_CREATED",
    "process_create": "PROCESS_CREATED",
    "processcreation": "PROCESS_CREATED",
    "new_process": "PROCESS_CREATED",
    "file_created": "FILE_CREATED",
    "file_create": "FILE_CREATED",
    "filewrite": "FILE_CREATED",
    "file_written": "FILE_CREATED",
    "file_modified": "FILE_MODIFIED",
    "file_change": "FILE_MODIFIED",
    "file_delete": "FILE_MODIFIED",
    "registry_modified": "REGISTRY_MODIFIED",
    "registry_event": "REGISTRY_MODIFIED",
    "registry_change": "REGISTRY_MODIFIED",
    "regvalue_set": "REGISTRY_MODIFIED",
    "network_connection": "NETWORK_CONNECTION",
    "network_connect": "NETWORK_CONNECTION",
    "netflow": "NETWORK_CONNECTION",
    "connection": "NETWORK_CONNECTION",
    "outbound_connection": "NETWORK_CONNECTION",
    "dns_query": "DNS_QUERY",
    "dns": "DNS_QUERY",
    "query": "DNS_QUERY",
    "authentication": "AUTHENTICATION",
    "auth": "AUTHENTICATION",
    "privilege_change": "PRIVILEGE_CHANGE",
    "privilege_escalation": "PRIVILEGE_CHANGE",
    "special_logon": "PRIVILEGE_CHANGE",
    "special_privileges": "PRIVILEGE_CHANGE",
    "privilege_assignment": "PRIVILEGE_CHANGE",
    "service_created": "SERVICE_CREATED",
    "service_install": "SERVICE_CREATED",
    "service_installed": "SERVICE_CREATED",
    "service_installation": "SERVICE_CREATED",
    "remote_execution": "REMOTE_EXECUTION",
    "remote_exec": "REMOTE_EXECUTION",
    "psexec": "REMOTE_EXECUTION",
}

# Windows/Sysmon event-id style mappings
EVENT_ID_MAP: dict[str, str] = {
    "1": "PROCESS_CREATED",
    "3": "NETWORK_CONNECTION",
    "7": "PROCESS_CREATED",
    "11": "FILE_CREATED",
    "12": "REGISTRY_MODIFIED",
    "13": "REGISTRY_MODIFIED",
    "14": "REGISTRY_MODIFIED",
    "22": "DNS_QUERY",
    "4624": "LOGIN_SUCCESS",
    "4625": "LOGIN_ATTEMPT",
    "4672": "PRIVILEGE_CHANGE",
    "4688": "PROCESS_CREATED",
    "4697": "SERVICE_CREATED",
    "4698": "SERVICE_CREATED",
    "7045": "SERVICE_CREATED",
}

DEFAULT_SEVERITY: dict[str, str] = {
    "LOGIN_ATTEMPT": "LOW",
    "LOGIN_SUCCESS": "INFO",
    "PROCESS_CREATED": "INFO",
    "FILE_CREATED": "INFO",
    "FILE_MODIFIED": "INFO",
    "REGISTRY_MODIFIED": "INFO",
    "NETWORK_CONNECTION": "INFO",
    "DNS_QUERY": "INFO",
    "AUTHENTICATION": "INFO",
    "PRIVILEGE_CHANGE": "MEDIUM",
    "SERVICE_CREATED": "MEDIUM",
    "REMOTE_EXECUTION": "HIGH",
}

_ISO_PATTERNS = (
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
)

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Exact-match-only keys for event identity. Deliberately NOT alias-normalized:
# the canonical name "event_id" would otherwise collide with Windows/Sysmon
# "EventID", which must stay a numeric event-type hint instead.
EVENT_ID_KEYS = {"event_id", "record_id", "telemetry_id", "unique_id", "uuid"}


def _lookup_event_id(raw: dict[str, Any]) -> Any:
    for key, value in raw.items():
        if str(key).strip().lower() in EVENT_ID_KEYS and value not in (None, ""):
            return value
    return None


@dataclass
class NormalizationIssue:
    index: int
    scope: str  # "record" | "field"
    field: Optional[str]
    message: str


@dataclass
class NormalizedBatch:
    events: list[dict[str, Any]] = field(default_factory=list)
    issues: list[NormalizationIssue] = field(default_factory=list)
    skipped: int = 0


def new_event_id() -> str:
    return f"EVT-{uuid.uuid4().hex[:12].upper()}"


def parse_timestamp(value: Any) -> tuple[Optional[datetime], Optional[str]]:
    """Return (timestamp, error_message). Tolerates ISO strings and epochs."""
    if value is None or value == "":
        return None, "missing timestamp"
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        # epoch seconds or milliseconds
        seconds = float(value)
        if seconds > 1e12:
            seconds /= 1000.0
        if seconds < 0 or seconds > 4e9:
            return None, f"unparseable epoch timestamp: {value!r}"
        try:
            dt = datetime.fromtimestamp(seconds, tz=timezone.utc).replace(tzinfo=None)
        except (OverflowError, OSError, ValueError):
            return None, f"unparseable epoch timestamp: {value!r}"
    elif isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            dt = None
        if dt is None:
            for pattern in _ISO_PATTERNS:
                try:
                    dt = datetime.strptime(value.strip(), pattern)
                    break
                except ValueError:
                    continue
        if dt is None:
            return None, f"unparseable timestamp: {value!r}"
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    else:
        return None, f"unsupported timestamp type: {type(value).__name__}"
    if dt.year < 1970 or dt.year > 2100:
        return None, f"timestamp out of range: {dt.isoformat()}"
    return dt, None


def _canon_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _lookup(raw: dict[str, Any], canonical: str) -> Any:
    wanted = {_canon_key(a) for a in FIELD_ALIASES[canonical]}
    wanted.add(_canon_key(canonical))
    for key, value in raw.items():
        if _canon_key(key) in wanted and value not in (None, ""):
            return value
    return None


def _coerce_int(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _normalize_type(value: Any, raw: dict[str, Any]) -> Optional[str]:
    if value is not None and str(value).strip():
        text = str(value).strip()
        if _TECHNIQUE_RE.match(text):
            return None
        key = text.lower().replace(" ", "_").replace("-", "_")
        if key in TYPE_ALIASES:
            return TYPE_ALIASES[key]
        upper = text.upper()
        if upper in EVENT_TYPES:
            return upper
        # Windows event ids sometimes appear as the event-type field
        if key in EVENT_ID_MAP:
            return EVENT_ID_MAP[key]
    # EventID style numeric field
    for candidate in ("event_id", "eventid", "event_id_numeric", "eventid_numeric", "id"):
        for k, v in raw.items():
            if _canon_key(k) == _canon_key(candidate) and str(v).strip().isdigit():
                mapped = EVENT_ID_MAP.get(str(v).strip())
                if mapped:
                    return mapped
    return None


def _normalize_severity(value: Any, event_type: str) -> str:
    if value is not None and str(value).strip():
        text = str(value).strip().upper()
        aliases = {"ERR": "HIGH", "ERROR": "HIGH", "WARNING": "MEDIUM", "WARN": "MEDIUM",
                   "NOTICE": "LOW", "INFORMATIONAL": "INFO", "INFO": "INFO"}
        text = aliases.get(text, text)
        if text in SEVERITIES:
            return text
    return DEFAULT_SEVERITY.get(event_type, "INFO")


def _truncate(value: Any, limit: int) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit]
    return value


def normalize_record(
    raw: Any,
    index: int = 0,
    source: str = "unknown",
    scenario_id: Optional[str] = None,
    max_field_length: int = 8192,
) -> tuple[Optional[dict[str, Any]], list[NormalizationIssue]]:
    """Normalize a single raw record. Returns (event_or_None, issues)."""
    issues: list[NormalizationIssue] = []
    if not isinstance(raw, dict):
        issues.append(NormalizationIssue(index, "record", None, f"record is not an object ({type(raw).__name__})"))
        return None, issues
    if not raw:
        issues.append(NormalizationIssue(index, "record", None, "empty record"))
        return None, issues

    def note(field_name: str, message: str, scope: str = "field") -> None:
        issues.append(NormalizationIssue(index, scope, field_name, message))

    event: dict[str, Any] = {
        "event_id": None,
        "timestamp": None,
        "event_type": None,
        "host": None,
        "user": None,
        "source_ip": None,
        "destination_ip": None,
        "source_port": None,
        "destination_port": None,
        "protocol": None,
        "process_name": None,
        "process_id": None,
        "parent_process": None,
        "parent_process_id": None,
        "command_line": None,
        "file_path": None,
        "file_hash": None,
        "domain": None,
        "severity": "INFO",
        "technique_id": None,
        "technique_name": None,
        "tactic": None,
        "source": source,
        "metadata": {},
        "scenario_id": scenario_id,
        "raw": raw,
    }

    # --- timestamp ---
    ts, ts_err = parse_timestamp(_lookup(raw, "timestamp"))
    if ts_err and "missing" not in ts_err:
        note("timestamp", ts_err)
    event["timestamp"] = ts
    if ts is None:
        note("timestamp", "timestamp missing or unparseable; event will sort last in timelines")

    # --- event type ---
    raw_type = _lookup(raw, "event_type")
    event_type = _normalize_type(raw_type, raw)
    if event_type is None:
        # last-chance heuristic inference from payload shape
        event_type = _infer_type_heuristic(raw)
    if event_type is None:
        note("event_type", "unable to determine event_type; record skipped", scope="record")
        return None, issues
    event["event_type"] = event_type

    # --- simple fields ---
    host = _lookup(raw, "host")
    if host:
        event["host"] = str(host).strip()[:255].lower()
    user = _lookup(raw, "user")
    if user:
        event["user"] = _canonical_user(str(user))
    for ip_field in ("source_ip", "destination_ip"):
        value = _lookup(raw, ip_field)
        if value:
            text = str(value).strip()
            if len(text) > 64:
                note(ip_field, "value too long, truncated")
            event[ip_field] = text[:64]
    for port_field in ("source_port", "destination_port"):
        value = _coerce_int(_lookup(raw, port_field))
        if value is not None and not (0 <= value <= 65535):
            note(port_field, f"port out of range: {value}")
            value = None
        event[port_field] = value
    proto = _lookup(raw, "protocol")
    if proto:
        event["protocol"] = str(proto).strip().upper()[:16]

    for proc_field in ("process_name", "parent_process"):
        value = _lookup(raw, proc_field)
        if value:
            path = str(value).strip()
            # keep only the binary name for stable cross-source comparison
            base = path.replace("\\", "/").split("/")[-1]
            event[proc_field] = (base or path)[:255]
    for pid_field in ("process_id", "parent_process_id"):
        value = _coerce_int(_lookup(raw, pid_field))
        if value is not None and value < 0:
            note(pid_field, f"negative pid ignored: {value}")
            value = None
        event[pid_field] = value
    cmd = _lookup(raw, "command_line")
    if cmd:
        event["command_line"] = str(cmd)[:max_field_length]
    fp = _lookup(raw, "file_path")
    if fp:
        event["file_path"] = str(fp)[:1024]
    fh = _lookup(raw, "file_hash")
    if fh:
        event["file_hash"] = str(fh).lower()[:128]
    dom = _lookup(raw, "domain")
    if dom:
        event["domain"] = str(dom).strip().lower()[:255]

    # --- technique / tactic passthrough ---
    tech = _lookup(raw, "technique_id")
    if tech:
        tech_text = str(tech).strip().upper()
        if _TECHNIQUE_RE.match(tech_text):
            event["technique_id"] = tech_text
        else:
            note("technique_id", f"invalid technique id: {tech!r}")
    tech_name = _lookup(raw, "technique_name")
    if tech_name:
        event["technique_name"] = str(tech_name)[:255]
    tactic = _lookup(raw, "tactic")
    if tactic:
        event["tactic"] = str(tactic).strip().upper()[:64]

    src = _lookup(raw, "source")
    if src:
        event["source"] = str(src).strip()[:64].lower()

    meta = _lookup(raw, "metadata")
    if isinstance(meta, dict):
        event["metadata"] = {str(k)[:64]: _truncate(v, 512) for k, v in list(meta.items())[:32]}
    elif meta:
        event["metadata"] = {"note": str(meta)[:512]}

    # preserve source-specific fields that were not part of the canonical schema
    consumed: set[str] = set()
    for canonical, aliases in FIELD_ALIASES.items():
        wanted = {_canon_key(a) for a in aliases}
        wanted.add(_canon_key(canonical))
        for key in raw:
            if _canon_key(key) in wanted:
                consumed.add(key)
    for key in raw:
        if str(key).strip().lower() in EVENT_ID_KEYS:
            consumed.add(key)
    reserved = {"gt_id", "_gt_id", "GT"}
    leftovers = {k: v for k, v in raw.items() if k not in consumed and k not in reserved and v not in (None, "")}
    if leftovers:
        merged = dict(event["metadata"])
        for key, value in list(leftovers.items())[:24]:
            merged[str(key)[:64]] = _truncate(value, 512)
        event["metadata"] = merged

    # ground-truth tag used by the evaluation engine
    gt = raw.get("gt_id") or raw.get("_gt_id") or raw.get("GT")
    if gt:
        event["gt_id"] = str(gt)[:32]
    else:
        event["gt_id"] = None

    if not event["host"] and not event["user"] and not event["source_ip"] and not event["destination_ip"]:
        note("host", "record has no host/user/ip identity; retained but hard to correlate")

    event["severity"] = _normalize_severity(_lookup(raw, "severity"), event_type)

    # --- id ---
    given_id = _lookup_event_id(raw)
    if given_id and str(given_id).strip() and _canon_key(str(given_id)) not in {"id", "eventid"}:
        event["event_id"] = f"EVT-{str(given_id).strip()[:32]}"
    else:
        event["event_id"] = new_event_id()

    # ensure technique id shape one more time (raw "technique" key)
    return event, issues


def _canonical_user(value: str) -> str:
    text = value.strip()
    if "\\" in text:
        text = text.split("\\")[-1]
    if "@" in text:
        text = text.split("@")[0]
    return text.lower()[:255]


def _infer_type_heuristic(raw: dict[str, Any]) -> Optional[str]:
    keys = {_canon_key(k) for k in raw}
    if "queryname" in keys or "dns_query" in keys:
        return "DNS_QUERY"
    if "targetfilename" in keys or ("path" in keys and "image" not in keys):
        return "FILE_CREATED"
    if "parentimage" in keys or "parent_process" in keys:
        return "PROCESS_CREATED"
    if ("dst_port" in keys or "destination_port" in keys) and "dport" in keys:
        return "NETWORK_CONNECTION"
    return None


def normalize_records(
    records: Iterable[Any],
    source: str = "unknown",
    scenario_id: Optional[str] = None,
    max_field_length: int = 8192,
    start_index: int = 0,
) -> NormalizedBatch:
    batch = NormalizedBatch()
    for offset, raw in enumerate(records):
        index = start_index + offset
        event, issues = normalize_record(raw, index=index, source=source,
                                         scenario_id=scenario_id, max_field_length=max_field_length)
        batch.issues.extend(issues)
        if event is None:
            batch.skipped += 1
            continue
        batch.events.append(event)
    return batch
