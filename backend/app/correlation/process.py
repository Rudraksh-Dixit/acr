"""Process-lineage correlation: parent/child and shared-actor relationships."""
from __future__ import annotations

from typing import Any, Optional

from app.ingestion.entity_extractor import process_entity_value


def _host(event: dict[str, Any]) -> str:
    return str(event.get("host") or "").lower()


def _pid(value: Any) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def process_link(a: dict[str, Any], b: dict[str, Any]) -> Optional[str]:
    """Return a description when two events are linked through process lineage.

    Cases:
      * direct parent/child: a's process id == b's parent process id (same host)
      * same actor: both events were produced by the same running process
      * spawned binary: a created the file that b executes on the same host
    """
    if _host(a) != _host(b) or not _host(a):
        # lineage requires a shared host unless both lack one entirely
        if _host(a) or _host(b):
            return None

    a_pid, a_ppid = _pid(a.get("process_id")), _pid(a.get("parent_process_id"))
    b_pid, b_ppid = _pid(b.get("process_id")), _pid(b.get("parent_process_id"))

    if a_pid is not None and b_ppid is not None and a_pid == b_ppid:
        an = a.get("process_name") or f"pid {a_pid}"
        bn = b.get("process_name") or f"pid {b_pid}"
        return f"{an} (pid {a_pid}) spawned {bn} (pid {b_ppid})"
    if b_pid is not None and a_ppid is not None and b_pid == a_ppid:
        an = a.get("process_name") or f"pid {a_pid}"
        bn = b.get("process_name") or f"pid {b_pid}"
        return f"{bn} (pid {b_pid}) spawned {an} (pid {a_ppid})"

    a_proc = process_entity_value(a.get("host"), a.get("process_name"))
    b_proc = process_entity_value(b.get("host"), b.get("process_name"))
    if a_proc and b_proc and a_proc == b_proc:
        return f"both events produced by {a_proc.split(':', 1)[-1]}"

    # a dropped a file that b runs (create -> execute on same host)
    a_file = str(a.get("file_path") or "").lower()
    b_cmd = str(b.get("command_line") or "").lower()
    b_proc_name = str(b.get("process_name") or "").lower()
    if a_file and a.get("event_type") == "FILE_CREATED":
        base = a_file.replace("\\", "/").split("/")[-1]
        if base and (base in b_cmd or base == b_proc_name):
            return f"created file {base} was executed by {b.get('process_name') or 'process'}"
    b_file = str(b.get("file_path") or "").lower()
    a_cmd = str(a.get("command_line") or "").lower()
    a_proc_name = str(a.get("process_name") or "").lower()
    if b_file and b.get("event_type") == "FILE_CREATED":
        base = b_file.replace("\\", "/").split("/")[-1]
        if base and (base in a_cmd or base == a_proc_name):
            return f"created file {base} was executed by {a.get('process_name') or 'process'}"
    return None
