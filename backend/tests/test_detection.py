"""Detection rule tests."""
from __future__ import annotations

from app.core.config import settings
from app.detection import run_detection
from app.ingestion.normalizer import normalize_records


def _detect(records: list[dict]):
    batch = normalize_records(records, source="test")
    return run_detection(batch.events, settings), batch.events


def test_encoded_powershell_detected_as_t1027():
    matches, _ = _detect([{
        "timestamp": "2026-01-01T10:00:00Z", "event_type": "PROCESS_CREATED",
        "host": "h1", "process_name": "powershell.exe",
        "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
    }])
    assert any(m.technique_id == "T1027" for m in matches)


def test_benign_powershell_is_not_flagged():
    matches, _ = _detect([{
        "timestamp": "2026-01-01T10:00:00Z", "event_type": "PROCESS_CREATED",
        "host": "h1", "process_name": "powershell.exe",
        "command_line": "powershell.exe Get-Process | Format-Table",
    }])
    assert matches == []


def test_office_spawning_powershell_detected():
    matches, _ = _detect([{
        "timestamp": "2026-01-01T10:00:00Z", "event_type": "PROCESS_CREATED",
        "host": "h1", "process_name": "powershell.exe", "parent_process": "winword.exe",
        "command_line": "powershell.exe -nop -c Get-ChildItem",
    }])
    assert any(m.rule_id == "OFFICE_SPAWNS_POWERSHELL" for m in matches)
    assert any(m.technique_id == "T1059.001" for m in matches)


def test_brute_force_and_success_after_failures():
    records = [
        {"timestamp": f"2026-01-01T10:00:{i:02d}Z", "event_type": "LOGIN_ATTEMPT",
         "host": "dc1", "user": "victim", "source_ip": "10.0.0.9"}
        for i in range(6)
    ]
    records.append({
        "timestamp": "2026-01-01T10:01:00Z", "event_type": "LOGIN_SUCCESS",
        "host": "dc1", "user": "victim", "source_ip": "10.0.0.9",
    })
    matches, _ = _detect(records)
    rule_ids = {m.rule_id for m in matches}
    assert "AUTH_BRUTE_FORCE" in rule_ids
    assert "AUTH_SUCCESS_AFTER_FAILURES" in rule_ids
    assert any(m.technique_id == "T1110.001" for m in matches)
    assert any(m.technique_id == "T1078" for m in matches)


def test_registry_persistence_detected():
    matches, _ = _detect([{
        "timestamp": "2026-01-01T10:00:00Z", "event_type": "REGISTRY_MODIFIED",
        "host": "h1", "user": "alice",
        "file_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
    }])
    assert any(m.rule_id == "REGISTRY_PERSISTENCE" for m in matches)
    assert any(m.technique_id == "T1547.001" for m in matches)


def test_credential_dumping_tool_detected():
    matches, _ = _detect([{
        "timestamp": "2026-01-01T10:00:00Z", "event_type": "PROCESS_CREATED",
        "host": "h1", "process_name": "mimikatz.exe",
        "command_line": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\"",
    }])
    assert any(m.rule_id == "CREDENTIAL_DUMPING_TOOL" for m in matches)
    assert any(m.technique_id == "T1003.001" for m in matches)

    matches, _ = _detect([{
        "timestamp": "2026-01-01T10:00:01Z", "event_type": "PROCESS_CREATED",
        "host": "h1", "process_name": "cmd.exe",
        "command_line": "cmd.exe /c rundll32 comsvcs.dll, MiniDump lsass.dll full.dmp",
    }])
    assert any(m.technique_id == "T1003.001" for m in matches)


def test_match_contains_evidence_and_title():
    matches, _ = _detect([{
        "timestamp": "2026-01-01T10:00:00Z", "event_type": "PROCESS_CREATED",
        "host": "h1", "process_name": "powershell.exe", "parent_process": "winword.exe",
        "command_line": "powershell.exe -nop -c Get-ChildItem",
    }])
    match = matches[0]
    assert match.title
    assert match.description
    assert isinstance(match.evidence, list) and match.evidence
    assert match.event["event_id"]
