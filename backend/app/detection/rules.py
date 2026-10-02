"""Registry persistence, service installation and remote-execution rules."""
from __future__ import annotations

from typing import Any, Optional

from app.detection.base import (
    PERSISTENCE_KEY_PATTERNS,
    DetectionRule,
    RuleContext,
    RuleMatch,
    evidence,
    make_match,
)

import re

_TEMP_PATH = re.compile(r"(\\temp\\|/temp/|\\appdata\\local\\temp|\\users\\public\\|\\programdata\\)", re.I)


class RegistryPersistenceRule(DetectionRule):
    rule_id = "REGISTRY_PERSISTENCE"
    rule_name = "Registry persistence key modification"
    description = "Write to an autostart registry key (Run/RunOnce/Winlogon/Services/IFEO)."

    def evaluate(self, event: dict[str, Any], ctx: RuleContext) -> Optional[RuleMatch]:
        if event.get("event_type") != "REGISTRY_MODIFIED":
            return None
        target = (event.get("file_path") or "") + " " + (event.get("command_line") or "")
        target_lower = target.lower()
        hit = next((p for p in PERSISTENCE_KEY_PATTERNS if re.search(p, target_lower)), None)
        if not hit:
            return None
        key = hit.replace("\\\\", "\\")
        return make_match(
            self, event, severity="HIGH", technique_id="T1547.001",
            technique_name="Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
            title="Persistence registry key modified",
            description=f"Registry persistence location '{key}' was modified on {event.get('host')}.",
            ev=[evidence("file_path", event.get("file_path"), "persistence registry key"),
                evidence("process_name", event.get("process_name"), "process writing the key"),
                evidence("command_line", event.get("command_line"), "value written"),
                evidence("host", event.get("host"), "affected host")],
        )


class ServiceInstallRule(DetectionRule):
    rule_id = "SUSPICIOUS_SERVICE_INSTALL"
    rule_name = "Suspicious service installation"
    description = "A service was created with a binary in a user-writable/temp path."

    def evaluate(self, event: dict[str, Any], ctx: RuleContext) -> Optional[RuleMatch]:
        if event.get("event_type") != "SERVICE_CREATED":
            return None
        target = event.get("file_path") or event.get("command_line") or ""
        suspicious_path = bool(_TEMP_PATH.search(target)) or target.lower().endswith((".exe", ".bat", ".cmd", ".dll"))
        if not suspicious_path:
            return None
        return make_match(
            self, event, severity="HIGH", technique_id="T1543.003",
            technique_name="Create or Modify System Process: Windows Service",
            title=f"Suspicious service installed on {event.get('host')}",
            description=f"A service was created pointing at '{target[:200]}', commonly used for persistence or lateral movement.",
            ev=[evidence("file_path", event.get("file_path"), "service binary path"),
                evidence("command_line", event.get("command_line"), "service definition"),
                evidence("process_name", event.get("process_name"), "installing process"),
                evidence("host", event.get("host"), "affected host")],
        )


class RemoteExecutionRule(DetectionRule):
    rule_id = "REMOTE_EXECUTION"
    rule_name = "Remote execution observed"
    description = "Remote command execution (PsExec/WMI/WinRM style) telemetry."

    def evaluate(self, event: dict[str, Any], ctx: RuleContext) -> Optional[RuleMatch]:
        if event.get("event_type") != "REMOTE_EXECUTION":
            return None
        meta = event.get("metadata") or {}
        method = str(meta.get("method", "")).lower() if isinstance(meta, dict) else ""
        protocol = (event.get("protocol") or "").lower()
        if "winrm" in method or protocol in {"winrm", "http", "https"}:
            technique, name = "T1021.006", "Remote Services: Windows Remote Management"
        elif "wmi" in method:
            technique, name = "T1047", "Windows Management Instrumentation"
        else:
            technique, name = "T1021.002", "Remote Services: SMB/Windows Admin Shares"
        return make_match(
            self, event, severity="HIGH", technique_id=technique, technique_name=name,
            title=f"Remote execution on {event.get('host') or 'host'}",
            description=f"Remote execution {'via ' + method + ' ' if method else ''}observed"
                        f"{' from ' + str(event.get('source_ip')) if event.get('source_ip') else ''}.",
            ev=[evidence("host", event.get("host"), "target host"),
                evidence("source_ip", event.get("source_ip"), "operator source"),
                evidence("user", event.get("user"), "authenticating account"),
                evidence("command_line", event.get("command_line"), "executed command"),
                evidence("metadata", meta, "execution method")],
        )


class ScheduledTaskRule(DetectionRule):
    rule_id = "SCHEDULED_TASK_CREATED"
    rule_name = "Scheduled task / cron persistence"
    description = "A scheduled task was registered."

    def evaluate(self, event: dict[str, Any], ctx: RuleContext) -> Optional[RuleMatch]:
        if event.get("event_type") not in {"SERVICE_CREATED", "FILE_CREATED", "REGISTRY_MODIFIED", "PROCESS_CREATED"}:
            return None
        text = ((event.get("file_path") or "") + " " + (event.get("command_line") or "")).lower()
        if "\\tasks\\" not in text and "/create" not in text and "/tn " not in text and "schtasks /create" not in text:
            return None
        return make_match(
            self, event, severity="HIGH", technique_id="T1053.005",
            technique_name="Scheduled Task/Job: Scheduled Task",
            title="Scheduled task created",
            description="Telemetry shows registration of a scheduled task, a common persistence mechanism.",
            ev=[evidence("file_path", event.get("file_path"), "task definition"),
                evidence("command_line", event.get("command_line"), "creation command")],
        )


class CredentialDumpingToolRule(DetectionRule):
    rule_id = "CREDENTIAL_DUMPING_TOOL"
    rule_name = "Credential dumping tool execution"
    description = "Known credential-dumper tooling or LSASS dump pattern."

    DUMPERS = {"mimikatz.exe", "procdump.exe", "lazagne.exe", "invoke-mimikatz", "nanodump.exe", "sharpdump.exe"}

    def evaluate(self, event: dict[str, Any], ctx: RuleContext) -> Optional[RuleMatch]:
        if event.get("event_type") not in {"PROCESS_CREATED", "FILE_CREATED"}:
            return None
        name = (event.get("process_name") or "").lower()
        command = (event.get("command_line") or "").lower()
        path = (event.get("file_path") or "").lower()
        dump_pattern = "lsass" in command or "comsvcs" in command or "minidump" in command
        if name not in self.DUMPERS and not dump_pattern:
            return None
        return make_match(
            self, event, severity="CRITICAL", technique_id="T1003.001",
            technique_name="OS Credential Dumping: LSASS Memory",
            title=f"Credential dumping activity: {name or path.split(chr(92))[-1] or 'dump'}",
            description="A credential-dumping pattern (LSASS access or known dumper) was observed - "
                        "an attacker may already hold plaintext credentials.",
            ev=[evidence("process_name", name, "credential dumper"),
                evidence("command_line", event.get("command_line"), "dump command"),
                evidence("parent_process", event.get("parent_process"), "launching process"),
                evidence("host", event.get("host"), "affected host")],
        )


GENERIC_RULES: list[DetectionRule] = [
    RegistryPersistenceRule(),
    ServiceInstallRule(),
    RemoteExecutionRule(),
    ScheduledTaskRule(),
    CredentialDumpingToolRule(),
]
