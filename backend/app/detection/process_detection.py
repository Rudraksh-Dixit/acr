"""Process-centric detection rules (script execution, office chains, LOLBins, file drops)."""
from __future__ import annotations

from typing import Any, Optional

from app.detection.base import (
    EXECUTABLE_EXTENSIONS,
    LOLBINS,
    OFFICE_PROCESSES,
    SCRIPT_INTERPRETERS,
    DetectionRule,
    RuleContext,
    RuleMatch,
    evidence,
    is_benign_powershell,
    make_match,
    suspicious_powershell_markers,
)


class OfficeSpawnsShellRule(DetectionRule):
    rule_id = "OFFICE_SPAWNS_POWERSHELL"
    rule_name = "Office application spawned a script shell"
    description = "A Microsoft Office process launched PowerShell - a common macro-exploitation pattern."

    def evaluate(self, event: dict[str, Any], ctx: RuleContext) -> Optional[RuleMatch]:
        if event.get("event_type") != "PROCESS_CREATED":
            return None
        parent = (event.get("parent_process") or "").lower()
        child = (event.get("process_name") or "").lower()
        if parent not in OFFICE_PROCESSES or child not in {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe"}:
            return None
        return make_match(
            self, event, severity="HIGH", technique_id="T1059.001",
            technique_name="Command and Scripting Interpreter: PowerShell",
            title=f"{parent} spawned {child}",
            description=f"Microsoft Word/Office component '{parent}' spawned '{child}' on {event.get('host')}.",
            ev=[evidence("parent_process", parent, "office application as parent"),
                evidence("process_name", child, "script interpreter as child"),
                evidence("command_line", event.get("command_line"), "child command line"),
                evidence("host", event.get("host"), "affected host")],
        )


class EncodedPowerShellRule(DetectionRule):
    rule_id = "ENCODED_POWERSHELL"
    rule_name = "Encoded PowerShell command"
    description = "PowerShell invoked with -EncodedCommand or a large Base64 blob."

    def evaluate(self, event: dict[str, Any], ctx: RuleContext) -> Optional[RuleMatch]:
        if event.get("event_type") != "PROCESS_CREATED":
            return None
        child = (event.get("process_name") or "").lower()
        if child not in {"powershell.exe", "pwsh.exe"}:
            return None
        command = event.get("command_line") or ""
        lowered = command.lower()
        has_flag = any(flag in lowered for flag in ("-enc", "-encodedcommand", "-ec "))
        has_blob = bool(__import__("re").search(r"[A-Za-z0-9+/]{120,}={0,2}", command))
        if not (has_flag or has_blob):
            return None
        return make_match(
            self, event, severity="HIGH", technique_id="T1027",
            technique_name="Obfuscated Files or Information",
            title="Encoded PowerShell execution",
            description="PowerShell was launched with an encoded command, a common payload-obfuscation technique.",
            ev=[evidence("command_line", command[:400], "encoded/obfuscated payload"),
                evidence("process_name", child, "interpreter used"),
                evidence("technique", "T1027", "MITRE technique (obfuscation)")],
        )


class SuspiciousPowerShellRule(DetectionRule):
    rule_id = "SUSPICIOUS_POWERSHELL"
    rule_name = "Suspicious PowerShell behavior"
    description = "PowerShell used for download cradles, evasion flags or execution-policy bypass."
    benign_guard = True

    def evaluate(self, event: dict[str, Any], ctx: RuleContext) -> Optional[RuleMatch]:
        if event.get("event_type") != "PROCESS_CREATED":
            return None
        child = (event.get("process_name") or "").lower()
        if child not in {"powershell.exe", "pwsh.exe"}:
            return None
        if is_benign_powershell(event):
            return None
        command = event.get("command_line") or ""
        markers, high_risk = suspicious_powershell_markers(command)
        if not markers:
            return None
        severity = "HIGH" if high_risk else "MEDIUM"
        return make_match(
            self, event, severity=severity, technique_id="T1059.001",
            technique_name="Command and Scripting Interpreter: PowerShell",
            title="Suspicious PowerShell invocation",
            description="PowerShell ran with evasion or remote-loading indicators and no benign administrative markers.",
            ev=[evidence("command_line", event.get("command_line"), f"suspicious indicators: {', '.join(markers[:5])}"),
                evidence("parent_process", event.get("parent_process"), "process that spawned PowerShell"),
                evidence("host", event.get("host"), "affected host")],
        )


class SuspiciousLolbinRule(DetectionRule):
    rule_id = "SUSPICIOUS_LOLBIN"
    rule_name = "Living-off-the-land binary execution"
    description = "rundll32/regsvr32/mshta/certutil executed with unusual arguments."

    def evaluate(self, event: dict[str, Any], ctx: RuleContext) -> Optional[RuleMatch]:
        if event.get("event_type") != "PROCESS_CREATED":
            return None
        child = (event.get("process_name") or "").lower()
        if child not in LOLBINS:
            return None
        command = (event.get("command_line") or "").lower()
        suspicious_args = ("http", "urlcache", "-ml", "javascript:", "vbscript:", "\\\\", "/i ", "hidden", "scrobj")
        if not any(arg in command for arg in suspicious_args):
            return None
        technique, name = "T1218", "System Binary Proxy Execution"
        if child == "certutil.exe":
            technique, name = "T1105", "Ingress Tool Transfer"
        return make_match(
            self, event, severity="HIGH", technique_id=technique, technique_name=name,
            title=f"Suspicious {child} execution",
            description=f"{child} executed with arguments consistent with payload proxying/downloading.",
            ev=[evidence("process_name", child, "LOLBin"),
                evidence("command_line", event.get("command_line"), "suspicious arguments"),
                evidence("parent_process", event.get("parent_process"), "parent process")],
        )


class ExecutableCreationRule(DetectionRule):
    rule_id = "SUSPICIOUS_EXECUTABLE_CREATION"
    rule_name = "Executable written to disk"
    description = "An executable or script was created, especially by a script interpreter or in a persistence location."

    def evaluate(self, event: dict[str, Any], ctx: RuleContext) -> Optional[RuleMatch]:
        if event.get("event_type") != "FILE_CREATED":
            return None
        path = (event.get("file_path") or "").lower()
        if not path.endswith(EXECUTABLE_EXTENSIONS):
            return None
        parent = (event.get("parent_process") or "").lower()
        proc = (event.get("process_name") or "").lower()
        actor = proc or parent
        startup = "\\startup" in path or "/startup" in path
        suspicious_writer = actor in SCRIPT_INTERPRETERS or actor in LOLBINS or actor in {"svchost.exe", "wscript.exe", "msiexec.exe"}
        if not startup and not suspicious_writer and not any(seg in path for seg in ("\\temp\\", "/temp/", "\\appdata\\", "\\users\\public\\")):
            return None
        if startup:
            return make_match(
                self, event, severity="HIGH", technique_id="T1547.001",
                technique_name="Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                title="Executable placed in startup location",
                description=f"'{path}' was written to an autostart location by {actor or 'unknown process'}.",
                ev=[evidence("file_path", event.get("file_path"), "persistence location"),
                    evidence("parent_process", actor, "writing process"),
                    evidence("host", event.get("host"), "affected host")],
            )
        severity = "HIGH" if suspicious_writer else "MEDIUM"
        return make_match(
            self, event, severity=severity, technique_id="T1105",
            technique_name="Ingress Tool Transfer",
            title=f"Executable/script written: {path.split('/')[-1].split(chr(92))[-1]}",
            description=f"{actor or 'unknown process'} created executable content at '{path}'.",
            ev=[evidence("file_path", event.get("file_path"), "newly written executable"),
                evidence("parent_process", actor, "writing process"),
                evidence("host", event.get("host"), "affected host")],
        )


class RemovableOrUserDirScriptRule(DetectionRule):  # kept for extension parity
    rule_id = "SCRIPT_IN_USER_DIRECTORY"
    rule_name = "Script executed from user-writable directory"
    description = "A script interpreter executed content from AppData/Temp."

    def evaluate(self, event: dict[str, Any], ctx: RuleContext) -> Optional[RuleMatch]:
        if event.get("event_type") != "PROCESS_CREATED":
            return None
        child = (event.get("process_name") or "").lower()
        if child not in {"powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}:
            return None
        command = (event.get("command_line") or "").lower()
        if not any(seg in command for seg in ("\\appdata\\", "\\temp\\", "\\users\\public\\", "%temp%")):
            return None
        if child == "powershell.exe" and is_benign_powershell(event):
            return None
        return make_match(
            self, event, severity="MEDIUM", technique_id="T1059.001",
            technique_name="Command and Scripting Interpreter: PowerShell",
            title=f"{child} executed content from a user-writable directory",
            description="Script interpreter ran a file located in a world-writable/user directory.",
            ev=[evidence("command_line", event.get("command_line"), "path in user-writable location"),
                evidence("process_name", child, "interpreter")],
        )


PROCESS_RULES: list[DetectionRule] = [
    OfficeSpawnsShellRule(),
    EncodedPowerShellRule(),
    SuspiciousPowerShellRule(),
    SuspiciousLolbinRule(),
    ExecutableCreationRule(),
    RemovableOrUserDirScriptRule(),
]
