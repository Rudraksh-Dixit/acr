"""Scenario LAT-001: credential access -> lateral movement -> remote execution."""
from __future__ import annotations

from app.scenarios.base import Ctx, register

OPERATOR_IP = "10.0.0.15"
TARGET = "win-12.corp.local"
SOURCE_HOST = "win-11.corp.local"
ACCOUNT = "svc_backup"
C2_IP = "45.155.205.23"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def generate(ctx: Ctx) -> tuple[list[dict], dict]:
    events: list[dict] = []

    # 1) credential dumping on the first host
    events.append(ctx.ev(
        "E1", 0, EventID=1, Computer=SOURCE_HOST, User=ACCOUNT,
        Image="C:\\Tools\\mimikatz.exe",
        ParentImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        CommandLine="mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
        ProcessId=2400, ParentProcessId=2300, source="sysmon",
    ))

    # 2) operator authenticates from an internal workstation address
    events.append(ctx.ev("E2", 8, event_time=ctx.ts(8), computer=SOURCE_HOST, account_name=ACCOUNT,
                         src_ip=OPERATOR_IP, action="successful_logon", logon_type=3,
                         source="windows-security"))

    # 3) SMB connection toward the second host
    events.append(ctx.ev("E3", 12, EventID=3, Computer=SOURCE_HOST, User=ACCOUNT,
                         Image="C:\\Windows\\System32\\svchost.exe",
                         ProcessId=900, DestinationIp="10.0.0.22", DestinationPort=445,
                         Protocol="tcp", source="sysmon"))

    # 4) remote execution lands on the target host (PsExec-style)
    events.append(ctx.ev(
        "E4", 16, event_time=ctx.ts(16), computer=TARGET, account_name=ACCOUNT,
        src_ip=OPERATOR_IP, action="remote_execution", method="psexec",
        command_line="cmd.exe /c whoami /groups", source="windows-security",
    ))

    # 5) service creation used for execution
    events.append(ctx.ev("E5", 18, event_time=ctx.ts(18), computer=TARGET, account_name=ACCOUNT,
                         action="service_installed", service_name="PSEXESVC",
                         service_path="C:\\Windows\\PSEXESVC.exe", source="windows-security"))

    # 6) PowerShell runs on the target under the remote session
    events.append(ctx.ev(
        "E6", 22, EventID=1, Computer=TARGET, User=ACCOUNT,
        Image=PS,
        ParentImage="C:\\Windows\\System32\\services.exe",
        CommandLine="powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"whoami /all; ipconfig /all\"",
        ProcessId=3300, ParentProcessId=700, source="sysmon",
    ))

    # 7) stage a second-stage binary on the target
    events.append(ctx.ev("E7", 27, EventID=11, Computer=TARGET, User=ACCOUNT,
                         TargetFilename="C:\\Windows\\Temp\\svc_host.exe",
                         Image=PS, ProcessId=3300, source="sysmon"))

    # 8) outbound beacon from the target
    events.append(ctx.ev("E8", 33, EventID=3, Computer=TARGET, User=ACCOUNT,
                         Image=PS, ProcessId=3300, DestinationIp=C2_IP, DestinationPort=443,
                         Protocol="tcp", source="sysmon"))

    ground_truth = {
        "chain_events": [f"E{i}" for i in range(1, 9)],
        "techniques": ["T1003.001", "T1021.002", "T1543.003", "T1059.001", "T1105", "T1071.001"],
        "tactics": ["CREDENTIAL ACCESS", "LATERAL MOVEMENT", "PERSISTENCE", "EXECUTION",
                    "COMMAND AND CONTROL"],
        "narrative": "Credentials dumped on WIN-01, reused to execute remotely on WIN-02 via a "
                     "service, staging a payload that beacons out.",
        "primary_host": TARGET,
        "attacker_ip": OPERATOR_IP,
    }
    return events, ground_truth


register(
    "LAT-001",
    "Lateral Movement via Remote Services",
    "Credential dumping -> SMB lateral movement -> remote execution/service -> payload -> C2.",
    False,
    generate,
)
