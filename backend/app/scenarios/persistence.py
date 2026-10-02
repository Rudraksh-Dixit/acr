"""Scenario PERS-001: valid account -> registry/service/task persistence."""
from __future__ import annotations

from app.scenarios.base import Ctx, register

HOST = "win-03.corp.local"
USER = "contractor"
SRC = "10.0.0.55"
PAYLOAD = "C:\\Users\\Public\\svhost.exe"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def generate(ctx: Ctx) -> tuple[list[dict], dict]:
    events: list[dict] = []

    events.append(ctx.ev("E1", 0, event_time=ctx.ts(0), computer=HOST, account_name=USER,
                         src_ip=SRC, action="successful_logon", logon_type=3,
                         source="windows-security"))

    events.append(ctx.ev(
        "E2", 6, EventID=1, Computer=HOST, User=USER,
        Image=PS, ParentImage="C:\\Windows\\explorer.exe",
        CommandLine=f'powershell.exe -NoProfile -Command "New-ItemProperty -Path \'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\' -Name \'HealthCheck\' -Value \'{PAYLOAD}\' -PropertyType String -Force"',
        ProcessId=1800, ParentProcessId=1200, source="sysmon",
    ))
    events.append(ctx.ev("E3", 9, EventID=13, Computer=HOST, User=USER,
                         TargetFilename="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\HealthCheck",
                         Details=PAYLOAD, Image=PS, ProcessId=1800, source="sysmon"))
    events.append(ctx.ev("E4", 13, EventID=11, Computer=HOST, User=USER,
                         TargetFilename=PAYLOAD, Image=PS, ProcessId=1800, source="sysmon"))
    events.append(ctx.ev("E5", 18, event_time=ctx.ts(18), computer=HOST, account_name=USER,
                         action="service_installed", service_name="HealthGuardSvc",
                         service_path=PAYLOAD, source="windows-security"))
    events.append(ctx.ev("E6", 23, EventID=13, Computer=HOST, User=USER,
                         TargetFilename="HKLM\\SYSTEM\\CurrentControlSet\\Services\\HealthGuardSvc\\ImagePath",
                         Details=PAYLOAD, Image=PAYLOAD, ProcessId=1900, source="sysmon"))
    events.append(ctx.ev("E7", 28, EventID=1, Computer=HOST, User=USER,
                         Image="C:\\Windows\\System32\\schtasks.exe",
                         ParentImage=PS,
                         CommandLine='schtasks /create /tn "HealthCheck" /tr "' + PAYLOAD + '" /sc onlogon /ru SYSTEM',
                         ProcessId=2100, ParentProcessId=1800, source="sysmon"))
    events.append(ctx.ev("E8", 34, EventID=3, Computer=HOST, User=USER,
                         Image=PAYLOAD, ProcessId=1900, DestinationIp="91.219.236.19",
                         DestinationPort=443, Protocol="tcp", source="sysmon"))

    ground_truth = {
        "chain_events": [f"E{i}" for i in range(1, 9)],
        "techniques": ["T1078", "T1547.001", "T1105", "T1543.003", "T1053.005", "T1071.001"],
        "tactics": ["PERSISTENCE", "EXECUTION", "COMMAND AND CONTROL"],
        "narrative": "A valid account establishes three persistence mechanisms (Run key, service, "
                     "scheduled task) and opens a C2 channel.",
        "primary_host": HOST,
        "attacker_ip": SRC,
    }
    return events, ground_truth


register(
    "PERS-001",
    "Persistence Multi-Technique",
    "Valid account establishes registry, service and scheduled-task persistence with C2.",
    False,
    generate,
)
