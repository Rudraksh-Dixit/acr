"""Benign administrative PowerShell scenario - the engine must NOT flag it."""
from __future__ import annotations

from app.scenarios.base import Ctx, register

HOST = "win-04.corp.local"
USER = "helpdesk"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def generate(ctx: Ctx) -> tuple[list[dict], dict]:
    events: list[dict] = []

    events.append(ctx.ev("E1", 0, event_time=ctx.ts(0), computer=HOST, account_name=USER,
                         src_ip="10.0.0.31", action="successful_logon", logon_type=2,
                         source="windows-security"))
    events.append(ctx.ev(
        "E2", 5, EventID=1, Computer=HOST, User=USER,
        Image=PS, ParentImage="C:\\Windows\\System32\\WindowsTerminal.exe",
        CommandLine="powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -Command \"Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,Status | Format-Table -AutoSize\"",
        ProcessId=4400, ParentProcessId=1500, source="sysmon",
    ))
    events.append(ctx.ev("E3", 9, EventID=1, Computer=HOST, User=USER,
                         Image=PS, ParentImage="C:\\Windows\\System32\\WindowsTerminal.exe",
                         CommandLine="powershell.exe -NoProfile -Command \"Get-Date; Get-ComputerInfo | Select-Object OsName,OsVersion\"",
                         ProcessId=4410, ParentProcessId=1500, source="sysmon"))
    events.append(ctx.ev("E4", 14, EventID=11, Computer=HOST, User=USER,
                         TargetFilename="C:\\logs\\healthcheck-report.txt", Image=PS,
                         ProcessId=4410, source="sysmon"))
    events.append(ctx.ev("E5", 18, EventID=3, Computer=HOST, User=USER,
                         Image=PS, ProcessId=4410, DestinationIp="10.0.0.10",
                         DestinationPort=445, Protocol="tcp", source="sysmon"))
    events.append(ctx.ev("E6", 24, EventID=1, Computer=HOST, User=USER,
                         Image="C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
                         ParentImage="C:\\Windows\\explorer.exe",
                         CommandLine='"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" /n "C:\\Monitoring\\health.xlsx"',
                         ProcessId=4500, ParentProcessId=1500, source="sysmon"))

    ground_truth = {
        "chain_events": [],
        "techniques": [],
        "tactics": [],
        "narrative": "Routine health checks: admin PowerShell reading services/system info, writing a "
                     "log file, local file share access and opening a spreadsheet.",
        "primary_host": HOST,
    }
    return events, ground_truth


register(
    "PS-BENIGN-001",
    "Benign Administrative PowerShell",
    "Helpdesk runs read-only PowerShell health checks - must not be classified as an attack.",
    True,
    generate,
)
