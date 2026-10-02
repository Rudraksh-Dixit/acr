"""Benign office activity scenario - must not produce attack chains."""
from __future__ import annotations

from app.scenarios.base import Ctx, register

HOST = "win-05.corp.local"
USER = "jsmith"
OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"


def generate(ctx: Ctx) -> tuple[list[dict], dict]:
    events: list[dict] = []

    events.append(ctx.ev("E1", 0, Time=ctx.ts(0), EventID=4624, Computer=HOST, User=USER,
                         IpAddress="10.0.0.15", LogonType=2, source="windows-security"))
    events.append(ctx.ev("E2", 12, Time=ctx.ts(12), EventID=1, Computer=HOST, User=USER,
                         Image=OFFICE, ParentImage="C:\\Windows\\explorer.exe",
                         CommandLine=f'"{OFFICE}" /n "C:\\Users\\{USER}\\Documents\\Q4-plan.docx"',
                         ProcessId=5000, ParentProcessId=2000, source="sysmon"))
    events.append(ctx.ev("E3", 16, Time=ctx.ts(16), EventID=11, Computer=HOST, User=USER,
                         TargetFilename=f"C:\\Users\\{USER}\\Documents\\Q4-plan.docx",
                         Image=OFFICE, ProcessId=5000, source="sysmon"))
    events.append(ctx.ev("E4", 21, Time=ctx.ts(21), EventID=22, Computer=HOST, User=USER,
                         QueryName="outlook.office365.com",
                         Image="C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                         ProcessId=5100, source="sysmon"))
    events.append(ctx.ev("E5", 25, Time=ctx.ts(25), EventID=3, Computer=HOST, User=USER,
                         Image="C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                         ProcessId=5100, DestinationIp="52.96.165.34", DestinationPort=443,
                         Protocol="tcp", source="sysmon"))
    events.append(ctx.ev("E6", 31, Time=ctx.ts(31), EventID=1, Computer=HOST, User=USER,
                         Image="C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
                         ParentImage="C:\\Windows\\explorer.exe",
                         CommandLine=f'"{OFFICE.replace("WINWORD", "EXCEL")}" /n "C:\\Users\\{USER}\\Documents\\budget.xlsx"',
                         ProcessId=5200, ParentProcessId=2000, source="sysmon"))
    events.append(ctx.ev("E7", 37, Time=ctx.ts(37), EventID=13, Computer=HOST, User=USER,
                         TargetFilename="HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Security\\Trusted Documents",
                         Details="(value unchanged)", Image=OFFICE, ProcessId=5000, source="sysmon"))

    ground_truth = {
        "chain_events": [],
        "techniques": [],
        "tactics": [],
        "narrative": "Normal document editing, mail synchronization and spreadsheet work.",
        "primary_host": HOST,
    }
    return events, ground_truth


register(
    "BENIGN-OFFICE-001",
    "Benign Office Activity",
    "Normal document and mail usage - must not be classified as an attack.",
    True,
    generate,
)
