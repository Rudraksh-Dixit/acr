"""Detection rule interfaces. Rules are transparent, deterministic and modular."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from app.core.config import Settings


@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    event: dict[str, Any]
    severity: str
    technique_id: str
    technique_name: str
    title: str
    description: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    related_event_ids: list[str] = field(default_factory=list)


class RuleContext:
    """Mutable per-run state shared by rules (e.g. login-failure counters)."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.login_failures: dict[tuple[str, str], list] = {}
        self.seen_hashes: set[str] = set()

    def record_login_failure(self, key: tuple[str, str], timestamp: Any) -> list:
        from datetime import timedelta

        window = self.settings.brute_force_window
        entries = [t for t in self.login_failures.get(key, []) if t and timestamp and (timestamp - t) <= timedelta(seconds=window)]
        if timestamp:
            entries.append(timestamp)
        self.login_failures[key] = entries[-50:]
        return entries

    def failure_count(self, key: tuple[str, str]) -> int:
        return len(self.login_failures.get(key, []))


class DetectionRule:
    """Base class for all detection rules."""

    rule_id: str = "BASE"
    rule_name: str = "Base rule"
    description: str = ""

    def evaluate(self, event: dict[str, Any], ctx: RuleContext) -> Optional[RuleMatch]:  # pragma: no cover
        raise NotImplementedError


# --- shared heuristics -----------------------------------------------------

OFFICE_PROCESSES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "visio.exe"}
SCRIPT_INTERPRETERS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
LOLBINS = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "msbuild.exe"}
EXECUTABLE_EXTENSIONS = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi")

PERSISTENCE_KEY_PATTERNS = (
    r"\\currentversion\\run",
    r"\\currentversion\\runonce",
    r"\\currentversion\\runservices",
    r"\\windows nt\\currentversion\\winlogon",
    r"\\image file execution options\\",
    r"\\currentversion\\shell",
    r"\\currentversion\\userinit",
    r"\\services\\",
    r"\\explorer\\run",
)

BENIGN_POWERSHELL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("benign cmdlet", re.compile(r"get-(service|process|date|childitem|eventlog|computerinfo|aduser|mailbox|volume|help|command|history)", re.I)),
    ("benign cmdlet", re.compile(r"test-connection|restart-service|out-gridview|invoke-item", re.I)),
    ("policy set to remoteSigned", re.compile(r"set-executionpolicy\s+remotesigned", re.I)),
]

SUSPICIOUS_POWERSHELL_PATTERNS: list[tuple[str, re.Pattern[str], bool]] = [
    # (display name, pattern, high_risk)
    ("encoded command", re.compile(r"(?<![\w-])-(enc|encodedcommand|ec)(?![\w-])", re.I), True),
    ("base64 payload", re.compile(r"frombase64string", re.I), True),
    ("download cradle", re.compile(r"downloadstring|downloadfile|net\.webclient|start-bitstransfer", re.I), True),
    ("invoke-expression", re.compile(r"(?<![\w-])iex(?![\w-])|invoke-expression", re.I), True),
    ("remote download", re.compile(r"invoke-webrequest", re.I), False),
    ("execution policy bypass", re.compile(r"(?<![\w-])bypass(?![\w-])", re.I), False),
    ("noprofile flag", re.compile(r"(?<![\w-])-nop(?![\w-])", re.I), False),
    ("hidden window", re.compile(r"(?<![\w-])-w(indowstyle)?\s+hidden(?![\w-])|windowstyle\s+hidden", re.I), False),
    ("amsi/exclusion tampering", re.compile(r"amsiinitfailed|amsiutils|add-mppreference|exclusionpath", re.I), True),
    ("remote session cmdlets", re.compile(r"invoke-command|enter-pssession", re.I), False),
    ("in-memory API calls", re.compile(r"virtualalloc|getprocaddress|writeprocessmemory|createthread", re.I), True),
]

_ENCODED_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")


def suspicious_powershell_markers(command: str) -> tuple[list[str], bool]:
    """Return (matched indicators, any_high_risk)."""
    matched: list[str] = []
    high_risk = False
    for name, pattern, is_high in SUSPICIOUS_POWERSHELL_PATTERNS:
        if pattern.search(command):
            matched.append(name)
            high_risk = high_risk or is_high
    return matched, high_risk


def _cmd(event: dict[str, Any]) -> str:
    return (event.get("command_line") or "").lower()


def _path(event: dict[str, Any]) -> str:
    return (event.get("file_path") or "").lower()


def _proc(event: dict[str, Any]) -> str:
    return (event.get("process_name") or "").lower()


def _parent(event: dict[str, Any]) -> str:
    return (event.get("parent_process") or "").lower()


def is_benign_powershell(event: dict[str, Any]) -> bool:
    """True when a PowerShell command shows only benign administrative
    markers and no malicious indicators - keeps 'benign PowerShell' benign."""
    command = event.get("command_line") or ""
    if not command:
        return False
    markers, _ = suspicious_powershell_markers(command)
    if markers:
        return False
    return any(pattern.search(command) for _, pattern in BENIGN_POWERSHELL_PATTERNS)


def evidence(field_name: str, value: Any, why: str) -> dict[str, Any]:
    return {"field": field_name, "value": value if isinstance(value, (str, int, float, bool)) else str(value)[:500], "why": why}


def make_match(
    rule: DetectionRule,
    event: dict[str, Any],
    severity: str,
    technique_id: str,
    technique_name: str,
    title: str,
    description: str,
    ev: list[dict[str, Any]],
    related: Optional[list[str]] = None,
) -> RuleMatch:
    return RuleMatch(
        rule_id=rule.rule_id,
        rule_name=rule.rule_name,
        event=event,
        severity=severity,
        technique_id=technique_id,
        technique_name=technique_name,
        title=title,
        description=description,
        evidence=ev,
        related_event_ids=related or [],
    )
