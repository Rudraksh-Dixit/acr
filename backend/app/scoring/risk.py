"""Risk scoring: how dangerous is the reconstructed activity?

Risk is intentionally separate from confidence. A tightly-correlated benign
administrative session can have high confidence and low risk.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.config import Settings, settings as default_settings

SEVERITY_POINTS = {"CRITICAL": 25, "HIGH": 18, "MEDIUM": 10, "LOW": 4, "INFO": 0}

TACTIC_FACTORS: dict[str, tuple[float, str]] = {
    "CREDENTIAL ACCESS": (15, "Credential access activity observed"),
    "PERSISTENCE": (15, "Persistence mechanism established"),
    "LATERAL MOVEMENT": (15, "Movement between hosts"),
    "COMMAND AND CONTROL": (15, "Command-and-control channel"),
    "PRIVILEGE ESCALATION": (10, "Privilege escalation attempt"),
    "DEFENSE EVASION": (8, "Defense evasion behavior"),
    "EXECUTION": (6, "Attacker-controlled execution"),
    "INITIAL ACCESS": (8, "Initial access vector"),
    "DISCOVERY": (6, "Network/host discovery"),
    "EXFILTRATION": (15, "Data exfiltration"),
    "IMPACT": (20, "Impact/destructive activity"),
}


@dataclass
class RiskResult:
    score: float
    level: str
    factors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"score": self.score, "level": self.level, "factors": self.factors}


def risk_level(score: float) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 56:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def compute_risk(
    events: list[dict[str, Any]],
    detections: list[dict[str, Any]] | None = None,
    tactics: list[str] | None = None,
    settings: Settings | None = None,
) -> RiskResult:
    cfg = settings or default_settings
    _ = cfg
    factors: list[dict[str, Any]] = []
    score = 0.0

    # 1) peak severity across events and detections
    severities = [str(e.get("severity") or "INFO").upper() for e in events]
    severities += [str(d.get("severity") or "INFO").upper() for d in (detections or [])]
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    peak = "INFO"
    for sev in severities:
        if sev in order and (peak == "INFO" or order.index(sev) > order.index(peak)):
            peak = sev
    peak_points = SEVERITY_POINTS.get(peak, 0)
    if peak_points:
        score += peak_points
        factors.append({"factor": "peak_severity", "points": peak_points, "detail": f"Highest severity: {peak}"})

    # 2) tactic-driven factors
    tactic_set = {str(t).upper() for t in (tactics or [])}
    for tactic, (points, detail) in TACTIC_FACTORS.items():
        if tactic in tactic_set:
            score += points
            factors.append({"factor": f"tactic_{tactic.replace(' ', '_').lower()}", "points": points, "detail": detail})

    # 3) blast radius
    hosts = {str(e.get("host")).lower() for e in events if e.get("host")}
    users = {str(e.get("user")).lower() for e in events if e.get("user")}
    if len(hosts) > 1:
        points = min(10.0, 4.0 * (len(hosts) - 1))
        score += points
        factors.append({"factor": "multiple_hosts", "points": points, "detail": f"{len(hosts)} hosts involved"})
    if len(users) > 1:
        points = min(8.0, 3.0 * (len(users) - 1))
        score += points
        factors.append({"factor": "multiple_users", "points": points, "detail": f"{len(users)} accounts involved"})

    # 4) technique breadth
    techniques = {e.get("technique_id") for e in events if e.get("technique_id")}
    techniques |= {d.get("technique_id") for d in (detections or []) if d.get("technique_id")}
    if techniques:
        points = float(min(10, len(techniques)))
        score += points
        factors.append(
            {"factor": "technique_count", "points": points, "detail": f"{len(techniques)} distinct ATT&CK techniques"}
        )

    final = round(min(100.0, score), 1)
    factors.sort(key=lambda f: -f["points"])
    return RiskResult(score=final, level=risk_level(final), factors=factors)
