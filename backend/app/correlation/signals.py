"""Signal definitions and pairwise scoring.

Each signal contributes a measurable, explainable number of points. The
granular signals roll up into the documented primary signals:

    shared_network_entity = same_source_ip + same_destination_ip + shared_domain
    sequence_match        = event_dependency
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from app.core.config import WEIGHT_GROUPS, Settings, settings as default_settings
from app.correlation import process as process_sig
from app.correlation import technique as technique_sig
from app.correlation.entity import shared_entities
from app.correlation.temporal import classify_delta, decay_for, delta_seconds, get_timestamp

GROUP_ORDER = (
    "temporal",
    "same_host",
    "same_user",
    "shared_network_entity",
    "process_relationship",
    "shared_file",
    "attack_progression",
    "sequence_match",
)


@dataclass
class SignalContribution:
    signal: str
    group: str
    weight: float
    points: float
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal": self.signal,
            "group": self.group,
            "weight": round(self.weight, 1),
            "points": round(self.points, 1),
            "detail": self.detail,
        }


@dataclass
class PairScore:
    event_a: str
    event_b: str
    total: float
    contributions: list[SignalContribution] = field(default_factory=list)
    window: Optional[str] = None

    @property
    def groups(self) -> set[str]:
        return {c.group for c in self.contributions if c.points > 0}

    @property
    def has_non_temporal_host_evidence(self) -> bool:
        """Spec rule: never correlate on 'same machine + time' alone."""
        return bool(self.groups - {"temporal", "same_host"})

    def group_points(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for c in self.contributions:
            out[c.group] = out.get(c.group, 0.0) + c.points
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_a": self.event_a,
            "event_b": self.event_b,
            "total": round(self.total, 1),
            "window": self.window,
            "contributions": [c.to_dict() for c in self.contributions],
        }


def _dependency_detail(a: dict[str, Any], b: dict[str, Any]) -> Optional[str]:
    """Logical ordering between two events (created -> executed, auth -> run...)."""
    if a.get("host") and b.get("host") and str(a["host"]).lower() != str(b["host"]).lower():
        return None
    ts_a, ts_b = get_timestamp(a), get_timestamp(b)
    first, second = (a, b)
    if ts_a and ts_b and ts_b < ts_a:
        first, second = b, a

    first_file = str(first.get("file_path") or "")
    if first.get("event_type") == "FILE_CREATED" and first_file:
        base = first_file.replace("\\", "/").split("/")[-1].lower()
        cmd = str(second.get("command_line") or "").lower()
        proc = str(second.get("process_name") or "").lower()
        if base and (base in cmd or base == proc):
            return f"file '{base}' created then referenced by {second.get('process_name') or 'next event'}"

    if first.get("event_type") in {"LOGIN_SUCCESS", "AUTHENTICATION"} and second.get("event_type") in {
        "PROCESS_CREATED", "REMOTE_EXECUTION", "FILE_CREATED", "REGISTRY_MODIFIED"
    }:
        if first.get("user") and second.get("user") and str(first["user"]).lower() == str(second["user"]).lower():
            return f"user '{first['user']}' authenticated then performed {second.get('event_type')}"

    if first.get("event_type") == "DNS_QUERY" and second.get("event_type") in {"FILE_CREATED", "NETWORK_CONNECTION"}:
        domain = str(first.get("domain") or "").lower()
        cmd2 = str(second.get("command_line") or "").lower()
        if domain and domain in cmd2:
            return f"resolved '{domain}' then used it in {second.get('event_type')}"

    if first.get("event_type") == "NETWORK_CONNECTION" and second.get("event_type") == "FILE_CREATED":
        ip = str(first.get("destination_ip") or "")
        cmd2 = str(second.get("command_line") or "").lower()
        if ip and ip in cmd2:
            return f"connected to {ip} then wrote a file referencing it"

    if first.get("event_type") == "PROCESS_CREATED" and second.get("event_type") == "REGISTRY_MODIFIED":
        proc = str(first.get("process_name") or "").lower()
        cmd2 = str(second.get("command_line") or "").lower()
        if proc and proc in cmd2:
            return f"'{proc}' executed then modified registry"
    return None


def score_pair(
    a: dict[str, Any],
    b: dict[str, Any],
    settings: Settings | None = None,
) -> PairScore:
    cfg = settings or default_settings
    weights = cfg.weights
    contributions: list[SignalContribution] = []

    def group_of(signal: str) -> str:
        for group, signals in WEIGHT_GROUPS.items():
            if signal in signals:
                return group
        return signal

    def add(signal: str, points: float, detail: str) -> None:
        if points <= 0:
            return
        weight = float(weights.get(signal, 0))
        contributions.append(SignalContribution(signal, group_of(signal), weight, round(points, 2), detail))

    # 1) temporal
    delta = delta_seconds(a, b)
    window = classify_delta(delta, cfg)
    temporal_points = 0.0
    if window:
        temporal_points = weights.get("temporal", 0) * decay_for(delta, cfg)
        add("temporal", temporal_points, f"events are {delta:.0f}s apart ({window} window)")

    # 2) entity signals
    shared = shared_entities(a, b)
    detail_templates = {
        "same_host": "same host {value}",
        "same_user": "same user {value}",
        "same_source_ip": "same source IP {value}",
        "same_destination_ip": "same destination IP {value}",
        "shared_domain": "same domain {value}",
        "shared_file": "shared file {value}",
    }
    for signal, value in shared.items():
        weight = float(weights.get(signal, 0))
        template = detail_templates.get(signal, "shared {signal}")
        add(signal, weight, template.format(value=value))

    # 3) process lineage
    lineage = process_sig.process_link(a, b)
    if lineage:
        add("process_relationship", float(weights.get("process_relationship", 0)), lineage)

    # 4) attack progression
    factor, detail = technique_sig.progression(a, b)
    if factor is not None:
        add("attack_progression", weights.get("attack_progression", 0) * factor, detail)

    # 5) logical event dependency
    dep = _dependency_detail(a, b)
    if dep:
        add("event_dependency", float(weights.get("event_dependency", 0)), dep)

    total = round(sum(c.points for c in contributions), 2)
    return PairScore(
        event_a=a.get("event_id", ""),
        event_b=b.get("event_id", ""),
        total=total,
        contributions=contributions,
        window=window,
    )
