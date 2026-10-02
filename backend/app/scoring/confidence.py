"""Confidence scoring: how strongly do the signals support 'one attack chain'?

The score is an additive aggregation of per-signal contributions measured on
the internal links of the chain, so it always comes with human-readable
reasons (never a bare number).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.config import Settings, settings as default_settings
from app.correlation.signals import PairScore

GROUP_LABELS = {
    "temporal": "Temporal proximity",
    "same_host": "Same host",
    "same_user": "Same user",
    "shared_network_entity": "Shared network entity",
    "process_relationship": "Parent-child process relationship",
    "shared_file": "Shared file",
    "attack_progression": "ATT&CK sequence consistency",
    "sequence_match": "Event dependency / sequence match",
}


@dataclass
class ConfidenceResult:
    score: float
    reasons: list[dict[str, Any]] = field(default_factory=list)
    links_analyzed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "reasons": self.reasons,
            "links_analyzed": self.links_analyzed,
        }


def _group_points(edge: PairScore) -> dict[str, float]:
    out: dict[str, float] = {}
    for contribution in edge.contributions:
        out[contribution.group] = out.get(contribution.group, 0.0) + contribution.points
    return out


def compute_confidence(
    chain_event_ids: list[str],
    edges: list[PairScore],
    settings: Settings | None = None,
    chain_mean_link: float | None = None,
) -> ConfidenceResult:
    cfg = settings or default_settings
    _ = cfg
    member = set(chain_event_ids)
    internal = [e for e in edges if e.event_a in member and e.event_b in member]
    if not internal:
        return ConfidenceResult(score=0.0, reasons=[], links_analyzed=0)

    group_sums: dict[str, float] = {}
    group_details: dict[str, list[str]] = {}
    for edge in internal:
        for group, points in _group_points(edge).items():
            group_sums[group] = group_sums.get(group, 0.0) + points
            if points > 0:
                detail = next((c.detail for c in edge.contributions if c.group == group), "")
                if detail:
                    group_details.setdefault(group, []).append(detail)

    reasons: list[dict[str, Any]] = []
    total = 0.0
    # stable, documented order
    ordered_groups = [g for g in GROUP_LABELS if g in group_sums]
    ordered_groups += [g for g in group_sums if g not in GROUP_LABELS]
    for group in ordered_groups:
        mean_points = group_sums[group] / len(internal)
        if mean_points < 0.5:
            continue
        label = GROUP_LABELS.get(group, group)
        details = group_details.get(group, [])
        explanation = f"averaged over {len(internal)} internal link(s)"
        if details:
            explanation = f"e.g. {details[0]}"
        total += mean_points
        reasons.append(
            {
                "signal": group,
                "label": label,
                "points": round(mean_points, 1),
                "explanation": explanation,
            }
        )

    score = round(min(100.0, total), 1)
    reasons.sort(key=lambda r: -r["points"])
    return ConfidenceResult(score=score, reasons=reasons, links_analyzed=len(internal))


def confidence_from_pair(edge: PairScore) -> ConfidenceResult:
    """Convenience for API responses describing a single link."""
    return ConfidenceResult(
        score=round(min(100.0, edge.total), 1),
        reasons=[
            {
                "signal": c.group,
                "label": GROUP_LABELS.get(c.group, c.group),
                "points": round(c.points, 1),
                "explanation": c.detail,
            }
            for c in edge.contributions
            if c.points > 0
        ],
        links_analyzed=1,
    )
