"""Attack-chain reconstruction: correlation clusters -> explainable chains."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from app.core.config import Settings, settings as default_settings
from app.core.logging import get_logger, log_event
from app.correlation.engine import CorrelationResult
from app.correlation.signals import PairScore
from app.correlation.technique import tactic_of
from app.ingestion.entity_extractor import display_entity, extract_entities
from app.mitre import get_mapper
from app.reconstruction.attack_path import build_attack_path
from app.scoring.confidence import ConfidenceResult, compute_confidence
from app.scoring.missing_steps import infer_missing_steps
from app.scoring.risk import RiskResult, compute_risk

logger = get_logger("reconstruction")

# A plain (non-seeded) event needs stronger evidence to be absorbed into a
# chain than two detection-bearing events do. With the weights in
# core/config.py summing to 100, same host (20) + same user (11) + temporal
# proximity (20) scores 51 - just above this bar - while weaker pairings
# (e.g. same user + time only, 31) stay out.
DEFAULT_ABSORB_THRESHOLD = 50.0


@dataclass
class ChainDraft:
    chain_id: str
    event_ids: list[str]
    events: list[dict[str, Any]]
    detections: list[dict[str, Any]]
    internal_edges: list[PairScore]
    confidence: ConfidenceResult
    risk: RiskResult
    tactics: list[str]
    techniques: list[dict[str, Any]]
    hosts: list[str]
    users: list[str]
    processes: list[str]
    entities: list[dict[str, Any]]
    attack_path: list[dict[str, Any]]
    possible_missing_steps: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    is_attack: bool
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    duration_seconds: Optional[float]
    status: str = "RECONSTRUCTED"
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "status": self.status,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "event_count": len(self.event_ids),
            "is_attack": self.is_attack,
            "confidence": self.confidence.to_dict(),
            "risk": self.risk.to_dict(),
            "tactics": self.tactics,
            "techniques": self.techniques,
            "hosts": self.hosts,
            "users": self.users,
            "processes": self.processes,
            "entities": self.entities,
            "attack_path": self.attack_path,
            "possible_missing_steps": self.possible_missing_steps,
            "evidence": self.evidence,
            "summary": self.summary,
            "event_ids": self.event_ids,
        }


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _seed_ids(
    events: list[dict[str, Any]],
    detections: list[dict[str, Any]],
) -> set[str]:
    seeds = {str(d["event_id"]) for d in detections if d.get("event_id")}
    seeds |= {str(e["event_id"]) for e in events if e.get("technique_id") and e.get("event_id")}
    return seeds


def _order_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        events,
        key=lambda e: (e.get("timestamp") is None, e.get("timestamp") or datetime.max, str(e.get("event_id"))),
    )


def _summarize_chain(draft_events: list[dict[str, Any]], confidence: float, risk: RiskResult) -> str:
    hosts = sorted({e["host"] for e in draft_events if e.get("host")})
    users = sorted({e["user"] for e in draft_events if e.get("user")})
    tactics = []
    for event in draft_events:
        t = tactic_of(event)
        if t and t not in tactics:
            tactics.append(t)
    window = ""
    stamps = [e["timestamp"] for e in draft_events if e.get("timestamp")]
    if stamps:
        window = f" between {min(stamps).isoformat()}Z and {max(stamps).isoformat()}Z"
    parts = [f"{len(draft_events)} correlated events"]
    if hosts:
        parts.append(f"on host(s) {', '.join(hosts)}")
    if users:
        parts.append(f"as user(s) {', '.join(users)}")
    if tactics:
        parts.append(f"spanning tactics {', '.join(tactics)}")
    return (
        f"Chain assembled from {'; '.join(parts)}{window}. "
        f"Correlation confidence {confidence:.0f}%, risk {risk.level} ({risk.score:.0f}/100)."
    )


def build_chains(
    events: list[dict[str, Any]],
    correlation: CorrelationResult,
    detections: list[dict[str, Any]],
    settings: Settings | None = None,
    absorb_threshold: float | None = None,
) -> list[ChainDraft]:
    cfg = settings or default_settings
    absorb = absorb_threshold if absorb_threshold is not None else DEFAULT_ABSORB_THRESHOLD
    mapper = get_mapper()

    by_id = {e["event_id"]: e for e in events if e.get("event_id")}
    detections_by_event: dict[str, list[dict[str, Any]]] = {}
    for det in detections:
        if det.get("event_id"):
            detections_by_event.setdefault(str(det["event_id"]), []).append(det)

    seeds = _seed_ids(events, detections)
    if not seeds:
        log_event(logger, "reconstruction_no_seeds", events=len(events))
        return []

    edges = correlation.edges
    neighbours: dict[str, list[PairScore]] = {}
    for edge in edges:
        neighbours.setdefault(edge.event_a, []).append(edge)
        neighbours.setdefault(edge.event_b, []).append(edge)

    # union over links that meet the seed/absorb thresholds
    uf = _UnionFind()
    for edge in edges:
        a_seeded = edge.event_a in seeds
        b_seeded = edge.event_b in seeds
        if a_seeded and b_seeded:
            threshold = cfg.min_edge_score
        elif a_seeded or b_seeded:
            threshold = absorb
        else:
            continue
        if edge.total >= threshold:
            uf.union(edge.event_a, edge.event_b)

    components: dict[str, list[str]] = {}
    for eid in seeds:
        if eid not in by_id:
            continue
        components.setdefault(uf.find(eid), []).append(eid)
    # absorb non-seed events that link into a component
    for edge in edges:
        root_a = uf.find(edge.event_a) if edge.event_a in by_id else None
        root_b = uf.find(edge.event_b) if edge.event_b in by_id else None
        if root_a is None or root_b is None or root_a != root_b:
            continue
        for eid in (edge.event_a, edge.event_b):
            if eid not in components.setdefault(root_a, []):
                components[root_a].append(eid)

    drafts: list[ChainDraft] = []
    raw_drafts: list[dict[str, Any]] = []

    for member_ids in components.values():
        if len(member_ids) < 2:
            continue  # single-event detections remain visible as detections
        chain_events = _order_events([by_id[i] for i in member_ids if i in by_id])
        if len(chain_events) < 2:
            continue
        ids = [e["event_id"] for e in chain_events]
        id_set = set(ids)
        internal_edges = [e for e in edges if e.event_a in id_set and e.event_b in id_set]
        chain_detections = [d for d in detections if str(d.get("event_id")) in id_set]

        confidence = compute_confidence(ids, internal_edges, cfg)
        tactics = []
        for event in chain_events:
            t = tactic_of(event)
            if t and t not in tactics:
                tactics.append(t)
        for det in chain_detections:
            t = (det.get("tactic") or mapper.tactic_for(det.get("technique_id")) or "").upper()
            if t and t not in tactics:
                tactics.append(t)
        tactics.sort(key=lambda t: _tactic_order(t))

        techniques: list[dict[str, Any]] = []
        seen_tech: set[str] = set()
        for event in chain_events:
            tid = event.get("technique_id")
            if tid and tid not in seen_tech:
                seen_tech.add(tid)
                techniques.append({
                    "technique_id": tid,
                    "name": event.get("technique_name") or mapper.name_for(tid) or tid,
                    "tactic": (event.get("tactic") or mapper.tactic_for(tid) or ""),
                    "observed": True,
                })
        for det in chain_detections:
            tid = det.get("technique_id")
            if tid and tid not in seen_tech:
                seen_tech.add(tid)
                techniques.append({
                    "technique_id": tid,
                    "name": det.get("technique_name") or mapper.name_for(tid) or tid,
                    "tactic": (det.get("tactic") or mapper.tactic_for(tid) or ""),
                    "observed": True,
                })

        risk = compute_risk(chain_events, chain_detections, tactics, cfg)
        missing = infer_missing_steps(chain_events, tactics, list(seen_tech), confidence.score, cfg)

        hosts = sorted({e["host"] for e in chain_events if e.get("host")})
        users = sorted({e["user"] for e in chain_events if e.get("user")})
        processes = sorted({
            p for e in chain_events for p in (e.get("process_name"), e.get("parent_process")) if p
        })

        entity_map: dict[tuple[str, str], str] = {}
        for event in chain_events:
            for ref in extract_entities(event):
                entity_map.setdefault((ref.entity_type, ref.value), ref.role)
        entities = [
            {"type": t, "value": v, "label": display_entity(t, v), "role": role}
            for (t, v), role in sorted(entity_map.items())
        ]

        evidence = _build_evidence(chain_events, chain_detections, internal_edges)
        path = build_attack_path(chain_events, [t["technique_id"] for t in techniques], tactics, missing)

        stamps = [e["timestamp"] for e in chain_events if e.get("timestamp")]
        start = min(stamps) if stamps else None
        end = max(stamps) if stamps else None
        duration = (end - start).total_seconds() if start and end else None

        is_attack = (
            confidence.score >= cfg.attack_confidence_threshold
            and risk.score >= cfg.attack_risk_threshold
            and bool(chain_detections or techniques)
        )

        raw_drafts.append({
            "events": chain_events,
            "ids": ids,
            "detections": chain_detections,
            "edges": internal_edges,
            "confidence": confidence,
            "risk": risk,
            "tactics": tactics,
            "techniques": techniques,
            "hosts": hosts,
            "users": users,
            "processes": processes,
            "entities": entities,
            "evidence": evidence,
            "path": path,
            "missing": missing,
            "is_attack": is_attack,
            "start": start,
            "end": end,
            "duration": duration,
            "summary": _summarize_chain(chain_events, confidence.score, risk),
        })

    # stable, human-friendly chain ids ordered by first activity
    raw_drafts.sort(key=lambda d: (d["start"] is None, d["start"] or datetime.max, d["ids"][0]))
    for index, data in enumerate(raw_drafts, start=1):
        drafts.append(ChainDraft(chain_id=f"ACR-{index:04d}", event_ids=data["ids"], events=data["events"],
                                 detections=data["detections"], internal_edges=data["edges"],
                                 confidence=data["confidence"], risk=data["risk"], tactics=data["tactics"],
                                 techniques=data["techniques"], hosts=data["hosts"], users=data["users"],
                                 processes=data["processes"], entities=data["entities"],
                                 attack_path=data["path"], possible_missing_steps=data["missing"],
                                 evidence=data["evidence"], is_attack=data["is_attack"],
                                 start_time=data["start"], end_time=data["end"],
                                 duration_seconds=data["duration"], summary=data["summary"]))

    log_event(logger, "reconstruction_complete", events=len(events), seeds=len(seeds),
              chains=len(drafts), attacks=sum(1 for d in drafts if d.is_attack))
    return drafts


def _tactic_order(tactic: str) -> int:
    from app.core.config import TACTIC_ORDER

    return TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else 99


def _build_evidence(
    events: list[dict[str, Any]],
    detections: list[dict[str, Any]],
    edges: list[PairScore],
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for det in sorted(detections, key=lambda d: str(d.get("severity", "INFO")), reverse=True):
        evidence.append({
            "kind": "OBSERVED",
            "type": "DETECTION",
            "rule_id": det.get("rule_id"),
            "rule_name": det.get("rule_name"),
            "severity": det.get("severity"),
            "technique_id": det.get("technique_id"),
            "event_id": det.get("event_id"),
            "summary": det.get("title"),
            "description": det.get("description"),
            "details": det.get("evidence") or [],
        })
    for edge in sorted(edges, key=lambda e: -e.total)[:6]:
        groups = ", ".join(sorted(edge.groups))
        evidence.append({
            "kind": "OBSERVED",
            "type": "CORRELATION_LINK",
            "event_ids": [edge.event_a, edge.event_b],
            "points": round(edge.total, 1),
            "window": edge.window,
            "summary": f"Events linked by {groups} ({edge.total:.0f} points)",
            "details": [c.to_dict() for c in edge.contributions],
        })
    # chronological anchors
    ordered = sorted(events, key=lambda e: (e.get("timestamp") is None, e.get("timestamp") or datetime.max))
    if ordered:
        first, last = ordered[0], ordered[-1]
        evidence.append({
            "kind": "OBSERVED",
            "type": "TIMELINE_BOUNDS",
            "event_ids": [first.get("event_id"), last.get("event_id")],
            "summary": f"Chain spans {len(ordered)} events from {first.get('event_type')} to {last.get('event_type')}",
            "details": [
                {"field": "first", "value": str(first.get("timestamp")), "why": "earliest event in chain"},
                {"field": "last", "value": str(last.get("timestamp")), "why": "latest event in chain"},
            ],
        })
    return evidence
