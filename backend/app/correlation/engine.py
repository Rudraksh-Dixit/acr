"""Correlation engines.

`CorrelationEngine` is the interface the rest of ACR depends on, so a future
ML/graph/LLM implementation can replace `RuleBasedCorrelationEngine` without
touching reconstruction, scoring or the API.
"""
from __future__ import annotations

import bisect
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.core.config import Settings, settings as default_settings
from app.core.logging import get_logger, log_event
from app.correlation.signals import PairScore, score_pair
from app.correlation.temporal import get_timestamp, time_sort_key
from app.ingestion.entity_extractor import entity_index_keys

logger = get_logger("correlation")


@dataclass
class CorrelationResult:
    edges: list[PairScore] = field(default_factory=list)
    clusters: list[list[str]] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def edges_by_event(self) -> dict[str, list[PairScore]]:
        out: dict[str, list[PairScore]] = {}
        for edge in self.edges:
            out.setdefault(edge.event_a, []).append(edge)
            out.setdefault(edge.event_b, []).append(edge)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "edges": [e.to_dict() for e in self.edges],
            "clusters": self.clusters,
            "stats": self.stats,
        }


class CorrelationEngine(ABC):
    """Interface for correlation implementations (rule-based now, ML later)."""

    name: str = "abstract"

    @abstractmethod
    def correlate(self, events: list[dict[str, Any]], settings: Settings | None = None) -> CorrelationResult:
        raise NotImplementedError


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


class RuleBasedCorrelationEngine(CorrelationEngine):
    """Multi-signal, index-driven correlation.

    Candidate pairs are generated from entity buckets, a sliding temporal
    window and process-lineage lookups - every event is never compared with
    every other event.
    """

    name = "rule_based"

    def correlate(self, events: list[dict[str, Any]], settings: Settings | None = None) -> CorrelationResult:
        cfg = settings or default_settings
        result = CorrelationResult()
        if len(events) < 2:
            result.stats = {"events": len(events), "pairs_scored": 0, "edges": 0}
            return result

        by_id: dict[str, dict[str, Any]] = {e["event_id"]: e for e in events if e.get("event_id")}
        ordered = sorted(by_id.values(), key=time_sort_key)
        timestamps = [get_timestamp(e) for e in ordered]
        timed_pairs = sorted(
            (t.timestamp(), e["event_id"]) for e in ordered if (t := get_timestamp(e)) is not None
        )
        ts_values = [pair[0] for pair in timed_pairs]

        # --- entity buckets -------------------------------------------------
        buckets: dict[str, list[str]] = {}
        for event in ordered:
            for key in entity_index_keys(event):
                buckets.setdefault(key, []).append(event["event_id"])

        # --- process lineage lookups ---------------------------------------
        by_pid: dict[tuple[str, str], list[str]] = {}
        by_ppid: dict[tuple[str, str], list[str]] = {}
        for event in ordered:
            host = str(event.get("host") or "").lower()
            if event.get("process_id") is not None:
                by_pid.setdefault((host, str(event["process_id"])), []).append(event["event_id"])
            if event.get("parent_process_id") is not None:
                by_ppid.setdefault((host, str(event["parent_process_id"])), []).append(event["event_id"])

        # --- candidate generation -------------------------------------------
        scored_pairs: set[tuple[str, str]] = set()
        pairs_scored = 0
        candidates_considered = 0
        edges: list[PairScore] = []
        window_hist: dict[str, int] = {}
        cap = cfg.max_candidates_per_event

        for index, event in enumerate(ordered):
            eid = event.get("event_id")
            if not eid:
                continue
            candidate_ids: set[str] = set()
            for key in entity_index_keys(event):
                candidate_ids.update(buckets.get(key, []))
            # temporal sweep over the broad window
            ts = timestamps[index]
            if ts is not None and ts_values:
                lo = ts.timestamp() - cfg.window_broad
                hi = ts.timestamp() + cfg.window_broad
                left = bisect.bisect_left(ts_values, lo)
                right = bisect.bisect_right(ts_values, hi)
                for pos in range(left, right):
                    other = timed_pairs[pos][1]
                    if other != eid:
                        candidate_ids.add(other)
            # process lineage neighbours
            host = str(event.get("host") or "").lower()
            if event.get("process_id") is not None:
                candidate_ids.update(by_ppid.get((host, str(event["process_id"])), []))
            if event.get("parent_process_id") is not None:
                candidate_ids.update(by_pid.get((host, str(event["parent_process_id"])), []))
            candidate_ids.discard(eid)

            if len(candidate_ids) > cap:
                # keep candidates that also fall inside the temporal window first
                def priority(other_id: str) -> tuple[int, str]:
                    other = by_id.get(other_id, {})
                    ots = get_timestamp(other)
                    inside = 0 if (ts and ots and abs((ots - ts).total_seconds()) <= cfg.window_broad) else 1
                    return (inside, other_id)

                candidate_ids = set(sorted(candidate_ids, key=priority)[:cap])

            for other_id in candidate_ids:
                pair_key = tuple(sorted((eid, other_id)))
                if pair_key in scored_pairs:
                    continue
                scored_pairs.add(pair_key)
                candidates_considered += 1
                other = by_id.get(other_id)
                if other is None:
                    continue
                score = score_pair(event, other, cfg)
                pairs_scored += 1
                if score.total < cfg.min_edge_score:
                    continue
                if not score.has_non_temporal_host_evidence:
                    # same machine + time is insufficient by itself (spec 11)
                    continue
                if score.window:
                    window_hist[score.window] = window_hist.get(score.window, 0) + 1
                edges.append(score)

        edges.sort(key=lambda s: -s.total)

        # --- clusters (connected components over accepted edges) -----------
        uf = _UnionFind()
        for edge in edges:
            uf.union(edge.event_a, edge.event_b)
        components: dict[str, list[str]] = {}
        for eid in by_id:
            root = uf.find(eid)
            components.setdefault(root, []).append(eid)
        clusters = [ids for ids in components.values() if len(ids) > 1]
        clusters.sort(key=len, reverse=True)

        result.edges = edges
        result.clusters = [sorted(ids) for ids in clusters]
        result.stats = {
            "events": len(by_id),
            "entity_buckets": len(buckets),
            "candidates_considered": candidates_considered,
            "pairs_scored": pairs_scored,
            "edges": len(edges),
            "clusters": len(clusters),
            "avg_edge_score": round(sum(e.total for e in edges) / len(edges), 1) if edges else 0.0,
            "window_histogram": window_hist,
            "engine": self.name,
        }
        log_event(logger, "correlation_complete", **{k: v for k, v in result.stats.items() if k != "window_histogram"})
        return result


def get_engine(name: str = "rule_based") -> CorrelationEngine:
    if name == "rule_based":
        return RuleBasedCorrelationEngine()
    raise ValueError(f"unknown correlation engine: {name}")
