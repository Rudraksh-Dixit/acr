"""Evaluation engine: compares pipeline stages against scenario ground truth.

Three stages are evaluated separately so the contribution of each component is
measurable:

    raw_detection   -> rule matches only (no grouping)
    correlation     -> entity/time clusters containing detections
    reconstruction  -> final scored attack chains

Metrics: precision, recall, F1, false-positive rate, detection latency and
throughput. Runs are persisted as evaluation_runs rows.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, settings as default_settings
from app.core.logging import get_logger, log_event
from app.correlation.engine import get_engine
from app.detection import run_detection
from app.ingestion.normalizer import normalize_records
from app.mitre import get_mapper
from app.models import EvaluationRun
from app.reconstruction.chain_builder import build_chains
from app.scenarios import generate_scenario, scenario_catalog

logger = get_logger("evaluation")

STAGES = ("raw_detection", "correlation", "reconstruction")


@dataclass
class MetricSet:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, other: "MetricSet") -> "MetricSet":
        return MetricSet(self.tp + other.tp, self.fp + other.fp, self.fn + other.fn, self.tn + other.tn)

    @property
    def precision(self) -> Optional[float]:
        denom = self.tp + self.fp
        return round(self.tp / denom, 4) if denom else None

    @property
    def recall(self) -> Optional[float]:
        denom = self.tp + self.fn
        return round(self.tp / denom, 4) if denom else None

    @property
    def f1(self) -> Optional[float]:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return round(2 * p * r / (p + r), 4)

    @property
    def fpr(self) -> Optional[float]:
        denom = self.fp + self.tn
        return round(self.fp / denom, 4) if denom else None

    def to_dict(self, include_fpr: bool = False) -> dict[str, Any]:
        data = {
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "precision": self.precision, "recall": self.recall, "f1": self.f1,
        }
        if include_fpr:
            data["false_positive_rate"] = self.fpr
        return data


def set_metrics(predicted: set[str], expected: set[str], universe_negative: bool = False) -> MetricSet:
    tp = len(predicted & expected)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    result = MetricSet(tp=tp, fp=fp, fn=fn)
    if universe_negative and not predicted and not expected:
        result.tn = 1
    return result


def _detection_dicts(matches) -> list[dict[str, Any]]:
    mapper = get_mapper()
    out = []
    for match in matches:
        tid = mapper.normalize_technique_id(match.technique_id)
        out.append({
            "rule_id": match.rule_id,
            "rule_name": match.rule_name,
            "event_id": match.event.get("event_id"),
            "severity": match.severity,
            "technique_id": tid,
            "technique_name": match.technique_name or mapper.name_for(tid),
            "tactic": mapper.tactic_for(tid) or "",
            "title": match.title,
            "description": match.description,
            "evidence": match.evidence,
            "host": match.event.get("host"),
            "scenario_id": match.event.get("scenario_id"),
        })
    return out


def _annotate_events_with_techniques(events: list[dict[str, Any]], detections: list[dict[str, Any]]) -> None:
    """Mirror of the enrichment stage performed during ingestion."""
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    best: dict[str, dict[str, Any]] = {}
    for det in detections:
        eid = det.get("event_id")
        if not eid:
            continue
        current = best.get(eid)
        if current is None or rank.get(det["severity"], 0) > rank.get(current["severity"], 0):
            best[eid] = det
    for event in events:
        det = best.get(event.get("event_id"))
        if det and not event.get("technique_id"):
            event["technique_id"] = det["technique_id"]
            event["technique_name"] = det["technique_name"]
            event["tactic"] = det["tactic"]


@dataclass
class ScenarioEvaluation:
    scenario_id: str
    is_benign: bool
    events: int = 0
    detections: int = 0
    chains: int = 0
    attack_chains: int = 0
    duration_seconds: float = 0.0
    detection_latency_seconds: Optional[float] = None
    stages: dict[str, Any] = field(default_factory=dict)
    predicted_techniques: list[str] = field(default_factory=list)
    reconstructed_chain_f1: Optional[float] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "is_benign": self.is_benign,
            "events": self.events,
            "detections": self.detections,
            "chains": self.chains,
            "attack_chains": self.attack_chains,
            "duration_seconds": round(self.duration_seconds, 4),
            "detection_latency_seconds": self.detection_latency_seconds,
            "stages": self.stages,
            "predicted_techniques": self.predicted_techniques,
            "reconstructed_chain_f1": self.reconstructed_chain_f1,
        }


def evaluate_scenario(
    scenario_id: str,
    settings: Settings | None = None,
    base: Optional[datetime] = None,
    seed: int = 42,
) -> ScenarioEvaluation:
    cfg = settings or default_settings
    mapper = get_mapper()
    started = time.perf_counter()

    scenario = generate_scenario(scenario_id, base=base, seed=seed)
    gt = scenario.ground_truth
    gt_techniques = {str(t).upper() for t in gt.get("techniques", [])}
    gt_events = {str(g) for g in gt.get("chain_events", [])}
    is_benign = bool(scenario.is_benign)

    batch = normalize_records(scenario.events, source="scenario", scenario_id=scenario_id)
    events = [mapper.annotate(e) for e in batch.events]
    matches = run_detection(events, cfg)
    detections = _detection_dicts(matches)
    _annotate_events_with_techniques(events, detections)

    # stage 1: raw detection (rules only, no grouping)
    event_by_id = {e["event_id"]: e for e in events}
    raw_techniques = {d["technique_id"] for d in detections if d.get("technique_id")}
    raw_flagged_ids = {
        d["event_id"] for d in detections
        if d.get("event_id") and d.get("severity") in {"HIGH", "CRITICAL"}
    }
    raw_flagged = {
        str(event_by_id[eid].get("gt_id")) for eid in raw_flagged_ids
        if eid in event_by_id and event_by_id[eid].get("gt_id")
    }
    raw_attack = bool(raw_flagged_ids)

    # stage 2: correlation clusters
    correlation = get_engine().correlate(events, cfg)
    det_event_ids = {d["event_id"] for d in detections if d.get("event_id")}
    cluster_members: list[set[str]] = [set(c) for c in correlation.clusters]
    attack_clusters = [c for c in cluster_members if c & det_event_ids]
    corr_techniques: set[str] = set()
    corr_events: set[str] = set()
    for cluster in attack_clusters:
        for eid in cluster:
            det = next((d for d in detections if d.get("event_id") == eid), None)
            if det and det.get("technique_id"):
                corr_techniques.add(det["technique_id"])
            event = event_by_id.get(eid)
            if event and event.get("technique_id"):
                corr_techniques.add(event["technique_id"])
            if event and event.get("gt_id"):
                corr_events.add(str(event["gt_id"]))
    corr_attack = bool(attack_clusters)

    # stage 3: reconstruction
    drafts = build_chains(events, correlation, detections, cfg)
    attack_drafts = [d for d in drafts if d.is_attack]
    recon_techniques: set[str] = set()
    recon_events: set[str] = set()
    best_f1: Optional[float] = None
    for draft in attack_drafts:
        recon_techniques |= {t["technique_id"] for t in draft.techniques if t.get("technique_id")}
        draft_gt = {str(e.get("gt_id")) for e in draft.events if e.get("gt_id")}
        recon_events |= draft_gt
        if gt_events:
            tp = len(draft_gt & gt_events)
            fp = len(draft_gt - gt_events)
            fn = len(gt_events - draft_gt)
            p = tp / (tp + fp) if (tp + fp) else 0.0
            r = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = (2 * p * r / (p + r)) if (p + r) else 0.0
            best_f1 = max(best_f1 or 0.0, f1)
    recon_attack = bool(attack_drafts)

    # detection latency: first detection vs first ground-truth event
    latency: Optional[float] = None
    if not is_benign and gt_events:
        gt_times = []
        gt_to_time = {str(e.get("gt_id")): e.get("timestamp") for e in events if e.get("gt_id")}
        for g in gt_events:
            ts = gt_to_time.get(g)
            if ts is not None:
                gt_times.append(ts)
        det_times = [
            event_by_id[d["event_id"]].get("timestamp")
            for d in detections
            if d.get("event_id") in event_by_id and event_by_id[d["event_id"]].get("timestamp")
        ]
        if gt_times and det_times:
            latency = (min(det_times) - min(gt_times)).total_seconds()
            latency = max(0.0, latency)

    duration = time.perf_counter() - started
    result = ScenarioEvaluation(
        scenario_id=scenario_id,
        is_benign=is_benign,
        events=len(events),
        detections=len(detections),
        chains=len(drafts),
        attack_chains=len(attack_drafts),
        duration_seconds=duration,
        detection_latency_seconds=latency,
        predicted_techniques=sorted(recon_techniques),
        reconstructed_chain_f1=round(best_f1, 4) if best_f1 is not None else None,
    )
    result.stages = {
        "raw_detection": {
            "techniques": set_metrics(raw_techniques, gt_techniques, universe_negative=is_benign).to_dict(),
            "events": set_metrics(raw_flagged, gt_events, universe_negative=is_benign).to_dict(),
            "attack_detected": raw_attack,
            "correct": raw_attack != is_benign,
        },
        "correlation": {
            "techniques": set_metrics(corr_techniques, gt_techniques, universe_negative=is_benign).to_dict(),
            "events": set_metrics(corr_events, gt_events, universe_negative=is_benign).to_dict(),
            "attack_detected": corr_attack,
            "correct": corr_attack != is_benign,
            "clusters": len(correlation.clusters),
        },
        "reconstruction": {
            "techniques": set_metrics(recon_techniques, gt_techniques, universe_negative=is_benign).to_dict(),
            "events": set_metrics(recon_events, gt_events, universe_negative=is_benign).to_dict(),
            "attack_detected": recon_attack,
            "correct": recon_attack != is_benign,
            "chain_f1": result.reconstructed_chain_f1,
        },
    }
    return result


def run_evaluation(
    scenario_ids: Optional[Iterable[str]] = None,
    settings: Settings | None = None,
    base: Optional[datetime] = None,
    seed: int = 42,
    session: Optional[Session] = None,
    persist: bool = True,
) -> dict[str, Any]:
    cfg = settings or default_settings
    started = time.perf_counter()
    ids = list(scenario_ids) if scenario_ids else [s["scenario_id"] for s in scenario_catalog()]

    per_scenario: list[dict[str, Any]] = []
    stage_techniques: dict[str, MetricSet] = {s: MetricSet() for s in STAGES}
    stage_events: dict[str, MetricSet] = {s: MetricSet() for s in STAGES}
    verdict: dict[str, MetricSet] = {s: MetricSet() for s in STAGES}
    latencies: list[float] = []
    total_events = 0
    chains_total = 0
    chains_correct = 0

    for scenario_id in ids:
        ev = evaluate_scenario(scenario_id, cfg, base=base, seed=seed)
        per_scenario.append(ev.to_dict())
        total_events += ev.events
        chains_total += ev.chains
        is_attack = not ev.is_benign
        if is_attack and ev.reconstructed_chain_f1 is not None and ev.reconstructed_chain_f1 >= 0.5:
            chains_correct += 1
        if ev.detection_latency_seconds is not None:
            latencies.append(ev.detection_latency_seconds)
        for stage in STAGES:
            stage_techniques[stage].tp += ev.stages[stage]["techniques"]["tp"]
            stage_techniques[stage].fp += ev.stages[stage]["techniques"]["fp"]
            stage_techniques[stage].fn += ev.stages[stage]["techniques"]["fn"]
            stage_events[stage].tp += ev.stages[stage]["events"]["tp"]
            stage_events[stage].fp += ev.stages[stage]["events"]["fp"]
            stage_events[stage].fn += ev.stages[stage]["events"]["fn"]
            if ev.is_benign and not ev.stages[stage]["attack_detected"]:
                verdict[stage].tn += 1
            elif ev.is_benign and ev.stages[stage]["attack_detected"]:
                verdict[stage].fp += 1
            elif (not ev.is_benign) and ev.stages[stage]["attack_detected"]:
                verdict[stage].tp += 1
            else:
                verdict[stage].fn += 1

    duration = time.perf_counter() - started
    metrics: dict[str, Any] = {
        "technique_level": {s: stage_techniques[s].to_dict() for s in STAGES},
        "event_level": {s: stage_events[s].to_dict() for s in STAGES},
        "attack_detection": {s: verdict[s].to_dict(include_fpr=True) for s in STAGES},
        "detection_latency_seconds": {
            "mean": round(sum(latencies) / len(latencies), 3) if latencies else None,
            "max": round(max(latencies), 3) if latencies else None,
            "samples": len(latencies),
        },
        "performance": {
            "events_processed": total_events,
            "events_per_second": round(total_events / duration, 1) if duration > 0 else None,
            "duration_seconds": round(duration, 4),
        },
        "reconstruction": {
            "chains_reconstructed": chains_total,
            "correctly_reconstructed_chains": chains_correct,
            "chain_accuracy": round(chains_correct / chains_total, 4) if chains_total else None,
        },
        "scenarios_evaluated": len(per_scenario),
    }

    payload = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "scenarios": ids,
            "seed": seed,
            "time_windows": cfg.time_windows(),
            "weights": cfg.weights,
            "min_edge_score": cfg.min_edge_score,
            "attack_confidence_threshold": cfg.attack_confidence_threshold,
            "attack_risk_threshold": cfg.attack_risk_threshold,
        },
        "metrics": metrics,
        "per_scenario": per_scenario,
        "duration_seconds": round(time.perf_counter() - started, 4),
    }

    if persist and session is not None:
        run_row = EvaluationRun(
            config=payload["config"],
            metrics=metrics,
            per_scenario=per_scenario,
            stages={s: stage_techniques[s].to_dict() for s in STAGES},
            events_processed=total_events,
            duration_seconds=payload["duration_seconds"],
        )
        session.add(run_row)
        session.commit()
        payload["run_id"] = run_row.id

    log_event(logger, "evaluation_complete", scenarios=len(per_scenario),
              events=total_events, f1_reconstruction=metrics["technique_level"]["reconstruction"]["f1"])
    return payload


def list_runs(session: Session, limit: int = 20) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(EvaluationRun).order_by(EvaluationRun.created_at.desc()).limit(limit)
    ).all()
    return [
        {
            "id": r.id,
            "created_at": r.created_at.isoformat() + "Z",
            "events_processed": r.events_processed,
            "duration_seconds": r.duration_seconds,
            "metrics": r.metrics,
        }
        for r in rows
    ]


def get_run(session: Session, run_id: int) -> Optional[dict[str, Any]]:
    row = session.get(EvaluationRun, run_id)
    if row is None:
        return None
    return {
        "id": row.id,
        "created_at": row.created_at.isoformat() + "Z",
        "config": row.config,
        "metrics": row.metrics,
        "per_scenario": row.per_scenario,
        "events_processed": row.events_processed,
        "duration_seconds": row.duration_seconds,
    }
