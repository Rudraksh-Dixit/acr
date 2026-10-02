"""Correlation engine tests: scoring, windows, clustering, edge guard."""
from __future__ import annotations

from datetime import datetime, timedelta

from app.core.config import settings
from app.correlation.engine import get_engine
from app.correlation.signals import score_pair
from app.ingestion.normalizer import normalize_records

BASE = datetime(2026, 1, 1, 10, 0, 0)


def _event(offset: int, **fields) -> dict:
    record = {
        "timestamp": (BASE + timedelta(seconds=offset)).isoformat() + "Z",
        "host": "host1",
        "user": "alice",
        "event_type": "PROCESS_CREATED",
        "process_name": "powershell.exe",
    }
    record.update(fields)
    batch = normalize_records([record], source="test")
    return batch.events[0]


def _cluster_map(result) -> dict[str, int]:
    out: dict[str, int] = {}
    for index, cluster in enumerate(result.clusters):
        for event_id in cluster:
            out[event_id] = index
    return out


def test_related_events_score_above_threshold():
    a = _event(0, process_id=100, command_line="powershell.exe -enc AAAA")
    b = _event(5, process_id=101, parent_process="powershell.exe", command_line="cmd.exe /c x")
    score = score_pair(a, b, settings)
    assert score.total >= settings.min_edge_score
    assert score.total >= 40
    assert "temporal" in score.groups


def test_unrelated_distant_events_score_below_threshold():
    a = _event(0, host="host1", user="alice", process_name="notepad.exe")
    b = _event(4000, host="host2", user="bob", process_name="chrome.exe",
               event_type="NETWORK_CONNECTION", destination_ip="8.8.8.8")
    score = score_pair(a, b, settings)
    assert score.total < settings.min_edge_score


def test_only_temporal_and_host_evidence_is_rejected():
    # same host + within window but nothing else (different users, different
    # processes): the edge guard must reject the pair
    a = _event(0, user="alice", process_name="notepad.exe", command_line="notepad.exe a.txt")
    b = _event(10, user="bob", process_name="chrome.exe", command_line="chrome.exe https://example.com")
    score = score_pair(a, b, settings)
    assert score.groups <= {"temporal", "same_host"}
    assert not score.has_non_temporal_host_evidence


def test_engine_clusters_correlated_events():
    events = [
        _event(0, process_name="winword.exe", parent_process="explorer.exe", event_type="PROCESS_CREATED"),
        _event(3, process_name="powershell.exe", parent_process="winword.exe"),
        _event(8, destination_ip="185.220.101.45", event_type="NETWORK_CONNECTION",
               process_name="powershell.exe"),
        _event(60000, host="host9", user="carl", process_name="sqlservr.exe",
               event_type="NETWORK_CONNECTION", destination_ip="10.9.9.9"),
    ]
    result = get_engine().correlate(events, settings)
    cluster_of = _cluster_map(result)
    assert cluster_of[events[0]["event_id"]] == cluster_of[events[1]["event_id"]]
    assert cluster_of[events[1]["event_id"]] == cluster_of[events[2]["event_id"]]
    # the far-away unrelated event must not join the attack cluster
    assert events[3]["event_id"] not in cluster_of
    assert result.stats["pairs_scored"] > 0
    assert all(e.total >= settings.min_edge_score for e in result.edges)


def test_time_windows_decay_confidence():
    near = _event(0, destination_ip="1.2.3.4", event_type="NETWORK_CONNECTION")
    also_near = _event(10, destination_ip="1.2.3.4", event_type="NETWORK_CONNECTION")
    far = _event(300, destination_ip="1.2.3.4", event_type="NETWORK_CONNECTION")
    near_score = score_pair(near, also_near, settings)
    far_score = score_pair(near, far, settings)
    assert near_score.window == "STRICT"
    assert far_score.window == "BROAD"
    assert far_score.total < near_score.total
