"""Import indicators, match them against stored telemetry, persist findings.

For every match we persist:
* a ``Detection`` row (``rule_id = IOC_MATCH``) carrying the indicator and its
  source in the evidence JSON (visible on the event detail endpoint), and
* an observed ``Evidence`` row on every chain containing the matched event
  (visible in the chain evidence panel).

Re-importing the same indicator from the same source never duplicates rows.
"""
from __future__ import annotations

import time
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ioc import Indicator, match_events
from app.models import ChainEvent, Detection, Event, Evidence

IOC_RULE_ID = "IOC_MATCH"
IOC_RULE_NAME = "IOC Match"
MAX_LISTED_MATCHES = 100

# severity policy (fixed, documented - not a computed metric)
_SEVERITY_BY_TYPE = {"hash": "HIGH", "ip": "MEDIUM", "domain": "MEDIUM"}


def _indicator_fingerprint(detection: Detection) -> Optional[str]:
    for item in detection.evidence_json or []:
        if isinstance(item, dict) and item.get("type") == "ioc_match":
            return f"{detection.event_id}|{item.get('indicator_value')}|{item.get('indicator_source')}"
    return None


def import_indicators(
    session: Session,
    indicators: list[Indicator],
    parse_meta: dict[str, Any],
    source_label: str,
) -> dict[str, Any]:
    """Match indicators against all stored events and persist findings."""
    started = time.perf_counter()
    events = [
        {
            "event_id": e.event_id, "host": e.host, "scenario_id": e.scenario_id,
            "source_ip": e.source_ip, "destination_ip": e.destination_ip,
            "domain": e.domain, "file_hash": e.file_hash,
        }
        for e in session.scalars(select(Event)).all()
    ]
    matches = match_events(events, indicators)

    # existing IOC fingerprints -> skip duplicates on re-import
    existing = set()
    for det in session.scalars(select(Detection).where(Detection.rule_id == IOC_RULE_ID)).all():
        fp = _indicator_fingerprint(det)
        if fp:
            existing.add(fp)

    # chain membership per event (for evidence rows)
    chains_by_event: dict[str, list[str]] = {}
    for row in session.scalars(select(ChainEvent)).all():
        chains_by_event.setdefault(row.event_id, []).append(row.chain_id)

    existing_evidence = {
        (ev.chain_id, ev.event_id, ev.summary)
        for ev in session.scalars(select(Evidence).where(Evidence.category == "ioc_match")).all()
    }

    detections_created = 0
    evidence_created = 0
    new_matches: list[dict[str, Any]] = []
    skipped_duplicates = 0

    for m in matches:
        fingerprint = f"{m['event_id']}|{m['indicator_value']}|{m['indicator_source']}"
        if fingerprint in existing:
            skipped_duplicates += 1
            continue
        evidence_item = {
            "type": "ioc_match",
            "indicator_type": m["indicator_type"],
            "indicator_value": m["indicator_value"],
            "indicator_source": m["indicator_source"],
            "matched_field": m["field"],
            "observed_value": m["observed_value"],
            "source": source_label,
        }
        det = Detection(
            rule_id=IOC_RULE_ID,
            rule_name=IOC_RULE_NAME,
            event_id=m["event_id"],
            related_event_ids=[],
            severity=_SEVERITY_BY_TYPE.get(m["indicator_type"], "MEDIUM"),
            title=f"IOC match: {m['indicator_value']}",
            description=(
                f"Event field '{m['field']}' matched indicator "
                f"{m['indicator_type']} '{m['indicator_value']}' "
                f"from source '{m['indicator_source']}'."
            ),
            evidence_json=[evidence_item],
            host=m.get("host"),
            scenario_id=m.get("scenario_id"),
        )
        session.add(det)
        session.flush()  # assign detection.id
        detections_created += 1
        existing.add(fingerprint)

        summary = (
            f"IOC match: {m['indicator_type']} {m['indicator_value']} "
            f"(source: {m['indicator_source']})"
        )
        for chain_id in chains_by_event.get(m["event_id"], []):
            if (chain_id, m["event_id"], summary) in existing_evidence:
                continue
            session.add(Evidence(
                chain_id=chain_id,
                event_id=m["event_id"],
                detection_id=det.id,
                kind="OBSERVED",
                category="ioc_match",
                summary=summary,
                details=evidence_item,
                inferred=False,
            ))
            evidence_created += 1
            existing_evidence.add((chain_id, m["event_id"], summary))

        new_matches.append({**m, "detection_id": det.id})
        existing.add(fingerprint)

    session.commit()  # get_db does not auto-commit (same pattern as ingestion)

    by_type: dict[str, int] = {}
    for ind in indicators:
        by_type[ind.type] = by_type.get(ind.type, 0) + 1
    matched_types: dict[str, int] = {}
    for m in matches:
        matched_types[m["indicator_type"]] = matched_types.get(m["indicator_type"], 0) + 1

    return {
        "format": parse_meta.get("format", "unknown"),
        "source": source_label,
        "indicators_received": parse_meta.get("received", len(indicators)),
        "indicators_parsed": len(indicators),
        "indicators_invalid": len(parse_meta.get("issues", [])),
        "issues": parse_meta.get("issues", []),
        "by_type": by_type,
        "events_scanned": len(events),
        "matches_found": len(matches),
        "detections_created": detections_created,
        "evidence_created": evidence_created,
        "duplicates_skipped": skipped_duplicates,
        "matched_by_type": matched_types,
        "matches": new_matches[:MAX_LISTED_MATCHES],
        "matches_truncated": len(new_matches) > MAX_LISTED_MATCHES,
        "duration_seconds": round(time.perf_counter() - started, 4),
    }
