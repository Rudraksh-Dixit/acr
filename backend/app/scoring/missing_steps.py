"""Possible-missing-step inference (always flagged as inferred, never observed).

The engine compares the observed tactic span against the kill-chain order and
suggests techniques that commonly sit in the gaps. Every suggestion carries
`inferred: true` and a computed confidence so the UI can visually separate
OBSERVED from INFERRED content.
"""
from __future__ import annotations

from typing import Any

from app.core.config import TACTIC_ORDER, Settings, settings as default_settings
from app.mitre import get_mapper

_INDEX = {name: i for i, name in enumerate(TACTIC_ORDER)}

# how far (in tactic steps) the gap sits from an observed tactic -> base confidence
_DISTANCE_CONFIDENCE = {1: 66.0, 2: 56.0, 3: 47.0}


def _clamp(value: float, low: float = 25.0, high: float = 85.0) -> float:
    return max(low, min(high, value))


def infer_missing_steps(
    events: list[dict[str, Any]],
    tactics: list[str],
    techniques: list[str],
    chain_confidence: float = 50.0,
    settings: Settings | None = None,
) -> list[dict[str, Any]]:
    cfg = settings or default_settings
    _ = cfg
    mapper = get_mapper()
    observed = [str(t).upper() for t in tactics if str(t).upper() in _INDEX]
    if not observed:
        return []

    steps: list[dict[str, Any]] = []
    indices = sorted(_INDEX[t] for t in observed)
    first, last = indices[0], indices[-1]

    gap_tactics = [TACTIC_ORDER[i] for i in range(first, last + 1) if TACTIC_ORDER[i] not in observed]
    for gap in gap_tactics:
        if gap in observed:
            continue
        distances = [_INDEX[o] - _INDEX[gap] for o in observed if _INDEX[o] > _INDEX[gap]]
        distance = min(distances) if distances else 1
        base = _DISTANCE_CONFIDENCE.get(distance, 40.0)
        if chain_confidence < 50:
            base -= 8
        suggestions = mapper.suggestions_for_tactic(gap)
        if not suggestions:
            continue
        suggestion = suggestions[0]
        meta = mapper.get(suggestion.technique_id)
        confidence = round(_clamp(base), 1)
        steps.append(
            {
                "technique_id": suggestion.technique_id,
                "technique_name": meta.name if meta else suggestion.technique_id,
                "tactic": gap,
                "confidence": confidence,
                "inferred": True,
                "observed": False,
                "kind": "MISSING_TACTIC_GAP",
                "reason": suggestion.reason,
                "explanation": (
                    f"Observed tactics jump over {gap}; this stage is required for a coherent "
                    f"attack path but produced no telemetry."
                ),
            }
        )

    # targeted heuristic: file write -> file execution without a user-execution hit
    executed_files = set()
    created_files: dict[str, str] = {}
    for event in events:
        path = str(event.get("file_path") or "").lower()
        if event.get("event_type") == "FILE_CREATED" and path:
            created_files[path] = event.get("host") or ""
        if event.get("event_type") == "PROCESS_CREATED":
            cmd = str(event.get("command_line") or "").lower()
            name = str(event.get("process_name") or "").lower()
            for created, host in created_files.items():
                base = created.replace("\\", "/").split("/")[-1]
                if base and (base in cmd or base == name) and (not host or host == (event.get("host") or "")):
                    executed_files.add(created)
    if executed_files and "T1204" not in {str(t).split(".")[0] for t in techniques}:
        meta = mapper.get("T1204")
        steps.append(
            {
                "technique_id": "T1204.002",
                "technique_name": meta.name if meta else "User Execution: Malicious File",
                "tactic": "EXECUTION",
                "confidence": round(_clamp(61.0 if chain_confidence >= 50 else 50.0), 1),
                "inferred": True,
                "observed": False,
                "kind": "MISSING_EXECUTION_STEP",
                "reason": "A file written during the chain was executed, but no explicit user-execution event was captured.",
                "explanation": (
                    f"File(s) {', '.join(sorted(executed_files))[:1]} were created and later executed; "
                    "the click/launch step itself was not observed."
                ),
            }
        )

    steps.sort(key=lambda s: -s["confidence"])
    # keep only the strongest inferences: far-away kill-chain gaps are noise
    steps = [s for s in steps if float(s.get("confidence") or 0) >= 45.0][:4]

    # pre-chain inference: telemetry begins mid-attack with no access/cred/persistence seen
    access_tactics = {"INITIAL ACCESS", "CREDENTIAL ACCESS", "PERSISTENCE"}
    if indices[0] > _INDEX["INITIAL ACCESS"] and not (access_tactics & set(observed)):
        for suggestion in mapper.suggestions_for_tactic("INITIAL ACCESS"):
            meta = mapper.get(suggestion.technique_id)
            steps.append({
                "technique_id": suggestion.technique_id,
                "technique_name": meta.name if meta else suggestion.technique_id,
                "tactic": "INITIAL ACCESS",
                # 46 clears the >=45 reportability floor while staying below gap steps
                "confidence": round(_clamp(46.0), 1),
                "inferred": True,
                "observed": False,
                "kind": "MISSING_PRE_CHAIN",
                "reason": "Telemetry begins mid-kill-chain; the delivery/initial-access step was not captured.",
                "explanation": f"First observed tactic is {observed[0]}; earlier stages likely occurred outside telemetry coverage.",
            })
            break
    steps = [s for s in steps if float(s.get("confidence") or 0) >= 45.0][:4]
    steps.sort(key=lambda s: -s["confidence"])
    return steps
