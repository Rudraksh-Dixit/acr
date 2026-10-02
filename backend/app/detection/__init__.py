"""Detection engine: runs every registered rule over normalized events.

Rules are deterministic and explainable - each match carries structured
evidence. Stateful rules (brute force) rely on time-ordered input.
"""
from __future__ import annotations

from typing import Iterable

from app.core.config import Settings, settings as default_settings
from app.core.logging import get_logger, log_event
from app.detection.authentication_detection import AUTH_RULES
from app.detection.base import DetectionRule, RuleContext, RuleMatch
from app.detection.network_detection import NETWORK_RULES
from app.detection.process_detection import PROCESS_RULES
from app.detection.rules import GENERIC_RULES

logger = get_logger("detection")

ALL_RULES: list[DetectionRule] = [*AUTH_RULES, *PROCESS_RULES, *NETWORK_RULES, *GENERIC_RULES]

RULE_INDEX: dict[str, DetectionRule] = {rule.rule_id: rule for rule in ALL_RULES}


def get_rules(settings: Settings | None = None) -> list[DetectionRule]:
    """Return enabled rules (settings hook kept for future rule toggles)."""
    _ = settings or default_settings
    return list(ALL_RULES)


def run_detection(
    events: Iterable[dict],
    settings: Settings | None = None,
    rules: list[DetectionRule] | None = None,
) -> list[RuleMatch]:
    """Evaluate all rules against events sorted by timestamp.

    Events with missing timestamps are evaluated last so stateful rules see a
    sensible ordering; they are still matched on content alone.
    """
    cfg = settings or default_settings
    ctx = RuleContext(cfg)
    event_list = list(events)
    ordered = sorted(event_list, key=lambda e: (e.get("timestamp") is None, e.get("timestamp") or 0))
    selected = rules if rules is not None else get_rules(cfg)
    matches: list[RuleMatch] = []
    for event in ordered:
        for rule in selected:
            try:
                match = rule.evaluate(event, ctx)
            except Exception as exc:  # pragma: no cover - defensive
                logger.exception("rule %s failed", rule.rule_id)
                log_event(logger, "rule_error", rule=rule.rule_id, error=str(exc))
                continue
            if match is not None:
                matches.append(match)
    log_event(logger, "detection_complete", events=len(event_list), matches=len(matches), rules=len(selected))
    return matches
