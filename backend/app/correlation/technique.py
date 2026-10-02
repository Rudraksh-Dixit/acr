"""MITRE ATT&CK progression signal: does the pair fit a plausible attack order?"""
from __future__ import annotations

from typing import Any, Optional

from app.core.config import TACTIC_ORDER
from app.mitre import get_mapper

_TACTIC_INDEX = {name: i for i, name in enumerate(TACTIC_ORDER)}


def tactic_of(event: dict[str, Any]) -> Optional[str]:
    tactic = event.get("tactic")
    if tactic:
        return str(tactic).upper()
    mapper = get_mapper()
    return mapper.tactic_for(event.get("technique_id"))


def tactic_index(tactic: Optional[str]) -> Optional[int]:
    if not tactic:
        return None
    return _TACTIC_INDEX.get(str(tactic).upper())


def progression(a: dict[str, Any], b: dict[str, Any]) -> tuple[Optional[float], str]:
    """Return (factor, detail).

    factor 1.0  -> b's tactic happens after a's in the kill chain (normal flow)
    factor 0.6  -> forward but a large jump (e.g. INITIAL ACCESS -> C2)
    factor 0.3  -> reversed order (telemetry out of order or noisy mapping)
    factor None -> not enough technique information to judge
    """
    ta, tb = tactic_of(a), tactic_of(b)
    ia, ib = tactic_index(ta), tactic_index(tb)
    if ia is None or ib is None:
        return None, ""
    # order by timestamp so "forward" means forward in the attack
    first, second = (ia, ib)
    ta_name, tb_name = ta, tb
    ts_a, ts_b = a.get("timestamp"), b.get("timestamp")
    if ts_a and ts_b and ts_b < ts_a:
        first, second = ib, ia
        ta_name, tb_name = tb, ta
    if second >= first:
        gap = second - first
        factor = 1.0 if gap <= 6 else 0.6
        return factor, f"{ta_name} -> {tb_name} progression consistent"
    return 0.3, f"{ta_name} -> {tb_name} reversed vs kill-chain order"


def observed_tactics(events: list[dict[str, Any]]) -> list[str]:
    seen: list[str] = []
    for event in events:
        tactic = tactic_of(event)
        if tactic and tactic not in seen:
            seen.append(tactic)
    return sorted(seen, key=lambda t: tactic_index(t) if tactic_index(t) is not None else 99)
