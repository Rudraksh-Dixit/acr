"""Cyber Kill Chain <-> MITRE ATT&CK tactic mapping (single source of truth).

The kill chain stage of a chain or technique is ALWAYS derived from the ATT&CK
tactic via the table below - never stored, never hand-edited per record.

Stages follow the Lockheed Martin Cyber Kill Chain (7 stages, 1-indexed):

    1 Recon  2 Weaponization  3 Delivery  4 Exploitation
    5 Installation  6 C2  7 Actions on Objectives

Mapping rationale (documented, conservative):

    Reconnaissance            -> 1 Recon
    Resource Development      -> 2 Weaponization
    Initial Access            -> 3 Delivery
    Execution                 -> 4 Exploitation
    Persistence               -> 5 Installation
    Privilege Escalation      -> 5 Installation
    Defense Evasion           -> 5 Installation
    Command and Control       -> 6 C2
    Credential Access         -> 7 Actions on Objectives  (objective: secrets)
    Lateral Movement          -> 7 Actions on Objectives
    Discovery                 -> 7 Actions on Objectives
    Collection                -> 7 Actions on Objectives
    Exfiltration              -> 7 Actions on Objectives
    Impact                    -> 7 Actions on Objectives

Unknown tactics map to ``None`` (the API then omits / nulls the field rather
than guessing).
"""
from __future__ import annotations

from typing import Iterable, Optional

KILL_CHAIN_STAGES: tuple[str, ...] = (
    "Recon",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "C2",
    "Actions on Objectives",
)

# ATT&CK tactic (upper-case, as stored by the MITRE mapper) -> stage number
TACTIC_TO_STAGE: dict[str, int] = {
    "RECONNAISSANCE": 1,
    "RESOURCE DEVELOPMENT": 2,
    "INITIAL ACCESS": 3,
    "EXECUTION": 4,
    "PERSISTENCE": 5,
    "PRIVILEGE ESCALATION": 5,
    "DEFENSE EVASION": 5,
    "COMMAND AND CONTROL": 6,
    "CREDENTIAL ACCESS": 7,
    "LATERAL MOVEMENT": 7,
    "DISCOVERY": 7,
    "COLLECTION": 7,
    "EXFILTRATION": 7,
    "IMPACT": 7,
}


def stage_for_tactic(tactic: Optional[str]) -> Optional[int]:
    """Kill chain stage number (1-7) for one ATT&CK tactic, or None."""
    if not tactic:
        return None
    return TACTIC_TO_STAGE.get(str(tactic).strip().upper())


def stage_name(stage: Optional[int]) -> Optional[str]:
    """Human label for a stage number, or None when out of range."""
    if stage is None or not 1 <= stage <= len(KILL_CHAIN_STAGES):
        return None
    return KILL_CHAIN_STAGES[stage - 1]


def furthest_stage(tactics: Optional[Iterable[Optional[str]]]) -> Optional[int]:
    """The most advanced kill chain stage covered by a set of tactics.

    A chain is only as far along as the furthest tactic it actually exhibits,
    so an Initial Access + C2 chain reports stage 6.
    """
    stages = [s for s in (stage_for_tactic(t) for t in (tactics or [])) if s]
    return max(stages) if stages else None


def covered_stages(tactics: Optional[Iterable[Optional[str]]]) -> list[int]:
    """Distinct stages (ascending) covered by a set of tactics."""
    return sorted({s for s in (stage_for_tactic(t) for t in (tactics or [])) if s})
