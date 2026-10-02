"""Local MITRE ATT&CK mapper.

Everything is loaded from techniques.json so ACR works offline and the mapping
stays auditable. The mapper resolves event technique ids to names/tactics,
answers coverage queries and powers missing-step inference.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Optional

TECHNIQUES_PATH = Path(__file__).with_name("techniques.json")


@dataclass(frozen=True)
class TechniqueMeta:
    technique_id: str
    name: str
    tactic: str
    description: str
    subtechnique_of: Optional[str] = None
    detection_hint: Optional[str] = None

    @property
    def is_subtechnique(self) -> bool:
        return bool(self.subtechnique_of)

    def to_dict(self) -> dict[str, Any]:
        from app.core.killchain import stage_for_tactic

        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "description": self.description,
            "subtechnique_of": self.subtechnique_of,
            "detection_hint": self.detection_hint,
            "is_subtechnique": self.is_subtechnique,
            "kill_chain_stage": stage_for_tactic(self.tactic),
        }


@dataclass(frozen=True)
class MissingStepSuggestion:
    technique_id: str
    tactic: str
    reason: str
    inferred: bool = True


class MitreMapper:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.version = payload.get("version", "unknown")
        self.tactics: list[str] = [t["name"] for t in payload.get("tactics", [])]
        self.techniques: dict[str, TechniqueMeta] = {
            t["technique_id"]: TechniqueMeta(
                technique_id=t["technique_id"],
                name=t["name"],
                tactic=t["tactic"].upper(),
                description=t.get("description", ""),
                subtechnique_of=t.get("subtechnique_of"),
                detection_hint=t.get("detection_hint"),
            )
            for t in payload.get("techniques", [])
        }
        self._suggestions: dict[str, list[dict[str, str]]] = payload.get("missing_step_suggestions", {})

    # --- lookups ---------------------------------------------------------
    def get(self, technique_id: Optional[str]) -> Optional[TechniqueMeta]:
        if not technique_id:
            return None
        return self.techniques.get(str(technique_id).upper())

    def tactic_for(self, technique_id: Optional[str]) -> Optional[str]:
        tech = self.get(technique_id)
        if tech:
            return tech.tactic
        if technique_id and "." in str(technique_id):
            parent = self.get(str(technique_id).split(".", 1)[0])
            if parent:
                return parent.tactic
        return None

    def name_for(self, technique_id: Optional[str]) -> Optional[str]:
        tech = self.get(technique_id)
        if tech:
            return tech.name
        if technique_id and "." in str(technique_id):
            parent = self.get(str(technique_id).split(".", 1)[0])
            if parent:
                return parent.name
        return None

    def normalize_technique_id(self, technique_id: Optional[str]) -> Optional[str]:
        if not technique_id:
            return None
        upper = str(technique_id).strip().upper()
        if upper in self.techniques:
            return upper
        if "." in upper and upper.split(".", 1)[0] in self.techniques:
            return upper  # unknown subtechnique, keep as-is
        if upper in self.techniques:
            return upper
        return upper if upper.startswith("T") else None

    def annotate(self, event: dict[str, Any]) -> dict[str, Any]:
        """Fill technique_name/tactic on an event dict when only an id is known."""
        tid = self.normalize_technique_id(event.get("technique_id"))
        if tid:
            event["technique_id"] = tid
            event["technique_name"] = event.get("technique_name") or self.name_for(tid)
            event["tactic"] = event.get("tactic") or self.tactic_for(tid)
        return event

    # --- coverage --------------------------------------------------------
    def coverage(self, technique_ids: Iterable[str]) -> dict[str, Any]:
        by_tactic: dict[str, list[dict[str, str]]] = {}
        seen: set[str] = set()
        for raw in technique_ids:
            tid = self.normalize_technique_id(raw)
            if not tid or tid in seen:
                continue
            seen.add(tid)
            meta = self.get(tid)
            if not meta:
                continue
            by_tactic.setdefault(meta.tactic, []).append({"technique_id": tid, "name": meta.name})
        ordered = [t for t in self.tactics if t in by_tactic]
        ordered += [t for t in by_tactic if t not in ordered]
        return {
            "tactics": [{"tactic": t, "techniques": by_tactic[t], "count": len(by_tactic[t])} for t in ordered],
            "unique_techniques": len(seen),
            "unique_tactics": len(by_tactic),
        }

    # --- missing-step inference source ------------------------------------
    def suggestions_for_tactic(self, tactic: str) -> list[MissingStepSuggestion]:
        out: list[MissingStepSuggestion] = []
        for item in self._suggestions.get(tactic.upper(), []):
            tid = item["technique_id"]
            meta = self.get(tid)
            out.append(
                MissingStepSuggestion(
                    technique_id=tid,
                    tactic=(meta.tactic if meta else tactic).upper(),
                    reason=item.get("reason", ""),
                    inferred=True,
                )
            )
        return out

    def to_db_rows(self) -> list[dict[str, Any]]:
        return [
            {
                "technique_id": t.technique_id,
                "name": t.name,
                "tactic": t.tactic,
                "description": t.description,
                "subtechnique_of": t.subtechnique_of,
                "is_subtechnique": t.is_subtechnique,
                "detection_hint": t.detection_hint,
            }
            for t in self.techniques.values()
        ]


@lru_cache(maxsize=1)
def load_mapper(path: str = str(TECHNIQUES_PATH)) -> MitreMapper:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return MitreMapper(payload)


def get_mapper() -> MitreMapper:
    return load_mapper()


def sync_techniques_to_db(session: Any) -> int:
    from app.models import Technique

    mapper = get_mapper()
    count = 0
    for row in mapper.to_db_rows():
        existing = session.get(Technique, row["technique_id"])
        if existing is None:
            session.add(Technique(**row))
            count += 1
        else:
            for key, value in row.items():
                setattr(existing, key, value)
    session.flush()
    return count
