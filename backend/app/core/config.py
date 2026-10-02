"""Application configuration for ACR.

All tunables (time windows, correlation weights, thresholds) live here so the
correlation engine and scoring modules stay data-driven and testable.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[3]  # .../acr (project root)
DATA_DIR = Path(os.environ.get("ACR_DATA_DIR", BASE_DIR / "data"))
DEFAULT_DB_URL = f"sqlite:///{(DATA_DIR / 'acr.db').as_posix()}"

# Correlation signal weights. They deliberately sum to 100 so a pair of events
# that agrees on every signal scores 100. Groups roll up to the documented
# primary signals: shared_network_entity = (same_source_ip + same_destination_ip
# + shared_domain).
DEFAULT_WEIGHTS: dict[str, int] = {
    "temporal": 20,
    "same_host": 20,
    "same_user": 11,
    "same_source_ip": 4,
    "same_destination_ip": 4,
    "shared_domain": 2,
    "process_relationship": 20,
    "shared_file": 4,
    "attack_progression": 10,
    "event_dependency": 5,
}

WEIGHT_GROUPS: dict[str, list[str]] = {
    "temporal": ["temporal"],
    "same_host": ["same_host"],
    "same_user": ["same_user"],
    "shared_network_entity": ["same_source_ip", "same_destination_ip", "shared_domain"],
    "process_relationship": ["process_relationship"],
    "shared_file": ["shared_file"],
    "attack_progression": ["attack_progression"],
    "sequence_match": ["event_dependency"],
}

# Ordered kill-chain style tactic progression used for attack-progression
# scoring and missing-step inference.
TACTIC_ORDER: list[str] = [
    "RECONNAISSANCE",
    "RESOURCE DEVELOPMENT",
    "INITIAL ACCESS",
    "EXECUTION",
    "PERSISTENCE",
    "PRIVILEGE ESCALATION",
    "DEFENSE EVASION",
    "CREDENTIAL ACCESS",
    "DISCOVERY",
    "LATERAL MOVEMENT",
    "COLLECTION",
    "COMMAND AND CONTROL",
    "EXFILTRATION",
    "IMPACT",
]


@dataclass
class Settings:
    app_name: str = "ACR - Attack Chain Reconstruction Engine"
    version: str = "1.0.0"
    debug: bool = False

    database_url: str = field(default_factory=lambda: os.environ.get("ACR_DB_URL", DEFAULT_DB_URL))
    data_dir: Path = field(default_factory=lambda: DATA_DIR)

    # --- temporal correlation windows (seconds) ---
    window_strict: int = 30
    window_normal: int = 120
    window_broad: int = 600

    # --- correlation ---
    weights: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    # minimum pairwise score for two events to be linked in the correlation graph
    min_edge_score: float = 35.0
    # minimum mean internal link score for a cluster to become a chain
    min_chain_confidence: float = 25.0
    max_candidates_per_event: int = 40

    # --- risk / verdict thresholds ---
    attack_confidence_threshold: float = 45.0
    attack_risk_threshold: float = 40.0

    # --- detection ---
    brute_force_failures: int = 5
    brute_force_window: int = 300
    suspicious_dns_length: int = 60

    # --- ingestion safety limits ---
    max_upload_bytes: int = 5_000_000
    max_events_per_ingest: int = 50_000
    max_field_length: int = 8_192

    # --- evaluation ---
    detection_threshold_confidence: float = 45.0

    log_level: str = field(default_factory=lambda: os.environ.get("ACR_LOG_LEVEL", "INFO"))

    def time_windows(self) -> dict[str, int]:
        return {"STRICT": self.window_strict, "NORMAL": self.window_normal, "BROAD": self.window_broad}


settings = Settings()


def get_settings() -> Settings:
    return settings
