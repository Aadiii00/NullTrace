"""
KillChain global configuration.
Loads config/killchain.yaml and exposes a singleton Settings object.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

from ruamel.yaml import YAML as _YAML
from pydantic import BaseModel, Field

_yaml_parser = _YAML(typ="safe")

# ── Paths ──────────────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
RULES_DIR = ROOT_DIR / "rules"
REPORTS_DIR = ROOT_DIR / "reports"
CONFIG_FILE = ROOT_DIR / "config" / "killchain.yaml"

DATA_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)


# ── Sub-config models ──────────────────────────────────────────────────────────
class IngestionConfig(BaseModel):
    chunk_size: int = 1000
    memory_limit_mb: int = 512
    threads: int = 4
    max_records: Optional[int] = None          # None = unlimited
    duplicate_detection: bool = True
    preserve_raw: bool = True


class CorrelationConfig(BaseModel):
    # Time window in seconds for temporal grouping
    time_window_seconds: int = 3600
    # Sequence-proximity window (lines)
    sequence_window: int = 500
    # Clock-skew tolerance seconds
    clock_skew_seconds: int = 60
    # Minimum score to accept a relationship
    min_relationship_score: int = 40
    # Weights (sum should be ~100)
    weight_process_entity: int = 30
    weight_process_lineage: int = 25
    weight_host_user: int = 15
    weight_network_auth: int = 15
    weight_sequence: int = 10
    weight_temporal: int = 5


class ScoringConfig(BaseModel):
    # Crown-jewel hosts — raise risk when involved
    crown_jewel_hosts: List[str] = Field(
        default=["SRV-DC-01", "SRV-DB-01", "SRV-FILE-01", "SRV-WEB-01"]
    )
    # Sensitive accounts — raise risk when involved
    sensitive_accounts: List[str] = Field(
        default=["svc_sql", "svc_backup"]
    )


class LiveConfig(BaseModel):
    poll_interval_seconds: float = 2.0
    batch_size: int = 100


class Settings(BaseModel):
    db_path: str = str(DATA_DIR / "killchain.duckdb")
    ingestion: IngestionConfig = Field(default_factory=IngestionConfig)
    correlation: CorrelationConfig = Field(default_factory=CorrelationConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    live: LiveConfig = Field(default_factory=LiveConfig)
    # Suspicious domain blocklist — loaded from config or defaults
    suspicious_domains: List[str] = Field(
        default=[
            "sim-exfil.example",
            "suspicious-example-c2.invalid",
            "bad-domain-demo.test",
        ]
    )
    # Suspicious external IPs
    suspicious_ips: List[str] = Field(
        default=["192.0.2.88", "203.0.113.57", "198.51.100.23"]
    )


def load_settings(config_path: Optional[Path] = None) -> Settings:
    """Load settings from YAML file, falling back to defaults."""
    path = config_path or CONFIG_FILE
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            raw = _yaml_parser.load(f) or {}
        return Settings(**raw)
    return Settings()


# Singleton
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def reset_settings(new_settings: Optional[Settings] = None) -> Settings:
    """Replace the singleton — used in tests."""
    global _settings
    _settings = new_settings or load_settings()
    return _settings
