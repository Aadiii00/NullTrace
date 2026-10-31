"""
KillChain detection data models.
Defines detection rules, alert severity levels, and detection records.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_int(cls, val: int) -> Severity:
        if val >= 9:
            return cls.CRITICAL
        if val >= 7:
            return cls.HIGH
        if val >= 4:
            return cls.MEDIUM
        if val >= 1:
            return cls.LOW
        return cls.INFORMATIONAL

    def to_int(self) -> int:
        mapping = {
            self.INFORMATIONAL: 1,
            self.LOW: 3,
            self.MEDIUM: 5,
            self.HIGH: 8,
            self.CRITICAL: 10,
        }
        return mapping[self]


class MITRETactic(str, Enum):
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class DetectionRule(BaseModel):
    rule_id: str
    name: str
    description: str
    severity: int = 5
    confidence: float = 0.85
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_tactic: str
    enabled: bool = True
    tags: List[str] = Field(default_factory=list)


class DetectionRecord(BaseModel):
    detection_id: str
    rule_id: str
    rule_name: str
    event_id: str
    dataset_id: str
    seq_num: int
    timestamp_utc: Optional[str] = None
    host_name: Optional[str] = None
    user_name: Optional[str] = None
    severity: int = 5
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_tactic: str
    match_context: Dict[str, Any] = Field(default_factory=dict)
    false_positive_risk: str = "LOW"
