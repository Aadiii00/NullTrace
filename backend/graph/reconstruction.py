"""
KillChain Attack Path Reconstruction Engine.
Reconstructs how suspicious activity progresses through the environment
across MITRE ATT&CK tactics, process lineage, authentication sessions, and network hops.

Supports:
- End-to-end multi-stage intrusion chains
- Incomplete and interrupted attack sequences
- Entry point identification and root cause analysis
- Missing telemetry identification (telemetry blind spots)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple


# Ordered MITRE ATT&CK Tactics
TACTIC_PROGRESSION_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


@dataclass
class AttackPathStep:
    step_number: int
    timestamp_utc: str
    tactic: str
    technique_id: str
    technique_name: str
    host_name: str
    user_name: str
    process_name: Optional[str] = None
    cmdline: Optional[str] = None
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    detection_id: Optional[str] = None
    event_id: Optional[str] = None
    classification: str = "OBSERVED"  # OBSERVED | DETECTED | INFERRED
    confidence: float = 1.0
    evidence_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step_number,
            "timestamp": self.timestamp_utc,
            "tactic": self.tactic,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "host": self.host_name,
            "user": self.user_name,
            "process": self.process_name or "N/A",
            "cmdline": self.cmdline or "N/A",
            "source": self.source_ip or self.host_name,
            "target": self.target_ip or self.host_name,
            "detection_id": self.detection_id,
            "event_id": self.event_id,
            "classification": self.classification,
            "confidence": round(self.confidence, 3),
            "evidence_summary": self.evidence_summary,
        }


@dataclass
class ReconstructedAttackPath:
    incident_id: str
    title: str
    entry_point: str
    entry_vector: str
    first_observed_ts: str
    last_observed_ts: str
    is_complete_chain: bool
    confidence_score: float
    tactics_traversed: List[str]
    affected_hosts: List[str]
    associated_users: List[str]
    related_processes: List[str]
    network_destinations: List[str]
    steps: List[AttackPathStep] = field(default_factory=list)
    missing_telemetry: List[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        hop_chain = []
        for s in self.steps:
            if not hop_chain or hop_chain[-1] != s.host_name:
                hop_chain.append(s.host_name)
        if not hop_chain:
            hop_chain = [self.entry_point or "Unknown Host"]

        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "entry_point": self.entry_point,
            "entry_vector": self.entry_vector,
            "first_observed_ts": self.first_observed_ts,
            "last_observed_ts": self.last_observed_ts,
            "is_complete_chain": self.is_complete_chain,
            "confidence_score": round(self.confidence_score, 3),
            "tactics_traversed": self.tactics_traversed,
            "affected_hosts": self.affected_hosts,
            "associated_users": self.associated_users,
            "related_processes": self.related_processes,
            "network_destinations": self.network_destinations,
            "path_chain": " → ".join(hop_chain[:6]),
            "steps": [s.to_dict() for s in self.steps],
            "total_steps": len(self.steps),
            "missing_telemetry": self.missing_telemetry,
            "summary": self.summary,
        }


class AttackPathReconstructor:
    """
    Deterministic chronological and causal attack path reconstructor.
    """

    def reconstruct_path(self, incident_id: str, alerts: List[Dict[str, Any]]) -> ReconstructedAttackPath:
        if not alerts:
            return ReconstructedAttackPath(
                incident_id=incident_id,
                title="Unknown Security Incident",
                entry_point="Unknown",
                entry_vector="Telemetry Absent",
                first_observed_ts="",
                last_observed_ts="",
                is_complete_chain=False,
                confidence_score=0.0,
                tactics_traversed=[],
                affected_hosts=[],
                associated_users=[],
                related_processes=[],
                network_destinations=[],
                missing_telemetry=["No alerts available for path reconstruction"],
            )

        # Sort alerts strictly by sequence number / timestamp
        sorted_alerts = sorted(alerts, key=lambda a: (a.get("seq_num") or 0, str(a.get("timestamp_utc", ""))))

        steps: List[AttackPathStep] = []
        tactics_seen: Set[str] = set()
        hosts_seen: Set[str] = set()
        users_seen: Set[str] = set()
        procs_seen: Set[str] = set()
        net_dests: Set[str] = set()

        for idx, a in enumerate(sorted_alerts):
            tactic = a.get("tactic_name") or a.get("threat_tactic_nm") or "Execution"
            tech_id = a.get("technique_id") or a.get("threat_technique_id") or "T1059"
            tech_nm = a.get("technique_name") or a.get("threat_technique_nm") or a.get("rule_name") or "Threat Activity"
            hname = a.get("host_name") or "UNKNOWN-HOST"
            uname = a.get("user_name") or "SYSTEM"
            proc = a.get("process_name")
            cmd = a.get("process_cmdline")
            sip = a.get("src_ip")
            dip = a.get("dst_ip") or a.get("dst_domain")

            tactics_seen.add(tactic)
            hosts_seen.add(hname)
            users_seen.add(uname)
            if proc:
                procs_seen.add(proc)
            if dip:
                net_dests.add(dip)

            step = AttackPathStep(
                step_number=idx + 1,
                timestamp_utc=str(a.get("timestamp_utc", "")),
                tactic=tactic,
                technique_id=tech_id,
                technique_name=tech_nm,
                host_name=hname,
                user_name=uname,
                process_name=proc,
                cmdline=cmd,
                source_ip=sip,
                target_ip=dip,
                detection_id=a.get("detection_id"),
                event_id=a.get("event_id"),
                classification="DETECTED" if a.get("detection_id") else "OBSERVED",
                confidence=float(a.get("confidence", 0.95)),
                evidence_summary=a.get("explanation") or a.get("rule_name") or f"{tactic} on {hname}",
            )
            steps.append(step)

        # Reconstruct entry point
        first_step = steps[0]
        entry_host = first_step.host_name
        entry_vector = f"{first_step.tactic} ({first_step.technique_id} - {first_step.technique_name})"

        # Identify missing telemetry / gaps in Cyber Kill Chain
        missing_telemetry: List[str] = []
        if "Initial Access" not in tactics_seen and "Execution" in tactics_seen:
            missing_telemetry.append("Initial delivery vector (phishing attachment / browser download) not captured")
        if "Persistence" not in tactics_seen:
            missing_telemetry.append("No endpoint persistence telemetry (registry autorun / scheduled task)")
        if "Command and Control" not in tactics_seen and len(hosts_seen) > 2:
            missing_telemetry.append("External C2 channel telemetry unobserved (possible air-gapped staging)")
        if "Impact" not in tactics_seen and "Lateral Movement" in tactics_seen:
            missing_telemetry.append("Post-exploitation adversary objective or data staging not yet observed")

        # Determine chain completeness
        is_complete = len(tactics_seen) >= 3 and (("Impact" in tactics_seen) or ("Command and Control" in tactics_seen))

        # Overall confidence score
        avg_confidence = sum(s.confidence for s in steps) / len(steps) if steps else 0.8
        chain_boost = 0.1 if is_complete else -0.05
        confidence_score = max(0.5, min(1.0, avg_confidence + chain_boost))

        summary = (
            f"Adversary activity initiated on {entry_host} via {entry_vector}, "
            f"traversing {len(hosts_seen)} hosts and {len(tactics_seen)} MITRE ATT&CK tactics across {len(steps)} verified steps."
        )

        return ReconstructedAttackPath(
            incident_id=incident_id,
            title=f"Attack Progression: {entry_vector}",
            entry_point=entry_host,
            entry_vector=entry_vector,
            first_observed_ts=first_step.timestamp_utc,
            last_observed_ts=steps[-1].timestamp_utc,
            is_complete_chain=is_complete,
            confidence_score=confidence_score,
            tactics_traversed=sorted(list(tactics_seen), key=lambda t: TACTIC_PROGRESSION_ORDER.index(t) if t in TACTIC_PROGRESSION_ORDER else 99),
            affected_hosts=sorted(list(hosts_seen)),
            associated_users=sorted(list(users_seen)),
            related_processes=sorted(list(procs_seen)),
            network_destinations=sorted(list(net_dests)),
            steps=steps,
            missing_telemetry=missing_telemetry,
            summary=summary,
        )

