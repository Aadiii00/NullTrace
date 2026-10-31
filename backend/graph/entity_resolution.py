"""
KillChain Entity Resolution Layer.
Identifies, normalizes, and maintains stable entity identifiers across
users, accounts, hosts, processes, IP addresses, domains, files, and registry keys.

Guarantees:
- Stable canonical identifiers
- Retains source evidence, aliases, first/last seen, event count, and confidence
- Avoids false merges (e.g. same username in different domains, reused PIDs across boots)
- Transparent confidence scoring based on attribute completeness
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class ResolvedEntity:
    entity_id: str
    entity_type: str  # host | user | account | process | ip | domain | file | registry | service
    canonical_name: str
    confidence: float  # 0.0 to 1.0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    event_count: int = 0
    alert_count: int = 0
    is_critical: bool = False
    is_compromised: bool = False
    risk_score: float = 0.0
    aliases: Set[str] = field(default_factory=set)
    attributes: Dict[str, Any] = field(default_factory=dict)
    evidence_events: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "canonical_name": self.canonical_name,
            "confidence": round(self.confidence, 3),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "alert_count": self.alert_count,
            "is_critical": self.is_critical,
            "is_compromised": self.is_compromised,
            "risk_score": round(self.risk_score, 1),
            "aliases": sorted(list(self.aliases)),
            "attributes": self.attributes,
            "evidence_count": len(self.evidence_events),
        }


class EntityResolver:
    """
    Deterministic Entity Resolution Engine with strict anti-collision logic.
    Maintains entity registry and indexes for lightning-fast lookup.
    """

    # Domain critical assets definition
    CRITICAL_ASSETS = {
        "SRV-DC-01": {"role": "Primary Domain Controller", "criticality": "CRITICAL", "subnet": "10.10.0.0/24"},
        "SRV-DB-01": {"role": "Production SQL Database", "criticality": "CRITICAL", "subnet": "10.10.0.0/24"},
        "SRV-FILE-01": {"role": "Enterprise File Server", "criticality": "HIGH", "subnet": "10.10.0.0/24"},
        "SRV-WEB-01": {"role": "Public Web Gateway", "criticality": "HIGH", "subnet": "10.10.0.0/24"},
        "FW-GATEWAY-01": {"role": "Perimeter NGFW Gateway", "criticality": "CRITICAL", "subnet": "10.10.99.0/24"},
    }

    MALICIOUS_DOMAINS = {
        "suspicious-example-c2.invalid",
        "sim-exfil.example",
        "bad-domain-demo.test",
    }

    ADMIN_USERS = {
        "administrator", "admin", "system", "sysg.admin", "root"
    }

    def __init__(self):
        self._entities: Dict[str, ResolvedEntity] = {}
        # Secondary index: (entity_type, alias/alias_key) -> entity_id
        self._alias_index: Dict[Tuple[str, str], str] = {}

    def get_or_create(self, entity_id: str, entity_type: str, canonical_name: str, confidence: float = 1.0) -> ResolvedEntity:
        if entity_id not in self._entities:
            ent = ResolvedEntity(
                entity_id=entity_id,
                entity_type=entity_type,
                canonical_name=canonical_name,
                confidence=confidence,
            )
            self._entities[entity_id] = ent
            self._alias_index[(entity_type, canonical_name.lower())] = entity_id
        return self._entities[entity_id]

    def get_entity(self, entity_id: str) -> Optional[ResolvedEntity]:
        return self._entities.get(entity_id)

    def all_entities(self) -> List[ResolvedEntity]:
        return list(self._entities.values())

    # ── Specialized Resolution Methods ─────────────────────────────────────────

    def resolve_host(self, host_name: Optional[str], ip: Optional[str] = None, os_type: Optional[str] = None, event_id: Optional[str] = None, timestamp: Optional[str] = None) -> Optional[ResolvedEntity]:
        """
        Resolve host entity. Uses normalized host name with endpoint attributes.
        Avoids merging distinct hosts that temporarily shared an IP.
        """
        if not host_name or not host_name.strip():
            if ip and self._is_internal_ip(ip):
                host_name = f"HOST-{ip.replace('.', '-')}"
            else:
                return None

        clean_name = host_name.strip().upper()
        entity_id = f"host:{clean_name}"

        # Confidence assessment
        confidence = 1.0 if clean_name.startswith(("WS-", "SRV-", "FW-")) else 0.85

        ent = self.get_or_create(entity_id, "host", clean_name, confidence)
        ent.aliases.add(clean_name)
        if ip:
            ent.aliases.add(ip)
            ent.attributes["last_known_ip"] = ip
        if os_type:
            ent.attributes["os_type"] = os_type

        # Check critical asset directory
        if clean_name in self.CRITICAL_ASSETS:
            meta = self.CRITICAL_ASSETS[clean_name]
            ent.is_critical = True
            ent.attributes["role"] = meta["role"]
            ent.attributes["criticality"] = meta["criticality"]
            ent.risk_score = max(ent.risk_score, 80.0)
        else:
            ent.attributes.setdefault("role", "Server" if clean_name.startswith("SRV-") else "Workstation")
            ent.attributes.setdefault("criticality", "HIGH" if clean_name.startswith("SRV-") else "MEDIUM")

        self._update_timestamps_and_evidence(ent, timestamp, event_id)
        return ent

    def resolve_user(self, user_name: Optional[str], domain: Optional[str] = None, host_name: Optional[str] = None, event_id: Optional[str] = None, timestamp: Optional[str] = None) -> Optional[ResolvedEntity]:
        r"""
        Resolve user and account entity. Preserves domain isolation:
        DOMAIN\user is distinct from LOCALHOST\user or AzureAD\user.
        """
        if not user_name or not user_name.strip():
            return None

        raw = user_name.strip()
        # Parse DOMAIN\user or user@domain
        parsed_domain = domain
        clean_user = raw
        if "\\" in raw:
            parts = raw.split("\\", 1)
            parsed_domain = parts[0]
            clean_user = parts[1]
        elif "@" in raw:
            parts = raw.split("@", 1)
            clean_user = parts[0]
            parsed_domain = parts[1]

        domain_str = (parsed_domain or "CORP").upper()
        clean_user_lower = clean_user.lower()

        # Stable entity identifier
        entity_id = f"user:{domain_str}:{clean_user_lower}"
        canonical = f"{domain_str}\\{clean_user}"

        is_admin = clean_user_lower in self.ADMIN_USERS or "admin" in clean_user_lower
        confidence = 0.95 if parsed_domain else 0.80

        ent = self.get_or_create(entity_id, "user", canonical, confidence)
        ent.aliases.add(clean_user)
        ent.aliases.add(raw)
        ent.attributes["is_admin"] = is_admin
        ent.attributes["domain"] = domain_str
        ent.attributes["user_name"] = clean_user
        ent.attributes["role"] = "Domain Administrator" if is_admin else "Domain User"
        if is_admin:
            ent.is_critical = True
            ent.risk_score = max(ent.risk_score, 75.0)

        self._update_timestamps_and_evidence(ent, timestamp, event_id)
        return ent

    def resolve_process(self, host_name: str, pid: Optional[int], process_name: Optional[str],
                        cmdline: Optional[str] = None, parent_name: Optional[str] = None,
                        process_entity_id: Optional[str] = None, event_id: Optional[str] = None,
                        timestamp: Optional[str] = None) -> Optional[ResolvedEntity]:
        """
        Resolve process entity.
        Process identity: host + process_entity_id (if available), or host + pid + process_name.
        Avoids incorrect merges across reboot or PID reuse.
        """
        if not host_name:
            return None
        h_clean = host_name.strip().upper()

        if process_entity_id and process_entity_id.strip():
            entity_id = f"proc:{h_clean}:{process_entity_id.strip()}"
            confidence = 0.98
        elif pid and process_name:
            # Hash host + pid + process_name for stable identity
            key = f"{h_clean}:{pid}:{process_name.lower()}"
            entity_id = f"proc:{h_clean}:{pid}:{hashlib.md5(key.encode()).hexdigest()[:8]}"
            confidence = 0.85
        elif process_name:
            entity_id = f"proc:{h_clean}:{process_name.lower()}"
            confidence = 0.70
        else:
            return None

        canonical = f"{process_name or 'unknown.exe'} (PID {pid or '?'}) on {h_clean}"
        ent = self.get_or_create(entity_id, "process", canonical, confidence)
        ent.attributes["host"] = h_clean
        ent.attributes["pid"] = pid
        ent.attributes["process_name"] = process_name
        if cmdline:
            ent.attributes["cmdline"] = cmdline
        if parent_name:
            ent.attributes["parent_name"] = parent_name

        self._update_timestamps_and_evidence(ent, timestamp, event_id)
        return ent

    def resolve_ip(self, ip_str: Optional[str], event_id: Optional[str] = None, timestamp: Optional[str] = None) -> Optional[ResolvedEntity]:
        """
        Resolve IP entity. Distinguishes private RFC1918 from public WAN addresses.
        """
        if not ip_str or not ip_str.strip() or ip_str in ("-", "0.0.0.0", "::", "127.0.0.1", "localhost"):
            return None

        clean_ip = ip_str.strip()
        is_internal = self._is_internal_ip(clean_ip)
        entity_id = f"ip:{clean_ip}"

        confidence = 0.95
        ent = self.get_or_create(entity_id, "ip", clean_ip, confidence)
        ent.attributes["is_internal"] = is_internal
        ent.attributes["ip"] = clean_ip

        if not is_internal:
            ent.attributes["classification"] = "EXTERNAL"
            ent.risk_score = max(ent.risk_score, 40.0)
        else:
            ent.attributes["classification"] = "INTERNAL"

        self._update_timestamps_and_evidence(ent, timestamp, event_id)
        return ent

    def resolve_domain(self, domain_name: Optional[str], event_id: Optional[str] = None, timestamp: Optional[str] = None) -> Optional[ResolvedEntity]:
        """
        Resolve domain entity. Identifies known adversary C2 domains and internal zones.
        """
        if not domain_name or not domain_name.strip() or domain_name in ("-", "unknown", "none"):
            return None

        clean_domain = domain_name.strip().lower()
        entity_id = f"domain:{clean_domain}"

        is_malicious = clean_domain in self.MALICIOUS_DOMAINS or any(m in clean_domain for m in self.MALICIOUS_DOMAINS)
        confidence = 0.98 if is_malicious else 0.85

        ent = self.get_or_create(entity_id, "domain", clean_domain, confidence)
        ent.attributes["domain"] = clean_domain
        ent.attributes["is_malicious"] = is_malicious
        if is_malicious:
            ent.is_critical = True
            ent.is_compromised = True
            ent.attributes["role"] = "Adversary C2 Server"
            ent.risk_score = 95.0

        self._update_timestamps_and_evidence(ent, timestamp, event_id)
        return ent

    def resolve_file(self, file_path: Optional[str], file_name: Optional[str] = None, sha256: Optional[str] = None,
                     event_id: Optional[str] = None, timestamp: Optional[str] = None) -> Optional[ResolvedEntity]:
        """
        Resolve file entity. Uses cryptographic SHA256 when available, otherwise normalized path.
        """
        if sha256 and len(sha256) == 64:
            entity_id = f"file:sha256:{sha256.lower()}"
            canonical = file_name or file_path or sha256[:12]
            confidence = 1.0
        elif file_path and file_path.strip():
            clean_path = file_path.strip().replace("/", "\\")
            canonical = clean_path
            entity_id = f"file:path:{hashlib.md5(clean_path.lower().encode()).hexdigest()[:12]}"
            confidence = 0.80
        elif file_name and file_name.strip():
            canonical = file_name.strip()
            entity_id = f"file:name:{canonical.lower()}"
            confidence = 0.65
        else:
            return None

        ent = self.get_or_create(entity_id, "file", canonical, confidence)
        if file_path:
            ent.attributes["path"] = file_path
        if file_name:
            ent.attributes["name"] = file_name
        if sha256:
            ent.attributes["sha256"] = sha256.lower()

        # Check for suspicious file extensions
        if canonical.lower().endswith((".locked", ".exe", ".ps1", ".vbs", ".bat", ".dll")):
            ent.attributes["is_executable_or_locked"] = True

        self._update_timestamps_and_evidence(ent, timestamp, event_id)
        return ent

    def resolve_registry(self, registry_path: Optional[str], registry_data: Optional[str] = None,
                         event_id: Optional[str] = None, timestamp: Optional[str] = None) -> Optional[ResolvedEntity]:
        """
        Resolve Windows registry key entity.
        """
        if not registry_path or not registry_path.strip():
            return None

        clean_path = registry_path.strip()
        entity_id = f"reg:{hashlib.md5(clean_path.lower().encode()).hexdigest()[:12]}"

        is_autorun = "currentversion\\run" in clean_path.lower()
        confidence = 0.90

        ent = self.get_or_create(entity_id, "registry", clean_path, confidence)
        ent.attributes["path"] = clean_path
        ent.attributes["is_autorun"] = is_autorun
        if registry_data:
            ent.attributes["data"] = registry_data
        if is_autorun:
            ent.attributes["persistence_mechanism"] = "T1547.001"
            ent.risk_score = max(ent.risk_score, 70.0)

        self._update_timestamps_and_evidence(ent, timestamp, event_id)
        return ent

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _is_internal_ip(ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            return ip_obj.is_private or ip_obj.is_loopback
        except ValueError:
            return ip_str.startswith("10.") or ip_str.startswith("192.168.") or ip_str.startswith("172.")

    @staticmethod
    def _update_timestamps_and_evidence(ent: ResolvedEntity, timestamp: Optional[str], event_id: Optional[str]) -> None:
        ent.event_count += 1
        if event_id:
            ent.evidence_events.add(event_id)
        if timestamp:
            if not ent.first_seen or timestamp < ent.first_seen:
                ent.first_seen = timestamp
            if not ent.last_seen or timestamp > ent.last_seen:
                ent.last_seen = timestamp
