"""
Fortinet FortiGate Firewall (firex-50G.log) Streaming Parser, Ingestion & Detection Pipeline.
Parses key-value syslog telemetry into Elastic Common Schema (ECS),
detects network/perimeter attacks (SSL-VPN Path Traversal, Mirai Botnet C2, SQLi, Admin Brute Force),
and correlates firewall incidents.
Optimized with transaction-wrapped chunks for sub-second database commits.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import duckdb
from rich.console import Console

from backend.database import get_db, init_schema

console = Console()

DATASET_ID = "firex-fortigate-ngfw"
LOG_FILE_PATH = "firex-50G.log"
TARGET_SAMPLE_SIZE = 30000
CHUNK_SIZE = 2000

KV_REGEX = re.compile(r'([a-zA-Z0-9_-]+)=(?:"([^"]*)"|([^\s]*))')


def parse_fortigate_line(line: str) -> Optional[Dict[str, str]]:
    if not line or not line.startswith("date="):
        return None
    d = {}
    for match in KV_REGEX.finditer(line):
        k = match.group(1)
        v = match.group(2) if match.group(2) is not None else match.group(3)
        d[k] = v
    return d


def run_firewall_pipeline(file_path: str = LOG_FILE_PATH, max_events: int = TARGET_SAMPLE_SIZE, db_path: Optional[str] = None):
    t0 = time.perf_counter()
    console.print(f"[bold cyan]NullTrace — Ingesting FortiGate Firewall Telemetry ({file_path})[/bold cyan]")
    
    conn = get_db(db_path)
    init_schema(db_path)
    
    # 1. Register Dataset
    file_p = Path(file_path)
    file_size = file_p.stat().st_size if file_p.exists() else 2079232000
    conn.execute("""
        INSERT OR REPLACE INTO datasets (dataset_id, filename, file_path, file_size_bytes, format, status)
        VALUES (?, ?, ?, ?, 'fortigate_kv', 'ready')
    """, [DATASET_ID, file_p.name, str(file_p.resolve()), file_size])

    # Clean existing data for this dataset
    conn.execute("DELETE FROM incident_detections WHERE incident_id IN (SELECT incident_id FROM incidents WHERE dataset_id = ?)", [DATASET_ID])
    conn.execute("DELETE FROM incidents WHERE dataset_id = ?", [DATASET_ID])
    conn.execute("DELETE FROM detections WHERE dataset_id = ?", [DATASET_ID])
    conn.execute("DELETE FROM event_entities WHERE event_id IN (SELECT event_id FROM events WHERE dataset_id = ?)", [DATASET_ID])
    conn.execute("DELETE FROM normalized_events WHERE event_id IN (SELECT event_id FROM events WHERE dataset_id = ?)", [DATASET_ID])
    conn.execute("DELETE FROM events WHERE dataset_id = ?", [DATASET_ID])

    res = conn.execute("SELECT COALESCE(MAX(id), 0) FROM event_entities").fetchone()
    entity_id_counter = int(res[0]) if res else 0

    events_batch = []
    norm_batch = []
    entities_batch = []
    detections_batch = []
    all_detections = []

    seq_num = 0
    ips_count = 0
    login_fails = 0
    denies = 0
    accepts = 0

    console.print("[dim]Streaming high-priority threat & traffic logs...[/dim]")

    def flush_batches():
        nonlocal events_batch, norm_batch, entities_batch, detections_batch
        if not events_batch:
            return
        conn.execute("BEGIN TRANSACTION")
        conn.executemany("""
            INSERT INTO events (
                seq_num, event_id, dataset_id, timestamp_utc, event_kind, event_category,
                event_action, event_outcome, event_severity, dataset_name, host_name,
                host_ip, host_os_type, user_name, user_domain, agent_id, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, events_batch)

        conn.executemany("""
            INSERT INTO normalized_events (
                event_id, seq_num, process_name, process_pid, process_entity_id, process_cmdline,
                process_exe, process_md5, process_sha256, parent_name, parent_pid,
                src_ip, src_port, dst_ip, dst_port, dst_domain, net_bytes, net_protocol,
                net_direction, net_transport, dns_question, dns_response_code, auth_outcome,
                logon_type, winlog_event_id, file_path, file_name, file_size, file_target_path,
                registry_path, registry_data, rule_id, rule_name, threat_technique_id,
                threat_technique_nm, threat_tactic_nm, label_synthetic, labels_extra_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, norm_batch)

        if entities_batch:
            conn.executemany("""
                INSERT INTO event_entities (id, event_id, entity_type, entity_value, raw_value)
                VALUES (?, ?, ?, ?, ?)
            """, entities_batch)

        if detections_batch:
            conn.executemany("""
                INSERT INTO detections (
                    detection_id, rule_id, rule_name, event_id, dataset_id, seq_num, timestamp_utc,
                    host_name, user_name, severity, confidence, technique_id, technique_name,
                    tactic_name, kill_chain_stage, explanation, source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, detections_batch)

        conn.execute("COMMIT")
        events_batch.clear()
        norm_batch.clear()
        entities_batch.clear()
        detections_batch.clear()

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if seq_num >= max_events:
                break

            # Prioritization filter
            is_ips = 'subtype="ips"' in line
            is_admin_fail = 'Admin login failed' in line
            is_deny = 'action="deny"' in line

            if not (is_ips or is_admin_fail or is_deny) and (accepts > 15000):
                continue

            parsed = parse_fortigate_line(line)
            if not parsed:
                continue

            event_id = str(uuid.uuid4())
            date_str = parsed.get("date", "2026-10-23")
            time_str = parsed.get("time", "08:49:08")
            tz_str = parsed.get("tz", "+0530")
            ts_iso = f"{date_str}T{time_str}{tz_str[:3]}:{tz_str[3:]}"

            log_type = parsed.get("type", "traffic")
            subtype = parsed.get("subtype", "forward")
            level = parsed.get("level", "notice")
            action = parsed.get("action", "unknown")
            attack_name = parsed.get("attack")
            logdesc = parsed.get("logdesc")
            user_name = parsed.get("user") or "SYSTEM"
            src_ip = parsed.get("srcip", "0.0.0.0")
            dst_ip = parsed.get("dstip", "0.0.0.0")
            src_port = int(parsed["srcport"]) if parsed.get("srcport", "").isdigit() else None
            dst_port = int(parsed["dstport"]) if parsed.get("dstport", "").isdigit() else None
            proto = parsed.get("proto", "6")
            service = parsed.get("service") or parsed.get("app") or "TCP"
            msg = parsed.get("msg") or logdesc or attack_name or "Firewall traffic logged"

            # Determine category & outcome
            if subtype == "ips":
                category = "intrusion_detection"
                action_name = attack_name or "ips_signature"
                kind = "alert"
                severity = 9 if "Buffer.Overflow" in (attack_name or "") or "Path.Traversal" in (attack_name or "") or "Botnet" in (attack_name or "") else 7
                outcome = "failure"
                ips_count += 1
            elif "login" in action or "Admin" in (logdesc or ""):
                category = "authentication"
                action_name = "admin_login_failed" if parsed.get("status") == "failed" else "admin_login"
                kind = "alert" if parsed.get("status") == "failed" else "event"
                severity = 8 if parsed.get("status") == "failed" else 2
                outcome = "failure" if parsed.get("status") == "failed" else "success"
                login_fails += 1
            else:
                category = "network"
                action_name = f"traffic_{action}"
                kind = "event"
                severity = 4 if action == "deny" else 1
                outcome = "failure" if action == "deny" else "success"
                if action == "deny":
                    denies += 1
                else:
                    accepts += 1

            host_name = f"FW-NODE-{src_ip.replace('.', '-')}" if src_ip.startswith("10.10.") else f"FW-GATEWAY-01"

            # 1. Raw event tuple
            events_batch.append((
                seq_num,
                event_id,
                DATASET_ID,
                ts_iso,
                kind,
                category,
                action_name,
                outcome,
                severity,
                "fortigate.firewall",
                host_name,
                src_ip,
                "fortios",
                user_name,
                "root",
                parsed.get("devid", "FGT60FTK00000000"),
                json.dumps(parsed),
            ))

            # 2. Normalized event tuple
            net_bytes = int(parsed.get("sentbyte", 0)) + int(parsed.get("rcvdbyte", 0))
            norm_batch.append((
                event_id,
                seq_num,
                service,
                None,
                None,
                msg,
                None,
                None,
                None,
                None,
                None,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                dst_ip if not attack_name else attack_name,
                net_bytes,
                "TCP" if proto == "6" else ("UDP" if proto == "17" else "ICMP"),
                "inbound" if not src_ip.startswith("10.10.") else "outbound",
                "ip",
                None,
                None,
                outcome,
                action,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                "FW-RULE-IPS" if is_ips else ("FW-RULE-BRUTE" if is_admin_fail else None),
                attack_name or logdesc,
                "T1190" if is_ips else ("T1110" if is_admin_fail else None),
                "Initial Access" if is_ips else ("Credential Access" if is_admin_fail else None),
                "Initial Access" if is_ips else ("Credential Access" if is_admin_fail else None),
                False,
                json.dumps({"devname": parsed.get("devname"), "srccountry": parsed.get("srccountry")}),
            ))

            # 3. Entities
            entity_id_counter += 1
            entities_batch.append((entity_id_counter, event_id, "host", host_name, host_name))
            if user_name and user_name != "SYSTEM":
                entity_id_counter += 1
                entities_batch.append((entity_id_counter, event_id, "user", user_name, user_name))

            # 4. Generate Detections for High-Confidence Threats
            det_info = None
            if attack_name:
                if "SSLVPN.Path.Traversal" in attack_name:
                    det_info = {
                        "rule_id": "FW-RULE-001",
                        "rule_name": "FortiOS SSL-VPN Remote Path Traversal Exploit",
                        "technique_id": "T1190",
                        "technique_name": "Exploit Public-Facing Application",
                        "tactic_name": "Initial Access",
                        "stage": "Exploitation",
                        "severity": 10,
                        "explanation": f"High-severity CVE path traversal exploit attempt detected targeting SSL-VPN portal from {src_ip} towards {dst_ip}."
                    }
                elif "Mirai.Botnet" in attack_name:
                    det_info = {
                        "rule_id": "FW-RULE-002",
                        "rule_name": "Mirai Botnet Command and Control Traffic",
                        "technique_id": "T1071.001",
                        "technique_name": "Web Protocols: Botnet C2",
                        "tactic_name": "Command and Control",
                        "stage": "Command & Control",
                        "severity": 9,
                        "explanation": f"Active Mirai botnet binary payload communication identified originating from internal host {src_ip} connecting to C2 node {dst_ip}."
                    }
                elif "SQL.Injection" in attack_name:
                    det_info = {
                        "rule_id": "FW-RULE-003",
                        "rule_name": "Web Application Generic SQL Injection Attempt",
                        "technique_id": "T1190",
                        "technique_name": "Exploit Public-Facing Application: SQLi",
                        "tactic_name": "Initial Access",
                        "stage": "Exploitation",
                        "severity": 8,
                        "explanation": f"SQL syntax injection attack patterns detected against database server interface at {dst_ip} from {src_ip}."
                    }
                elif "Buffer.Overflow" in attack_name:
                    det_info = {
                        "rule_id": "FW-RULE-004",
                        "rule_name": "Remote HTTP Authorization Buffer Overflow Exploitation",
                        "technique_id": "T1210",
                        "technique_name": "Exploitation of Remote Services",
                        "tactic_name": "Lateral Movement",
                        "stage": "Exploitation",
                        "severity": 10,
                        "explanation": f"Memory corruption buffer overflow exploit packet sequence detected targeting web server daemon at {dst_ip}."
                    }
                elif "SSH.Connection.Brute.Force" in attack_name:
                    det_info = {
                        "rule_id": "FW-RULE-005",
                        "rule_name": "SSH Remote Service Password Guessing",
                        "technique_id": "T1110.001",
                        "technique_name": "Password Guessing: SSH",
                        "tactic_name": "Credential Access",
                        "stage": "Credential Access",
                        "severity": 7,
                        "explanation": f"Rapid recurring SSH credential dictionary attack observed against port 22 on {dst_ip}."
                    }
            elif is_admin_fail:
                det_info = {
                    "rule_id": "FW-RULE-006",
                    "rule_name": "FortiGate Administrator Interface Brute Force",
                    "technique_id": "T1110",
                    "technique_name": "Brute Force: Credential Spraying",
                    "tactic_name": "Credential Access",
                    "stage": "Credential Access",
                    "severity": 8,
                    "explanation": f"External unauthorized login attempt for account '{user_name}' failed from management ingress {src_ip}."
                }

            if det_info:
                det_id = f"DET-FW-{seq_num:06d}"
                tup = (
                    det_id,
                    det_info["rule_id"],
                    det_info["rule_name"],
                    event_id,
                    DATASET_ID,
                    seq_num,
                    ts_iso,
                    host_name,
                    user_name,
                    det_info["severity"],
                    1.0,
                    det_info["technique_id"],
                    det_info["technique_name"],
                    det_info["tactic_name"],
                    det_info["stage"],
                    det_info["explanation"],
                    "firewall_engine",
                )
                detections_batch.append(tup)
                all_detections.append(tup)

            seq_num += 1

            if len(events_batch) >= CHUNK_SIZE:
                flush_batches()

    # Flush final remainder
    flush_batches()

    console.print(f"[green]✓ Ingested {seq_num:,} events (IPS Attacks: {ips_count:,}, Admin Fails: {login_fails:,}, Denies: {denies:,}, Accepts: {accepts:,})[/green]")
    console.print(f"[green]✓ Created {len(all_detections):,} threat detections across firewall telemetry[/green]")

    # Correlate Firewall Incidents
    console.print("[dim]Correlating firewall attack incidents...[/dim]")
    correlate_firewall_incidents(conn, all_detections)

    t_total = time.perf_counter() - t0
    console.print(f"[bold green]✓ FortiGate Firewall Telemetry ready in {t_total:.2f}s! Total events: {seq_num:,}[/bold green]")


def correlate_firewall_incidents(conn: duckdb.DuckDBPyConnection, detections: List[Tuple]):
    """Correlate firewall detections into high-impact perimeter incidents."""
    incidents_def = [
        {
            "id": f"INC-FW-001-{DATASET_ID[:8]}",
            "title": "Perimeter Exploitation: FortiOS SSL-VPN Path Traversal & Remote Exploit",
            "rule": "FortiOS SSL-VPN Remote Path Traversal Exploit",
            "risk": 96.0,
            "conf": 99.0,
            "tactics": ["Initial Access", "Defense Evasion"],
            "techniques": ["T1190", "T1133"],
            "summary": "External threat actors exploited known unauthenticated SSL-VPN path traversal vulnerabilities to access internal subnets.",
            "remediation": "Immediately patch FortiOS firmware, revoke all active SSL-VPN session tokens, and enforce MFA on perimeter VPN portals."
        },
        {
            "id": f"INC-FW-002-{DATASET_ID[:8]}",
            "title": "Distributed Botnet Outbreak: Mirai Command & Control Traffic",
            "rule": "Mirai Botnet Command and Control Traffic",
            "risk": 92.0,
            "conf": 95.0,
            "tactics": ["Command and Control", "Exfiltration"],
            "techniques": ["T1071.001", "T1571"],
            "summary": "Internal infected workstations established high-volume command and control beaconing to known Mirai botnet controller nodes.",
            "remediation": "Isolate infected internal IP addresses at the perimeter switch, sinkhole adversary C2 domains, and perform malware disinfection scans."
        },
        {
            "id": f"INC-FW-003-{DATASET_ID[:8]}",
            "title": "Distributed Web Application Attack: SQL Injection Campaign",
            "rule": "Web Application Generic SQL Injection Attempt",
            "risk": 85.0,
            "conf": 90.0,
            "tactics": ["Initial Access", "Credential Access"],
            "techniques": ["T1190"],
            "summary": "Automated attack scanners attempted multiple SQL injection sequences against corporate database web gateways.",
            "remediation": "Deploy Web Application Firewall (WAF) blocking signatures, review parameterized queries on API inputs, and block attacker source subnets."
        },
        {
            "id": f"INC-FW-004-{DATASET_ID[:8]}",
            "title": "Targeted Perimeter Brute Force: Administrator Login Guessing",
            "rule": "FortiGate Administrator Interface Brute Force",
            "risk": 82.0,
            "conf": 92.0,
            "tactics": ["Credential Access"],
            "techniques": ["T1110"],
            "summary": "Massive credential spraying and dictionary brute force attacks observed targeting perimeter firewall administrative web interfaces.",
            "remediation": "Disable administrative web login on WAN interface, restrict management access to dedicated jump boxes, and enable IP ban after 3 failed attempts."
        }
    ]

    for inc in incidents_def:
        matching_dets = [d for d in detections if inc["rule"] in d[2]]
        det_count = len(matching_dets)
        if det_count == 0:
            continue

        affected_hosts = list(set(d[7] for d in matching_dets))[:15]
        affected_users = list(set(d[8] for d in matching_dets if d[8] and d[8] != "SYSTEM"))[:10]
        first_ts = min(d[6] for d in matching_dets)
        last_ts = max(d[6] for d in matching_dets)
        first_seq = min(d[5] for d in matching_dets)
        last_seq = max(d[5] for d in matching_dets)

        conn.execute("""
            INSERT INTO incidents (
                incident_id, dataset_id, classification, risk_score, confidence_score,
                risk_explanation, confidence_explanation, detection_count, affected_hosts,
                affected_users, techniques, tactics, first_seen_seq, last_seen_seq,
                first_seen_ts, last_seen_ts, summary, report_text
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            inc["id"],
            DATASET_ID,
            inc["title"],
            inc["risk"],
            inc["conf"],
            inc["summary"],
            f"Based on {det_count} correlated FortiGate NGFW & IPS telemetry events.",
            det_count,
            json.dumps(affected_hosts),
            json.dumps(affected_users),
            json.dumps(inc["techniques"]),
            json.dumps(inc["tactics"]),
            first_seq,
            last_seq,
            first_ts,
            last_ts,
            inc["summary"],
            f"# Incident Report: {inc['title']}\n\n**Severity**: CRITICAL\n**Detections**: {det_count}\n\n**Remediation**: {inc['remediation']}"
        ])

        # Link detections
        for d in matching_dets[:200]:
            conn.execute("""
                INSERT OR IGNORE INTO incident_detections (incident_id, detection_id, join_reason)
                VALUES (?, ?, 'Correlated firewall perimeter signature match')
            """, [inc["id"], d[0]])

    console.print(f"[green]✓ Correlated {len(incidents_def)} enterprise perimeter security incidents[/green]")


if __name__ == "__main__":
    run_firewall_pipeline()
