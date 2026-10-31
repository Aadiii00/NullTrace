"""
KillChain Local Log Upload & Ingestion Engine.
Processes user-uploaded security logs (JSONL, JSON Array, FortiGate/Syslog Key-Value, or Text),
normalizes into ECS/OCSF format, evaluates detections, and correlates incidents.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.database import get_db, init_schema
from backend.detection.engine import DetectionEngine
from backend.correlation.engine import CorrelationEngine
from backend.graph.engine import AttackGraphEngine

KV_PATTERN = re.compile(r'([a-zA-Z0-9_\-]+)=(?:\"([^\"]*)\"|([^\s]*))')

def _parse_kv_line(line: str) -> Dict[str, str]:
    matches = KV_PATTERN.findall(line)
    return {k: (v1 if v1 != '' else v2) for k, v1, v2 in matches}

def _map_mitre_from_attack(attack_name: str) -> Tuple[str, str, str, int]:
    atk = attack_name or ""
    if "Log4j" in atk:
        return "T1190", "Initial Access", "Apache Log4j JNDI Remote Code Execution (CVE-2021-44228)", 9
    elif "Citrix" in atk:
        return "T1190", "Initial Access", "Citrix ADC Directory Traversal (CVE-2019-19781)", 9
    elif "FortiOS" in atk or "SSLVPN" in atk:
        return "T1190", "Initial Access", "FortiOS SSL-VPN Directory Traversal (CVE-2018-13379)", 9
    elif "SQL" in atk:
        return "T1190", "Initial Access", "Web Application Generic SQL Injection", 8
    elif "Cobalt" in atk:
        return "T1071.001", "Command and Control", "Cobalt Strike Adversary C2 Beaconing", 9
    elif "Brute" in atk or "Spray" in atk:
        return "T1110.001", "Credential Access", "Remote Password Spraying / Brute Force", 7
    elif "Ransomware" in atk or "Lock" in atk:
        return "T1486", "Impact", "Data Encrypted for Impact", 10
    elif "ZeroLogon" in atk:
        return "T1068", "Privilege Escalation", "ZeroLogon Netlogon Domain Elevation (CVE-2020-1472)", 10
    else:
        return "T1059", "Execution", f"Suspicious Activity ({atk or 'Threat'})", 7


def process_uploaded_log(file_path: Path, original_filename: str) -> Dict[str, Any]:
    """
    Ingest, normalize, evaluate, and correlate an uploaded log file.
    Writes dataset, raw events, normalized events, detections, and incidents.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Uploaded file not found at: {file_path}")

    file_size = file_path.stat().st_size
    clean_stem = re.sub(r'[^a-zA-Z0-9_\-]', '_', Path(original_filename).stem)
    dataset_id = f"upload-{clean_stem}-{uuid.uuid4().hex[:6]}"

    # Sample first few lines to determine format
    format_type = "jsonl"
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        first_lines = [f.readline().strip() for _ in range(5)]

    sample = next((l for l in first_lines if l), "")
    if sample.startswith("{") or sample.startswith("["):
        format_type = "json"
    elif "date=" in sample or "srcip=" in sample or "devname=" in sample or "action=" in sample:
        format_type = "kv_log"
    else:
        format_type = "text_log"

    conn = get_db(read_only=False)
    init_schema()

    # Register dataset record
    conn.execute("""
        INSERT INTO datasets (dataset_id, filename, file_path, file_size_bytes, format, status)
        VALUES (?, ?, ?, ?, ?, 'ingesting')
    """, [dataset_id, original_filename, str(file_path), file_size, format_type])

    event_rows = []
    norm_rows = []
    seq = 0
    t_start = time.perf_counter()

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue

            event_id = str(uuid.uuid4())
            ts = datetime.now(timezone.utc).isoformat()
            host_name = "WS-UPLOAD-01"
            user_name = "SYSTEM"
            src_ip = None
            dst_ip = None
            dst_domain = None
            proc_name = None
            cmdline = None
            cat = "security"
            act = "log_event"
            rule_id = None
            rule_name = None
            tech_id = None
            tech_nm = None
            tactic = None
            severity = 0

            cleaned = line_str.rstrip(",").strip()
            if format_type == "json" or cleaned.startswith("{"):
                try:
                    obj = json.loads(cleaned)
                    event_id = obj.get("event", {}).get("id") or obj.get("event_id") or event_id
                    ts = obj.get("@timestamp") or obj.get("timestamp_utc") or ts
                    host_name = obj.get("host", {}).get("name") or obj.get("host_name") or host_name
                    user_name = obj.get("user", {}).get("name") or obj.get("user_name") or user_name
                    cat = obj.get("event", {}).get("category") or obj.get("event_category") or cat
                    act = obj.get("event", {}).get("action") or obj.get("event_action") or act
                    src_ip = obj.get("source", {}).get("ip") or obj.get("src_ip")
                    dst_ip = obj.get("destination", {}).get("ip") or obj.get("dst_ip")
                    dst_domain = obj.get("dns", {}).get("question", {}).get("name") or obj.get("dst_domain")
                    proc_name = obj.get("process", {}).get("name") or obj.get("process_name")
                    cmdline = obj.get("process", {}).get("command_line") or obj.get("process_cmdline")
                    rule_id = obj.get("rule", {}).get("id") or obj.get("rule_id")
                    rule_name = obj.get("rule", {}).get("name") or obj.get("rule_name")
                    tech_id = obj.get("threat", {}).get("technique", {}).get("id") or obj.get("threat_technique_id")
                    tech_nm = obj.get("threat", {}).get("technique", {}).get("name") or obj.get("threat_technique_nm")
                    tactic = obj.get("threat", {}).get("tactic", {}).get("name") or obj.get("threat_tactic_nm")
                    severity = int(obj.get("event", {}).get("severity") or obj.get("severity") or 0)
                    raw_json = json.dumps(obj)
                except Exception:
                    raw_json = json.dumps({"raw": line_str})
            elif format_type == "kv_log":
                kv = _parse_kv_line(line_str)
                d = kv.get("date", "")
                t = kv.get("time", "")
                if d and t:
                    ts = f"{d}T{t}Z"
                src_ip = kv.get("srcip") or kv.get("remip")
                dst_ip = kv.get("dstip") or kv.get("locip")
                host_name = kv.get("devname") or "FW-GATEWAY-01"
                user_name = kv.get("user") or "SYSTEM"
                cat = kv.get("type", "network")
                act = kv.get("action", "traffic")
                atk = kv.get("attack") or kv.get("vuln") or kv.get("msg")
                if atk:
                    tech_id, tactic, tech_nm, severity = _map_mitre_from_attack(atk)
                    rule_id = f"rule-{hashlib.md5(atk.encode()).hexdigest()[:8]}"
                    rule_name = tech_nm

                raw_json = json.dumps(kv)
            else:
                raw_json = json.dumps({"raw": line_str})

            event_rows.append((
                seq, event_id, dataset_id, ts, "alert" if tech_id else "event",
                cat, act, "success", severity, "uploaded.log", host_name,
                src_ip, "windows" if "WS-" in host_name or "SRV-" in host_name else "linux",
                user_name, "CORP", "agent-upload", raw_json
            ))

            norm_rows.append((
                event_id, seq, proc_name, None, None, cmdline, None, None, None, None, None,
                src_ip, None, dst_ip, None, dst_domain, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None,
                rule_id, rule_name, tech_id, tech_nm, tactic, False, None
            ))

            seq += 1
            if seq >= 25000:
                # Cap at 25,000 records for fast responsive UX
                break

    # Bulk insert into DuckDB
    app_ev = conn.appender("events")
    app_ev.append_rows(event_rows)
    app_ev.flush()

    app_norm = conn.appender("normalized_events")
    app_norm.append_rows(norm_rows)
    app_norm.flush()

    # Update dataset status
    conn.execute("UPDATE datasets SET status = 'registered', updated_at = NOW() WHERE dataset_id = ?", [dataset_id])

    # Run Detection Engine on new dataset
    det_engine = DetectionEngine(rules_dir="rules")
    det_res = det_engine.run_detection(dataset_id)

    # Run Incident Correlation Engine
    corr_engine = CorrelationEngine()
    corr_res = corr_engine.run_correlation(dataset_id)

    # Precompute attack graph
    graph_engine = AttackGraphEngine()
    G = graph_engine.build_graph(dataset_id)

    elapsed = round(time.perf_counter() - t_start, 2)

    return {
        "status": "success",
        "dataset_id": dataset_id,
        "filename": original_filename,
        "format": format_type,
        "file_size_bytes": file_size,
        "file_size_formatted": f"{file_size / (1024*1024):.2f} MB" if file_size > 1024*1024 else f"{file_size / 1024:.1f} KB",
        "total_records": seq,
        "detections_count": det_res.get("total_detections", 0),
        "incidents_count": corr_res.get("incidents_created", 0),
        "graph_nodes": G.number_of_nodes(),
        "graph_edges": G.number_of_edges(),
        "processing_time_seconds": elapsed,
        "message": f"Successfully ingested {seq:,} records, generated {det_res.get('total_detections', 0)} detections across {corr_res.get('incidents_created', 0)} attack incidents in {elapsed}s."
    }
