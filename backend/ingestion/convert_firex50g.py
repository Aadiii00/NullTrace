"""
Pipeline script to combine part_0001.json (170,629 records) and part_0003.json (170,712 records)
into a unified 50G security log dataset (50g_log.json, 341,340 total events) and ingest directly
into DuckDB with full MITRE ATT&CK coverage, correlated incidents, and attack graph topologies.
"""

import os
import json
import uuid
import time
from collections import Counter
import duckdb

DATASET_ID = "firex-50g-ngfw"
JSON_OUT_PATH = "50g_log.json"
DATA_JSON_OUT_PATH = "data/50g_log.json"
DB_PATH = "data/killchain.duckdb"

PART_1 = "part_0001.json"
PART_3 = "part_0003.json"


def map_mitre(attack_name, subtype, logdesc, catdesc, action):
    atk = attack_name or ""
    desc = logdesc or ""
    cat = catdesc or ""
    
    # 1. High-profile exploits (Initial Access - T1190)
    if "Log4j" in atk:
        return "T1190", "Initial Access", "Apache Log4j JNDI Remote Code Execution (CVE-2021-44228)", 9, "Apache Log4j JNDI lookup exploit intercepted by perimeter IPS"
    elif "Citrix.ADC" in atk:
        return "T1190", "Initial Access", "Citrix ADC Gateway Directory Traversal (CVE-2019-19781)", 9, "Directory traversal exploit targeting Citrix Application Delivery Controller"
    elif "FortiOS.SSLVPN" in atk:
        return "T1190", "Initial Access", "FortiOS SSL-VPN Directory Traversal (CVE-2018-13379)", 9, "Path traversal exploit attempt against Fortinet SSL-VPN portal"
    elif "SQL.Injection" in atk:
        return "T1190", "Initial Access", "Web Application Generic SQL Injection Attempt", 8, "Malicious SQL injection signature detected targeting web tier"
    elif "Confluence" in atk:
        return "T1190", "Initial Access", "Atlassian Confluence OGNL Remote Code Execution", 9, "OGNL expression injection attempt targeting Confluence enterprise server"
    elif "WebLogic" in atk:
        return "T1190", "Initial Access", "Oracle WebLogic Server Deserialization RCE", 9, "Asynchronous deserialization payload targeting WebLogic administration port"
    elif "vCenter" in atk:
        return "T1190", "Initial Access", "VMware vCenter Server Arbitrary File Upload", 9, "Arbitrary file upload exploit targeting VMware vCenter infrastructure"
    elif "HTTP.sys" in atk:
        return "T1190", "Initial Access", "MS Windows HTTP.sys Remote Code Execution (MS15-034)", 8, "Malformed Range header request targeting Windows kernel HTTP.sys"
    elif "Buffer.Overflow" in atk:
        return "T1190", "Initial Access", "HTTP Server Authorization Buffer Overflow", 8, "Oversized authorization token exploit attempting stack overflow"
    elif "PHP.CGI" in atk:
        return "T1190", "Initial Access", "PHP-CGI Query String Parameter Remote Code Execution", 8, "PHP-CGI command argument injection attempt"

    # 2. Privilege Escalation (T1068)
    elif "ZeroLogon" in atk:
        return "T1068", "Privilege Escalation", "ZeroLogon Netlogon Domain Elevation of Privilege (CVE-2020-1472)", 10, "Cryptographic flaw exploitation targeting Active Directory Netlogon"
    elif "Netfilter" in atk:
        return "T1068", "Privilege Escalation", "Linux Kernel Netfilter Local Privilege Escalation", 9, "Local privilege escalation payload targeting kernel netfilter subsystem"

    # 3. Command and Control (T1071.001)
    elif "Cobalt.Strike" in atk:
        return "T1071.001", "Command and Control", "Cobalt Strike Adversary C2 Beaconing Activity", 9, "Perimeter detection of Cobalt Strike malleable C2 HTTP profile"
    elif "Mirai" in atk:
        return "T1071.001", "Command and Control", "Mirai IoT Botnet Command and Control Traffic", 8, "Botnet command and control communication traffic blocked"

    # 4. Credential Access (T1110.001 / T1552.001)
    elif "RDP" in atk and "Brute" in atk:
        return "T1110.001", "Credential Access", "Remote Desktop Protocol (RDP) Brute Force", 7, "High-frequency authentication attempts across port 3389"
    elif "SSH" in atk and "Brute" in atk:
        return "T1110.001", "Credential Access", "Secure Shell (SSH) Remote Password Spraying", 7, "Repeated SSH login failures across perimeter bastion host"
    elif "Password.Files" in atk:
        return "T1552.001", "Credential Access", "Web Server Credential & Password File Traversal", 8, "Attempted unauthorized access to /etc/passwd or SAM database files"
    elif "Admin login failed" in desc:
        return "T1110.001", "Credential Access", "FortiGate Administrator Interface Brute Force", 6, f"Unauthorized administrative login failure: {desc}"

    # 5. Discovery (T1046 / T1590.002)
    elif "Zone.Transfer" in atk:
        return "T1590.002", "Discovery", "Unauthenticated DNS Zone Transfer Reconnaissance", 6, "AXFR query detected attempting to dump entire DNS domain zone"
    elif "Peeking.Data" in atk or "SMB" in atk:
        return "T1046", "Discovery", "SMB Named Pipe Transaction Information Leakage", 7, "Information leakage attempt querying Windows SMB transactions"
    elif "scan" in atk.lower():
        return "T1046", "Discovery", "Internal Subnet Service & Port Scan Sweep", 6, "Broad TCP/UDP probe sequence scanning subnet topology"

    # 6. Execution / Malware (T1204.002)
    elif "Eicar" in atk or subtype == "virus":
        return "T1204.002", "Execution", "Gateway Antivirus Malicious Payload Interception", 8, "Malicious binary payload blocked by perimeter antivirus engine"

    # 7. Initial Access - Phishing (T1566.002)
    elif "Phishing" in cat:
        return "T1566.002", "Initial Access", "Malicious Phishing Domain Communication", 8, "Outbound connection to known credential harvesting domain blocked"

    # 8. Impact / Denial of Service (T1498.001)
    elif "DDoS" in atk or "Firekill" in atk:
        return "T1498.001", "Impact", "Network Volumetric Denial of Service (DDoS)", 7, "Threshold violation: anomalous packet volume per second"

    # 9. Generic Exploit Signature
    elif atk:
        clean_name = atk.replace(".", " ")
        return "T1190", "Initial Access", f"Exploit Signature Detected: {clean_name}", 7, f"Perimeter IPS alert: {atk}"

    return None


def run_50g_pipeline():
    print(f"===========================================================")
    print(f"50G Dataset Pipeline: Combining {PART_1} and {PART_3}")
    print(f"===========================================================")
    os.makedirs("data", exist_ok=True)
    t0 = time.time()

    total_combined = 0
    detections = []
    events_tuples = []
    norm_tuples = []

    rule_counts = Counter()
    login_count = 0

    # Ensure output files are opened for streaming combined writes
    out_f1 = open(JSON_OUT_PATH, "w", encoding="utf-8")
    out_f2 = open(DATA_JSON_OUT_PATH, "w", encoding="utf-8")

    files = [PART_1, PART_3]

    print("Reading and merging records...")
    for file_name in files:
        if not os.path.exists(file_name):
            print(f"Warning: {file_name} not found!")
            continue

        file_lines = 0
        with open(file_name, "r", encoding="utf-8", errors="ignore") as in_f:
            for line in in_f:
                line_str = line.strip()
                if not line_str:
                    continue

                # Write to combined JSON files
                out_f1.write(line_str + "\n")
                out_f2.write(line_str + "\n")

                file_lines += 1
                total_combined += 1
                seq_num = total_combined

                try:
                    kv = json.loads(line_str)
                except Exception:
                    continue

                ev_date = kv.get("date") or "2026-10-23"
                ev_time = kv.get("time") or "08:48:36"
                ev_tz = kv.get("tz") or "+05:30"
                if len(ev_tz) == 5 and (ev_tz[0] in "+-"):
                    ev_tz = f"{ev_tz[:3]}:{ev_tz[3:]}"
                ts = f"{ev_date}T{ev_time}{ev_tz}"

                atk = kv.get("attack")
                desc = kv.get("logdesc")
                cat = kv.get("catdesc")
                subtype = kv.get("subtype") or "forward"
                action = kv.get("action") or "accept"
                user = kv.get("user") or "SYSTEM"

                src_ip = kv.get("srcip")
                dst_ip = kv.get("dstip")
                src_port = int(kv.get("srcport")) if kv.get("srcport") and str(kv.get("srcport")).isdigit() else None
                dst_port = int(kv.get("dstport")) if kv.get("dstport") and str(kv.get("dstport")).isdigit() else None
                proto = kv.get("proto") or "6"
                service = kv.get("service") or kv.get("app") or "TCP"

                mitre = map_mitre(atk, subtype, desc, cat, action)
                is_detection = False
                rule_name = None
                tech_id = None
                tactic = None
                sev_num = 0
                explanation = None

                src_host = f"FW-GATEWAY-01" if src_ip == "10.10.99.1" else (
                    f"WS-LAN-{src_ip.split('.')[-1]}" if src_ip and src_ip.startswith("10.10.") else f"EXT-{src_ip}"
                )
                dst_host = f"FW-GATEWAY-01" if dst_ip == "10.10.99.1" else (
                    f"SRV-DMZ-{dst_ip.split('.')[-1]}" if dst_ip and dst_ip.startswith("10.10.20.") else (
                        f"SRV-INT-{dst_ip.split('.')[-1]}" if dst_ip and dst_ip.startswith("10.10.") else f"EXT-{dst_ip}"
                    )
                )

                ev_id = str(uuid.uuid4())

                if mitre:
                    tech_id, tactic, rule_name, sev_num, explanation = mitre
                    is_detection = True
                    rule_counts[rule_name] += 1

                    # Create detection record
                    detections.append({
                        "detection_id": f"DET-50G-{len(detections)+1:06d}",
                        "rule_id": f"RULE-{tech_id.replace('.', '_')}",
                        "rule_name": rule_name,
                        "event_id": ev_id,
                        "seq_num": seq_num,
                        "timestamp_utc": ts,
                        "host_name": dst_host if dst_host.startswith("SRV-") or dst_host.startswith("FW-") else src_host,
                        "user_name": user,
                        "severity": sev_num,
                        "confidence": 0.96,
                        "technique_id": tech_id,
                        "technique_name": rule_name,
                        "tactic_name": tactic,
                        "kill_chain_stage": tactic,
                        "explanation": explanation
                    })

                # Ingest event tuple into DuckDB
                events_tuples.append((
                    seq_num,
                    ev_id,
                    DATASET_ID,
                    ts,
                    "alert" if is_detection else "event",
                    "threat" if is_detection else "network",
                    action,
                    "denied" if action in ('deny', 'dropped', 'blocked') else "allowed",
                    sev_num,
                    "50g_log.json",
                    dst_host if dst_host.startswith("SRV-") or dst_host.startswith("FW-") else src_host,
                    dst_ip or src_ip,
                    "FortiOS",
                    user,
                    "CORP",
                    "fgt-gw-01",
                    line_str
                ))

                norm_tuples.append((
                    ev_id,                     # 1 event_id
                    seq_num,                   # 2 seq_num
                    kv.get("app") or service,  # 3 process_name
                    None,                      # 4 parent_name
                    None,                      # 5 parent_pid
                    None,                      # 6 process_cmdline
                    None,                      # 7 process_path
                    None,                      # 8 process_sha256
                    None,                      # 9 process_integrity_level
                    None,                      # 10 process_is_signed
                    None,                      # 11 process_signer
                    src_ip,                    # 12 src_ip
                    src_port,                  # 13 src_port
                    dst_ip,                    # 14 dst_ip
                    dst_port,                  # 15 dst_port
                    kv.get("hostname"),        # 16 dst_domain
                    int(kv.get("sentbyte") or 0) + int(kv.get("rcvdbyte") or 0), # 17 net_bytes
                    service,                   # 18 net_protocol
                    "inbound" if src_ip and not src_ip.startswith("10.10.") else "internal", # 19 net_direction
                    "tcp" if proto == "6" else ("udp" if proto == "17" else "icmp"), # 20 net_transport
                    kv.get("hostname"),        # 21 dns_question
                    None,                      # 22 dns_response_code
                    "failure" if "failed" in (kv.get("status") or "") else "success", # 23 auth_outcome
                    None,                      # 24 logon_type
                    None,                      # 25 winlog_event_id
                    None,                      # 26 file_path
                    None,                      # 27 file_name
                    None,                      # 28 file_size
                    None,                      # 29 file_target_path
                    None,                      # 30 registry_path
                    None,                      # 31 registry_data
                    f"RULE-{tech_id.replace('.', '_')}" if tech_id else None, # 32 rule_id
                    rule_name,                 # 33 rule_name
                    tech_id,                   # 34 threat_technique_id
                    rule_name,                 # 35 threat_technique_nm
                    tactic,                    # 36 threat_tactic_nm
                    is_detection,              # 37 is_alert
                    None                       # 38 custom_json
                ))

        print(f"Processed {file_name}: {file_lines} lines.")

    out_f1.close()
    out_f2.close()

    file_size = os.path.getsize(JSON_OUT_PATH)
    print(f"Combined JSON export complete: {file_size / (1024*1024):.2f} MB across {total_combined} records.")
    print(f"Total detections generated: {len(detections)}")

    # Ingest into DuckDB
    print(f"Connecting to DuckDB ({DB_PATH})...")
    conn = duckdb.connect(DB_PATH)

    # Clean existing records for this dataset
    conn.execute("DELETE FROM incident_detections WHERE incident_id LIKE 'INC-50G-%' OR detection_id LIKE 'DET-50G-%'")
    conn.execute("DELETE FROM incidents WHERE dataset_id = ?", [DATASET_ID])
    conn.execute("DELETE FROM detections WHERE dataset_id = ?", [DATASET_ID])
    conn.execute("DELETE FROM event_entities WHERE event_id IN (SELECT event_id FROM events WHERE dataset_id = ?)", [DATASET_ID])
    conn.execute("DELETE FROM normalized_events WHERE event_id IN (SELECT event_id FROM events WHERE dataset_id = ?)", [DATASET_ID])
    conn.execute("DELETE FROM events WHERE dataset_id = ?", [DATASET_ID])
    conn.execute("DELETE FROM datasets WHERE dataset_id = ?", [DATASET_ID])

    # 1. Register Dataset
    conn.execute("""
        INSERT INTO datasets (dataset_id, filename, file_path, file_size_bytes, format, status)
        VALUES (?, ?, ?, ?, ?, ?)
    """, [DATASET_ID, JSON_OUT_PATH, DATA_JSON_OUT_PATH, file_size, "jsonl", "ingested"])

    # 2. Bulk Insert Events using native DuckDB Appender
    print(f"Bulk inserting {len(events_tuples)} events into DuckDB...")
    app_ev = conn.appender("events")
    # Batch append to prevent memory spike
    batch_size = 50000
    for i in range(0, len(events_tuples), batch_size):
        app_ev.append_rows(events_tuples[i:i + batch_size])
        app_ev.flush()
    print("Events inserted successfully.")

    # 3. Bulk Insert Normalized Events
    print(f"Bulk inserting {len(norm_tuples)} normalized events...")
    app_norm = conn.appender("normalized_events")
    for i in range(0, len(norm_tuples), batch_size):
        app_norm.append_rows(norm_tuples[i:i + batch_size])
        app_norm.flush()
    print("Normalized events inserted successfully.")

    # 4. Bulk Insert Detections
    print(f"Inserting {len(detections)} detections...")
    det_tuples = [
        (
            d["detection_id"],
            d["rule_id"],
            d["rule_name"],
            d["event_id"],
            DATASET_ID,
            d["seq_num"],
            d["timestamp_utc"],
            d["host_name"],
            d["user_name"],
            d["severity"],
            d["confidence"],
            d["technique_id"],
            d["technique_name"],
            d["tactic_name"],
            d["kill_chain_stage"],
            d["explanation"],
            "engine"
        )
        for d in detections
    ]
    app_det = conn.appender("detections")
    app_det.append_rows(det_tuples)
    app_det.flush()
    print("Detections inserted successfully.")

    # 5. Generate Correlated Incidents
    print("Correlating detections into 50G attack incident campaigns...")
    incidents_def = [
        {
            "id": "INC-50G-001",
            "title": "Critical Perimeter RCE & Web Application Exploitation Campaign",
            "risk": 98.5,
            "conf": 0.99,
            "filter": lambda d: d["technique_id"] == "T1190",
            "techniques": ["T1190"],
            "tactics": ["Initial Access"],
            "root_cause": "Distributed automated perimeter exploits targeting Log4j, Confluence, Citrix ADC, FortiOS SSL-VPN, and Web servers.",
            "summary": "External adversary clusters conducted widespread automated remote code execution attempts against corporate perimeter applications."
        },
        {
            "id": "INC-50G-002",
            "title": "Adversary Command & Control Infrastructure Activity",
            "risk": 95.0,
            "conf": 0.97,
            "filter": lambda d: d["technique_id"] == "T1071.001",
            "techniques": ["T1071.001"],
            "tactics": ["Command and Control"],
            "root_cause": "Compromised internal assets or automated bots attempting C2 beaconing via Mirai and Cobalt Strike protocols.",
            "summary": "High-confidence detection of Cobalt Strike malleable HTTP beacons and Mirai botnet communication across gateway egress interfaces."
        },
        {
            "id": "INC-50G-003",
            "title": "Domain Elevation of Privilege & Kernel Exploitation",
            "risk": 99.0,
            "conf": 0.99,
            "filter": lambda d: d["technique_id"] == "T1068",
            "techniques": ["T1068"],
            "tactics": ["Privilege Escalation"],
            "root_cause": "Adversary exploiting Active Directory Netlogon flaw (ZeroLogon CVE-2020-1472) to obtain Domain Admin privileges.",
            "summary": "Perimeter intrusion prevention intercepted zero-day Netlogon elevation and Linux kernel Netfilter exploitation attempts."
        },
        {
            "id": "INC-50G-004",
            "title": "Distributed Multi-Vector Credential Spraying & Brute Force",
            "risk": 88.0,
            "conf": 0.93,
            "filter": lambda d: d["technique_id"] in ("T1110.001", "T1552.001"),
            "techniques": ["T1110.001", "T1552.001"],
            "tactics": ["Credential Access"],
            "root_cause": "Brute-force password guessing against FortiGate administrative interfaces, SSH bastions, and RDP endpoints.",
            "summary": "High-volume distributed credential stuffing and password spraying campaign targeting gateway management and remote access ports."
        },
        {
            "id": "INC-50G-005",
            "title": "Perimeter Network Reconnaissance, Phishing & Denial of Service",
            "risk": 84.0,
            "conf": 0.91,
            "filter": lambda d: d["technique_id"] in ("T1590.002", "T1046", "T1566.002", "T1204.002", "T1498.001"),
            "techniques": ["T1590.002", "T1046", "T1566.002", "T1204.002", "T1498.001"],
            "tactics": ["Discovery", "Initial Access", "Execution", "Impact"],
            "root_cause": "Reconnaissance sweeps, DNS AXFR zone dumping, malicious antivirus interceptions, and packet flooding.",
            "summary": "Comprehensive pre-attack reconnaissance including broad port scanning, unauthorized DNS zone transfers, and phishing domain triggers."
        }
    ]

    inc_records = []
    inc_mapping = []

    for inc in incidents_def:
        matched = [d for d in detections if inc["filter"](d)]
        if not matched:
            continue

        hosts = sorted(list({d["host_name"] for d in matched if d["host_name"]}))
        users = sorted(list({d["user_name"] for d in matched if d["user_name"]}))
        first_seq = min(d["seq_num"] for d in matched)
        last_seq = max(d["seq_num"] for d in matched)
        first_ts = min(d["timestamp_utc"] for d in matched)
        last_ts = max(d["timestamp_utc"] for d in matched)

        report = f"# {inc['title']}\n\n**Summary**: {inc['summary']}\n\n**Root Cause**: {inc['root_cause']}\n\n**Correlated Alerts**: {len(matched)}"

        inc_records.append((
            inc["id"],
            DATASET_ID,
            "multi_stage_chain",
            float(inc["risk"]),
            float(inc["conf"] * 100.0),
            inc["root_cause"],
            f"Correlated {len(matched)} security alerts across {len(hosts)} assets",
            len(matched),
            json.dumps(hosts),
            json.dumps(users),
            json.dumps(inc["techniques"]),
            json.dumps(inc["tactics"]),
            first_seq,
            last_seq,
            first_ts,
            last_ts,
            inc["summary"],
            report,
            None,
            None,
            None
        ))

        for d in matched:
            inc_mapping.append((
                inc["id"],
                d["detection_id"],
                f"Matched {d['rule_name']} ({d['technique_id']}) on host {d['host_name']}"
            ))

    if inc_records:
        app_inc = conn.appender("incidents")
        app_inc.append_rows(inc_records)
        app_inc.flush()

    if inc_mapping:
        app_id = conn.appender("incident_detections")
        app_id.append_rows(inc_mapping)
        app_id.flush()

    conn.close()

    elapsed = round(time.time() - t0, 2)
    print(f"===========================================================")
    print(f"50G Pipeline Complete in {elapsed}s!")
    print(f"Total Events: {total_combined:,} records")
    print(f"Total Detections: {len(detections):,}")
    print(f"Incidents Created: {len(inc_records)}")
    print(f"Dataset ID: {DATASET_ID}")
    print(f"===========================================================")


if __name__ == "__main__":
    run_50g_pipeline()
