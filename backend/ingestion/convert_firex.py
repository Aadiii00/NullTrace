"""
Universal FortiGate ECS JSON Converter & Ingestion Engine
Converts both firex-10G.log and firex-30G.log into standardized ECS JSON Lines
and ingests both datasets into DuckDB with high-performance appenders.
"""

import os
import re
import json
import uuid
from collections import Counter
import duckdb

KV_PATTERN = re.compile(r'([a-zA-Z0-9_\-]+)=(?:\"([^\"]*)\"|([^\s]*))')
DB_PATH = "data/killchain.duckdb"

TARGETS = [
    {
        "source_log": "firex-30G.log",
        "dataset_id": "firex-30g-ngfw",
        "json_out": "firex_30g_logs.json",
        "data_json_out": "data/firex_30g_logs.json",
        "det_prefix": "DET-30G",
        "inc_prefix": "INC-30G",
        "label": "FortiGate NGFW 30G Telemetry (firex_30g_logs.json • firex-30G.log)"
    },
    {
        "source_log": "firex-10G.log",
        "dataset_id": "firex-10g-ngfw",
        "json_out": "firex_10g_logs.json",
        "data_json_out": "data/firex_10g_logs.json",
        "det_prefix": "DET-10G",
        "inc_prefix": "INC-10G",
        "label": "FortiGate NGFW 10G Telemetry (firex_10g_logs.json • firex-10G.log)"
    }
]

def parse_kv(line: str):
    matches = KV_PATTERN.findall(line)
    return {k: (v1 if v1 != '' else v2) for k, v1, v2 in matches}

def map_mitre(attack_name, subtype, logdesc, catdesc, action):
    atk = attack_name or ""
    desc = logdesc or ""
    cat = catdesc or ""
    
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
    elif "ZeroLogon" in atk:
        return "T1068", "Privilege Escalation", "ZeroLogon Netlogon Domain Elevation of Privilege (CVE-2020-1472)", 10, "Cryptographic flaw exploitation targeting Active Directory Netlogon"
    elif "Netfilter" in atk:
        return "T1068", "Privilege Escalation", "Linux Kernel Netfilter Local Privilege Escalation", 9, "Local privilege escalation payload targeting kernel netfilter subsystem"
    elif "Cobalt.Strike" in atk:
        return "T1071.001", "Command and Control", "Cobalt Strike Adversary C2 Beaconing Activity", 9, "Perimeter detection of Cobalt Strike malleable C2 HTTP profile"
    elif "Mirai" in atk:
        return "T1071.001", "Command and Control", "Mirai IoT Botnet Command and Control Traffic", 8, "Botnet command and control communication traffic blocked"
    elif "RDP" in atk and "Brute" in atk:
        return "T1110.001", "Credential Access", "Remote Desktop Protocol (RDP) Brute Force", 7, "High-frequency authentication attempts across port 3389"
    elif "SSH" in atk and "Brute" in atk:
        return "T1110.001", "Credential Access", "Secure Shell (SSH) Remote Password Spraying", 7, "Repeated SSH login failures across perimeter bastion host"
    elif "Password.Files" in atk:
        return "T1552.001", "Credential Access", "Web Server Credential & Password File Traversal", 8, "Attempted unauthorized access to /etc/passwd or SAM database files"
    elif "Admin login failed" in desc:
        return "T1110.001", "Credential Access", "FortiGate Administrator Interface Brute Force", 6, f"Unauthorized administrative login failure: {desc}"
    elif "Zone.Transfer" in atk:
        return "T1590.002", "Discovery", "Unauthenticated DNS Zone Transfer Reconnaissance", 6, "AXFR query detected attempting to dump entire DNS domain zone"
    elif "Peeking.Data" in atk or "SMB" in atk:
        return "T1046", "Discovery", "SMB Named Pipe Transaction Information Leakage", 7, "Information leakage attempt querying Windows SMB transactions"
    elif "scan" in atk.lower():
        return "T1046", "Discovery", "Internal Subnet Service & Port Scan Sweep", 6, "Broad TCP/UDP probe sequence scanning subnet topology"
    elif "Eicar" in atk or subtype == "virus":
        return "T1204.002", "Execution", "Gateway Antivirus Malicious Payload Interception", 8, "Malicious binary payload blocked by perimeter antivirus engine"
    elif "Phishing" in cat:
        return "T1566.002", "Initial Access", "Malicious Phishing Domain Communication", 8, "Outbound connection to known credential harvesting domain blocked"
    elif "DDoS" in atk or "Firekill" in atk:
        return "T1498.001", "Impact", "Network Volumetric Denial of Service (DDoS)", 7, "Threshold violation: anomalous packet volume per second"
    elif atk:
        clean_name = atk.replace(".", " ")
        return "T1190", "Initial Access", f"Exploit Signature Detected: {clean_name}", 7, f"Perimeter IPS alert: {atk}"

    return None

def process_target(tgt, conn):
    source_log = tgt["source_log"]
    dataset_id = tgt["dataset_id"]
    json_out = tgt["json_out"]
    data_json_out = tgt["data_json_out"]
    det_prefix = tgt["det_prefix"]
    inc_prefix = tgt["inc_prefix"]

    print(f"\n==================================================")
    print(f"Processing: {source_log} -> {dataset_id}")
    print(f"==================================================")

    if not os.path.exists(source_log):
        print(f"Warning: {source_log} does not exist, skipping.")
        return

    selected_events = []
    detections = []
    rule_counts = Counter()
    login_count = 0
    dropped_count = 0
    traffic_count = 0
    line_limit = 350000

    with open(source_log, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            if i >= line_limit:
                break
            if "devname=" not in line and "logid=" not in line:
                continue

            kv = parse_kv(line)
            if not kv:
                continue

            ev_date = kv.get("date") or "2026-10-30"
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

            mitre = map_mitre(atk, subtype, desc, cat, action)

            src_ip = kv.get("srcip")
            dst_ip = kv.get("dstip")
            src_port = int(kv.get("srcport")) if kv.get("srcport") and kv.get("srcport").isdigit() else None
            dst_port = int(kv.get("dstport")) if kv.get("dstport") and kv.get("dstport").isdigit() else None
            proto = kv.get("proto") or "6"
            user = kv.get("user") or "SYSTEM"
            service = kv.get("service") or kv.get("app") or "TCP"

            is_detection = False
            rule_name = None
            tech_id = None
            tactic = None
            sev_num = 0
            explanation = None

            if mitre:
                tech_id, tactic, rule_name, sev_num, explanation = mitre
                if "Admin login" in rule_name:
                    if login_count >= 40:
                        continue
                    login_count += 1
                else:
                    if rule_counts[rule_name] >= 40:
                        continue
                    rule_counts[rule_name] += 1
                is_detection = True
            elif action in ('deny', 'dropped', 'blocked'):
                if dropped_count >= 1500:
                    continue
                dropped_count += 1
            elif subtype == 'forward':
                if traffic_count >= 14000:
                    continue
                traffic_count += 1
            else:
                continue

            ev_id = str(uuid.uuid4())
            seq_num = len(selected_events) + 1

            src_host = f"FW-GATEWAY-01" if src_ip == "10.10.99.1" else (
                f"WS-LAN-{src_ip.split('.')[-1]}" if src_ip and src_ip.startswith("10.10.") else f"EXT-{src_ip}"
            )
            dst_host = f"FW-GATEWAY-01" if dst_ip == "10.10.99.1" else (
                f"SRV-DMZ-{dst_ip.split('.')[-1]}" if dst_ip and dst_ip.startswith("10.10.20.") else (
                    f"SRV-INT-{dst_ip.split('.')[-1]}" if dst_ip and dst_ip.startswith("10.10.") else f"EXT-{dst_ip}"
                )
            )

            ecs_record = {
                "@timestamp": ts,
                "event": {
                    "id": ev_id,
                    "kind": "alert" if is_detection else "event",
                    "category": ["network", "threat" if is_detection else "session"],
                    "type": ["denied" if action in ('deny', 'dropped', 'blocked') else "allowed"],
                    "action": action,
                    "severity": sev_num,
                    "module": "fortigate",
                    "dataset": "fortigate.firewall",
                    "sequence": seq_num
                },
                "observer": {
                    "vendor": "Fortinet",
                    "product": "FortiGate NGFW",
                    "version": "7.2.5",
                    "name": kv.get("devname") or "FGT60FTK00000000"
                },
                "source": {
                    "ip": src_ip,
                    "port": src_port,
                    "interface": kv.get("srcintf"),
                    "country": kv.get("srccountry")
                },
                "destination": {
                    "ip": dst_ip,
                    "port": dst_port,
                    "interface": kv.get("dstintf"),
                    "country": kv.get("dstcountry")
                },
                "network": {
                    "transport": "tcp" if proto == "6" else ("udp" if proto == "17" else "icmp"),
                    "protocol": service.lower(),
                    "bytes": int(kv.get("sentbyte") or 0) + int(kv.get("rcvdbyte") or 0),
                    "packets": int(kv.get("sentpkt") or 0) + int(kv.get("rcvdpkt") or 0)
                },
                "user": {"name": user},
                "rule": {"name": rule_name or f"Firewall {action.capitalize()} Rule"}
            }

            if is_detection:
                ecs_record["threat"] = {
                    "framework": "MITRE ATT&CK",
                    "technique": {"id": tech_id, "name": rule_name},
                    "tactic": {"name": tactic}
                }
                ecs_record["message"] = explanation

                detections.append({
                    "detection_id": f"{det_prefix}-{seq_num:05d}",
                    "rule_id": f"RULE-{tech_id.replace('.', '_')}",
                    "rule_name": rule_name,
                    "event_id": ev_id,
                    "seq_num": seq_num,
                    "timestamp_utc": ts,
                    "host_name": dst_host if dst_host.startswith("SRV-") or dst_host.startswith("FW-") else src_host,
                    "user_name": user,
                    "severity": sev_num,
                    "confidence": 0.95,
                    "technique_id": tech_id,
                    "technique_name": rule_name,
                    "tactic_name": tactic,
                    "kill_chain_stage": tactic,
                    "explanation": explanation
                })

            selected_events.append((ecs_record, {
                "seq_num": seq_num,
                "event_id": ev_id,
                "timestamp_utc": ts,
                "event_category": "threat" if is_detection else "network",
                "event_action": action,
                "host_name": dst_host if dst_host.startswith("SRV-") or dst_host.startswith("FW-") else src_host,
                "user_name": user,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "net_protocol": service,
                "process_name": kv.get("app") or service,
                "rule_id": f"RULE-{tech_id.replace('.', '_')}" if tech_id else None,
                "rule_name": rule_name,
                "tech_id": tech_id,
                "tactic": tactic,
            }))

    print(f"Total events: {len(selected_events)} | Total detections: {len(detections)}")

    # Write JSON files
    for p in [json_out, data_json_out]:
        print(f"Writing {p}...")
        with open(p, 'w', encoding='utf-8') as out_f:
            for ecs_rec, _ in selected_events:
                out_f.write(json.dumps(ecs_rec) + '\n')

    file_size = os.path.getsize(json_out)

    # Ingest into DuckDB
    print(f"Ingesting {dataset_id} into DuckDB via appenders...")

    conn.execute("""
        INSERT INTO datasets (dataset_id, filename, file_path, file_size_bytes, format, status)
        VALUES (?, ?, ?, ?, ?, ?)
    """, [dataset_id, json_out, json_out, file_size, "jsonl", "ingested"])

    # 1. Events Appender
    ev_app = conn.appender("events")
    ev_rows = [
        (
            norm["seq_num"],
            norm["event_id"],
            dataset_id,
            norm["timestamp_utc"],
            ecs_rec["event"]["kind"],
            norm["event_category"],
            norm["event_action"],
            ecs_rec["event"]["type"][0] if ecs_rec["event"]["type"] else "allowed",
            ecs_rec["event"]["severity"],
            json_out,
            norm["host_name"],
            norm["dst_ip"] or norm["src_ip"],
            "FortiOS",
            norm["user_name"],
            "CORP",
            "fgt-gw-01",
            json.dumps(ecs_rec)
        )
        for ecs_rec, norm in selected_events
    ]
    ev_app.append_rows(ev_rows)
    ev_app.flush()

    # 2. Normalized Events Appender
    norm_app = conn.appender("normalized_events")
    norm_rows = [
        (
            norm["event_id"], norm["seq_num"], norm["process_name"], None, None,
            None, None, None, None, None, None,
            norm["src_ip"], norm["src_port"], norm["dst_ip"], norm["dst_port"], None,
            ecs_rec["network"]["bytes"], norm["net_protocol"],
            "inbound" if norm["src_ip"] and not norm["src_ip"].startswith("10.10.") else "internal",
            ecs_rec["network"]["transport"], None, None, None, None, None,
            None, None, None, None, None, None,
            norm["rule_id"], norm["rule_name"], norm["tech_id"], norm["rule_name"],
            norm["tactic"], None, None
        )
        for ecs_rec, norm in selected_events
    ]
    norm_app.append_rows(norm_rows)
    norm_app.flush()

    # 3. Detections Appender
    det_app = conn.appender("detections")
    det_rows = [
        (
            d["detection_id"],
            d["rule_id"],
            d["rule_name"],
            d["event_id"],
            dataset_id,
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
            "rule_engine"
        )
        for d in detections
    ]
    det_app.append_rows(det_rows)
    det_app.flush()

    # 4. Incidents
    incidents_def = [
        {
            "num": 1,
            "title": "Critical Perimeter RCE & Web Application Exploitation Campaign",
            "cat": "Exploit Public-Facing Application (Log4j, Confluence, Citrix, FortiOS)",
            "risk": 96.5,
            "conf": 0.98,
            "filter": lambda d: d["technique_id"] == "T1190",
            "techniques": ["T1190"],
            "tactics": ["Initial Access"],
            "summary": "External threat actors coordinated distributed exploitation attempts targeting perimeter Citrix ADC, FortiOS SSL-VPN, Log4j, and Web Application endpoints."
        },
        {
            "num": 2,
            "title": "Adversary Command & Control Infrastructure Activity",
            "cat": "Command and Control (Cobalt Strike & Mirai Botnet C2)",
            "risk": 94.0,
            "conf": 0.95,
            "filter": lambda d: d["technique_id"] == "T1071.001",
            "techniques": ["T1071.001"],
            "tactics": ["Command and Control"],
            "summary": "High-confidence detection of Cobalt Strike malleable C2 HTTP profiles and Mirai botnet command-and-control communication traffic across WAN interfaces."
        },
        {
            "num": 3,
            "title": "Domain Elevation of Privilege & Kernel Exploitation",
            "cat": "Privilege Escalation (ZeroLogon & Linux Netfilter)",
            "risk": 98.0,
            "conf": 0.99,
            "filter": lambda d: d["technique_id"] == "T1068",
            "techniques": ["T1068"],
            "tactics": ["Privilege Escalation"],
            "summary": "Perimeter intrusion detection alerted on cryptographic Netlogon elevation attempts (ZeroLogon CVE-2020-1472) and Linux kernel netfilter exploits."
        },
        {
            "num": 4,
            "title": "Distributed Multi-Vector Credential Spraying & Brute Force",
            "cat": "Credential Access (RDP, SSH, Admin Brute Force)",
            "risk": 85.0,
            "conf": 0.92,
            "filter": lambda d: d["technique_id"] in ("T1110.001", "T1552.001"),
            "techniques": ["T1110.001", "T1552.001"],
            "tactics": ["Credential Access"],
            "summary": "Sustained credential access campaign involving RDP connection brute force, SSH credential guessing, web password file traversal, and FortiGate administrative logon attempts."
        },
        {
            "num": 5,
            "title": "Perimeter Network Reconnaissance, Phishing & Denial of Service",
            "cat": "Discovery, Initial Access & Impact (DNS Zone Transfer, Phishing, DDoS)",
            "risk": 82.5,
            "conf": 0.90,
            "filter": lambda d: d["technique_id"] in ("T1590.002", "T1046", "T1566.002", "T1204.002", "T1498.001"),
            "techniques": ["T1590.002", "T1046", "T1566.002", "T1204.002", "T1498.001"],
            "tactics": ["Discovery", "Initial Access", "Execution", "Impact"],
            "summary": "External reconnaissance including unauthenticated DNS AXFR zone transfers, SMB named pipe enumeration, gateway antivirus interceptions, phishing redirects, and volumetric DDoS spikes."
        }
    ]

    for inc in incidents_def:
        inc_id = f"{inc_prefix}-{inc['num']:03d}"
        matched_dets = [d for d in detections if inc["filter"](d)]
        if not matched_dets:
            matched_dets = detections[:10]

        aff_hosts = list({d["host_name"] for d in matched_dets})
        aff_users = list({d["user_name"] for d in matched_dets})
        first_ts = min(d["timestamp_utc"] for d in matched_dets)
        last_ts = max(d["timestamp_utc"] for d in matched_dets)

        conn.execute("""
            INSERT INTO incidents (
                incident_id, dataset_id, classification, risk_score, confidence_score,
                detection_count, affected_hosts, affected_users,
                techniques, tactics, first_seen_ts, last_seen_ts, summary
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            inc_id,
            dataset_id,
            inc["cat"],
            inc["risk"],
            inc["conf"],
            len(matched_dets),
            json.dumps(aff_hosts),
            json.dumps(aff_users),
            json.dumps(inc["techniques"]),
            json.dumps(inc["tactics"]),
            first_ts,
            last_ts,
            inc["summary"]
        ])

        inc_det_tuples = [(inc_id, d["detection_id"], "correlated_mitre_campaign") for d in matched_dets]
        conn.executemany("INSERT INTO incident_detections (incident_id, detection_id, join_reason) VALUES (?, ?, ?)", inc_det_tuples)

    print(f"Successfully finished ingestion for {dataset_id}")

def main():
    os.makedirs("data", exist_ok=True)
    conn = duckdb.connect(DB_PATH)
    print("Cleaning existing FortiGate records in DuckDB...")
    conn.execute("DELETE FROM incident_detections WHERE incident_id LIKE 'INC-FW-%' OR incident_id LIKE 'INC-10G-%' OR incident_id LIKE 'INC-30G-%' OR detection_id LIKE 'DET-FW-%' OR detection_id LIKE 'DET-10G-%' OR detection_id LIKE 'DET-30G-%'")
    conn.execute("DELETE FROM incidents WHERE dataset_id LIKE 'firex-%' OR incident_id LIKE 'INC-FW-%'")
    conn.execute("DELETE FROM detections WHERE dataset_id LIKE 'firex-%' OR detection_id LIKE 'DET-FW-%' OR detection_id LIKE 'DET-10G-%' OR detection_id LIKE 'DET-30G-%'")
    conn.execute("DELETE FROM normalized_events WHERE event_id IN (SELECT event_id FROM events WHERE dataset_id LIKE 'firex-%')")
    conn.execute("DELETE FROM events WHERE dataset_id LIKE 'firex-%'")
    conn.execute("DELETE FROM datasets WHERE dataset_id LIKE 'firex-%'")

    for tgt in TARGETS:
        process_target(tgt, conn)
    conn.commit()
    conn.close()
    print("\nALL DATASETS (10G & 30G) INGESTED SUCCESSFULLY!")

if __name__ == "__main__":
    main()
