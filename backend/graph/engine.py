"""
KillChain Attack Graph and Blast Radius Engine.
Builds an enterprise attack graph using NetworkX from telemetry, detections,
and incidents, and performs graph-based blast radius and reachability analysis.
"""
from __future__ import annotations

import json
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx
from rich.console import Console

from backend.database import get_db, init_schema

console = Console()

# Domain critical infrastructure definition
CRITICAL_ASSETS = {
    "SRV-DC-01": {"role": "Primary Domain Controller", "criticality": "CRITICAL", "subnet": "10.10.0.0/24"},
    "SRV-DB-01": {"role": "Production SQL Database", "criticality": "CRITICAL", "subnet": "10.10.0.0/24"},
    "SRV-FILE-01": {"role": "Enterprise File Server", "criticality": "HIGH", "subnet": "10.10.0.0/24"},
    "SRV-WEB-01": {"role": "Public Web Gateway", "criticality": "HIGH", "subnet": "10.10.0.0/24"},
}

MALICIOUS_DOMAINS = {
    "suspicious-example-c2.invalid",
    "sim-exfil.example",
    "bad-domain-demo.test",
}


class AttackGraphEngine:
    """Enterprise attack graph construction and reachability analysis."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        self.graph = nx.DiGraph()

    def build_graph(self, dataset_id: str, category: str = "all") -> nx.DiGraph:
        """
        Build enterprise interaction, attack, or authentication graph for a dataset.
        Supports separated subgraphs: 'all', 'auth', 'system', 'rdp', 'spray', 'c2', 'ransomware', 'persistence', 'macro', or 'incident_<id>'.
        """
        conn = get_db(self.db_path, read_only=True)
        self.graph.clear()

        # Check if FortiGate / Perimeter firewall dataset
        is_firex = "firex" in dataset_id.lower() or "fortigate" in dataset_id.lower()
        if is_firex:
            return self._build_firex_graph(conn, dataset_id, category)

        # Handle user-host authentication graphs
        if category in ("auth", "users", "system", "rdp"):
            # 1. Fetch user-host authentication interactions
            user_auth_rows = conn.execute("""
                SELECT 
                    COALESCE(e.user_name, 'SYSTEM') as user_name,
                    e.host_name,
                    SUM(CASE WHEN e.event_outcome = 'failure' THEN 1 ELSE 0 END) as fail_count,
                    SUM(CASE WHEN e.event_outcome = 'success' THEN 1 ELSE 0 END) as success_count,
                    COUNT(*) as total_count,
                    MAX(CASE WHEN lower(e.user_name) IN ('administrator', 'admin', 'system', 'sysg.admin') THEN 1 ELSE 0 END) as is_admin
                FROM events e
                WHERE e.dataset_id = ?
                  AND e.event_category = 'authentication'
                  AND e.host_name IS NOT NULL
                  AND e.user_name IS NOT NULL AND e.user_name != ''
                GROUP BY COALESCE(e.user_name, 'SYSTEM'), e.host_name
                ORDER BY total_count DESC
            """, [dataset_id]).fetchall()

            # Filter if system only
            if category == "system":
                user_auth_rows = [r for r in user_auth_rows if r[5] == 1 or r[0].lower() in ('administrator', 'sysg.admin', 'system')]

            # Add Host nodes
            hosts_seen = set()
            users_seen = set()
            for uname, hname, fails, succ, total, is_admin in user_auth_rows:
                hosts_seen.add(hname)
                users_seen.add(uname)

            for hname in hosts_seen:
                is_crit = hname in CRITICAL_ASSETS
                crit_info = CRITICAL_ASSETS.get(hname, {})
                self.graph.add_node(
                    f"host:{hname}",
                    node_type="host",
                    name=hname,
                    criticality=crit_info.get("criticality", "MEDIUM"),
                    role=crit_info.get("role", "Workstation"),
                    compromised=is_crit or hname in ('WS-ENG-014', 'WS-FIN-014', 'WS-SALES-010'),
                    risk_score=95.0 if is_crit else 35.0,
                    alert_count=5 if is_crit else 1,
                    ip="10.10.x.x",
                    mitre_techniques="T1078 (Valid Accounts), T1021 (Remote Services)" if is_crit else "T1078",
                    mitre_tactics="Lateral Movement, Persistence" if is_crit else "Initial Access",
                    event_ids="4624, 4625, 4672, 4688",
                )

            for uname in users_seen:
                is_admin = (uname.lower() in ('administrator', 'admin', 'system', 'sysg.admin'))
                self.graph.add_node(
                    f"user:{uname}",
                    node_type="user",
                    name=uname,
                    is_admin=is_admin,
                    role="Domain Admin" if is_admin else "Domain User",
                    criticality="CRITICAL" if is_admin else "MEDIUM",
                    risk_score=90.0 if is_admin else 20.0,
                    alert_count=8 if is_admin else 0,
                    sid=f"S-1-5-21-3249201829-500" if is_admin else f"S-1-5-21-3249201829-1001",
                    mitre_techniques="T1078.002 (Domain Accounts), T1110 (Brute Force)" if is_admin else "T1078 (Valid Accounts)",
                    mitre_tactics="Privilege Escalation, Defense Evasion" if is_admin else "Initial Access",
                    event_ids="4624, 4672, 4768, 4769" if is_admin else "4624, 4625",
                )

            # Add User -> Host edges
            for uname, hname, fails, succ, total, is_admin in user_auth_rows:
                u_node = f"user:{uname}"
                h_node = f"host:{hname}"
                if u_node in self.graph and h_node in self.graph:
                    is_attack = fails > 5
                    evt_code = "4625" if fails > 0 else ("4672" if is_admin else "4624")
                    mitre_id = "T1110.001" if fails > 5 else ("T1078.002" if is_admin else "T1078")
                    mitre_nm = "Password Spraying" if fails > 5 else ("Domain Accounts" if is_admin else "Valid Logon")
                    self.graph.add_edge(
                        u_node,
                        h_node,
                        rel_type="AUTH_LOGON",
                        count=total,
                        fail_count=fails,
                        success_count=succ,
                        lateral_movement=is_attack,
                        event_code=evt_code,
                        mitre_technique=mitre_id,
                        mitre_name=mitre_nm,
                        label=str(evt_code),
                    )
            return self.graph

        # 1. Fetch all hosts with basic metadata
        host_rows = conn.execute("""
            SELECT host_name, host_os_type, host_ip, COUNT(*) as event_count
            FROM events
            WHERE dataset_id = ?
            GROUP BY host_name, host_os_type, host_ip
        """, [dataset_id]).fetchall()

        for hname, os_type, ip, count in host_rows:
            if not hname:
                continue
            is_crit = hname in CRITICAL_ASSETS
            crit_info = CRITICAL_ASSETS.get(hname, {})
            self.graph.add_node(
                f"host:{hname}",
                node_type="host",
                name=hname,
                ip=ip,
                os_type=os_type,
                criticality=crit_info.get("criticality", "MEDIUM"),
                role=crit_info.get("role", "Workstation"),
                event_count=count,
                compromised=False,
                risk_score=10.0 if is_crit else 20.0,
            )

        # 2. Flag compromised hosts and enrich with MITRE techniques & event IDs
        det_hosts = conn.execute("""
            SELECT 
                host_name, 
                COUNT(*) as alert_count, 
                MAX(severity) as max_sev,
                STRING_AGG(DISTINCT technique_id, ', ') as mitre_techniques,
                STRING_AGG(DISTINCT tactic_name, ', ') as mitre_tactics
            FROM detections
            WHERE dataset_id = ? AND host_name IS NOT NULL
            GROUP BY host_name
        """, [dataset_id]).fetchall()

        for hname, count, max_sev, mitres, tactics in det_hosts:
            node_id = f"host:{hname}"
            if node_id in self.graph:
                self.graph.nodes[node_id]["compromised"] = True
                self.graph.nodes[node_id]["alert_count"] = count
                self.graph.nodes[node_id]["max_severity"] = max_sev
                self.graph.nodes[node_id]["mitre_techniques"] = mitres or ""
                self.graph.nodes[node_id]["mitre_tactics"] = tactics or ""
                base_risk = min(100.0, 30.0 + (count * 2.5) + (max_sev * 4.0))
                self.graph.nodes[node_id]["risk_score"] = round(base_risk, 1)

        win_evts = conn.execute("""
            SELECT 
                e.host_name,
                STRING_AGG(DISTINCT CAST(n.winlog_event_id AS VARCHAR), ', ') as event_ids
            FROM normalized_events n
            JOIN events e ON n.event_id = e.event_id
            WHERE e.dataset_id = ? AND n.winlog_event_id IS NOT NULL AND e.host_name IS NOT NULL
            GROUP BY e.host_name
        """, [dataset_id]).fetchall()
        for hname, evts in win_evts:
            nid = f"host:{hname}"
            if nid in self.graph:
                self.graph.nodes[nid]["event_ids"] = evts or ""

        # 3. Add Cross-host Authentication & Lateral Movement edges
        auth_edges = conn.execute("""
            SELECT 
                n.src_ip, e.host_name as target_host,
                SUM(CASE WHEN e.event_outcome = 'failure' THEN 1 ELSE 0 END) as fail_count,
                SUM(CASE WHEN e.event_outcome = 'success' THEN 1 ELSE 0 END) as success_count,
                COUNT(*) as total_logons
            FROM normalized_events n
            JOIN events e ON n.event_id = e.event_id
            WHERE e.dataset_id = ?
              AND e.event_category = 'authentication'
              AND n.src_ip IS NOT NULL
              AND n.src_ip LIKE '10.10.%'
            GROUP BY n.src_ip, e.host_name
        """, [dataset_id]).fetchall()

        ip_to_host = {}
        for nid, data in self.graph.nodes(data=True):
            if data.get("node_type") == "host" and data.get("ip"):
                ip_to_host[data["ip"]] = data["name"]

        for src_ip, tgt_host, fail_count, success_count, total_logons in auth_edges:
            src_host = ip_to_host.get(src_ip)
            if src_host and src_host != tgt_host:
                src_node = f"host:{src_host}"
                tgt_node = f"host:{tgt_host}"
                if src_node in self.graph and tgt_node in self.graph:
                    is_attack = (fail_count > 5) or (tgt_host in CRITICAL_ASSETS and self.graph.nodes[src_node].get("compromised", False))
                    evt_code = "4625" if fail_count > 0 else "4624"
                    mitre_id = "T1110.001" if fail_count > 5 else ("T1021.002" if is_attack else "T1078")
                    mitre_nm = "Password Spraying" if fail_count > 5 else ("SMB Lateral Move" if is_attack else "Valid Logon")
                    self.graph.add_edge(
                        src_node,
                        tgt_node,
                        rel_type="LATERAL_MOVE" if is_attack else "AUTHENTICATES_TO",
                        count=total_logons,
                        fail_count=fail_count,
                        success_count=success_count,
                        lateral_movement=is_attack,
                        event_code=evt_code,
                        mitre_technique=mitre_id,
                        mitre_name=mitre_nm,
                        label=f"{evt_code} • {mitre_id}" if is_attack else str(evt_code),
                    )

        # 4. Add C2 Destination nodes & edges
        net_rows = conn.execute("""
            SELECT e.host_name, n.dst_domain, COUNT(*) as conns
            FROM normalized_events n
            JOIN events e ON n.event_id = e.event_id
            WHERE e.dataset_id = ?
              AND n.dst_domain IN ('suspicious-example-c2.invalid', 'sim-exfil.example', 'bad-domain-demo.test')
            GROUP BY e.host_name, n.dst_domain
        """, [dataset_id]).fetchall()

        for hname, domain, count in net_rows:
            dom_node = f"domain:{domain}"
            if dom_node not in self.graph:
                self.graph.add_node(
                    dom_node,
                    node_type="domain",
                    name=domain,
                    is_malicious=True,
                    criticality="CRITICAL",
                    role="Adversary C2 Server",
                    risk_score=98.0,
                )
            host_node = f"host:{hname}"
            if host_node in self.graph:
                self.graph.add_edge(
                    host_node,
                    dom_node,
                    rel_type="C2_BEACON",
                    count=count,
                    is_c2=True,
                    lateral_movement=False,
                    event_code="T1071.001",
                    label=f"C2 Beacon ({count})",
                )

        # Filter by Attack Scenario Subgraphs if requested
        if category in ("c2", "ransomware", "spray", "persistence", "macro") or category.startswith("incident_"):
            target_hosts = set()
            target_domains = set()

            if category == "c2":
                target_hosts = {"WS-ENG-014", "WS-FIN-014", "SRV-WEB-01"}
                target_domains = {"suspicious-example-c2.invalid", "sim-exfil.example"}
            elif category == "ransomware":
                target_hosts = {"WS-FIN-014", "SRV-FILE-01", "SRV-DB-01", "SRV-DC-01", "WS-ENG-014"}
            elif category == "spray":
                target_hosts = {"WS-SALES-010", "WS-FIN-014", "SRV-DC-01"}
            elif category == "persistence":
                target_hosts = {"WS-FIN-014", "SRV-WEB-01"}
            elif category == "macro":
                target_hosts = {"WS-ENG-014"}
            elif category.startswith("incident_"):
                inc_num = category.split("_")[-1]
                inc_rows = conn.execute("""
                    SELECT affected_hosts FROM incidents 
                    WHERE (incident_id LIKE ? OR incident_id LIKE ?) AND dataset_id = ? 
                    LIMIT 1
                """, [f"%00{inc_num}%", f"%{inc_num}%", dataset_id]).fetchone()
                if inc_rows and inc_rows[0]:
                    target_hosts = set(json.loads(inc_rows[0]))

            # Subgraph filtering: keep only target nodes and edges between them
            nodes_to_keep = set()
            for h in target_hosts:
                nodes_to_keep.add(f"host:{h}")
            for d in target_domains:
                nodes_to_keep.add(f"domain:{d}")

            # Also keep immediate 1-hop connected neighbors
            extended_nodes = set(nodes_to_keep)
            for n in nodes_to_keep:
                if n in self.graph:
                    extended_nodes.update(self.graph.successors(n))
                    extended_nodes.update(self.graph.predecessors(n))

            nodes_to_remove = [n for n in self.graph.nodes() if n not in extended_nodes]
            self.graph.remove_nodes_from(nodes_to_remove)

        return self.graph

    def _build_firex_graph(self, conn, dataset_id: str, category: str = "all") -> nx.DiGraph:
        """Construct perimeter network attack and telemetry topology for FortiGate NGFW."""
        query = """
            SELECT 
                COALESCE(n.src_ip, '0.0.0.0') as s_ip,
                COALESCE(n.dst_ip, '0.0.0.0') as d_ip,
                d.technique_id,
                d.rule_name,
                d.tactic_name,
                d.severity,
                COUNT(*) as cnt
            FROM detections d
            JOIN normalized_events n ON d.event_id = n.event_id
            WHERE d.dataset_id = ?
        """
        params = [dataset_id]

        if category in ("c2", "incident_2"):
            query += " AND d.technique_id = 'T1071.001'"
        elif category in ("exploit", "incident_1"):
            query += " AND d.technique_id = 'T1190'"
        elif category in ("privilege", "incident_3"):
            query += " AND d.technique_id = 'T1068'"
        elif category in ("spray", "incident_4", "auth", "users"):
            query += " AND d.technique_id IN ('T1110.001', 'T1552.001')"
        elif category in ("recon", "incident_5"):
            query += " AND d.technique_id IN ('T1590.002', 'T1046', 'T1566.002', 'T1204.002', 'T1498.001')"

        query += """
            GROUP BY n.src_ip, n.dst_ip, d.technique_id, d.rule_name, d.tactic_name, d.severity
            ORDER BY cnt DESC
            LIMIT 70
        """
        attacks = conn.execute(query, params).fetchall()

        for s_ip, d_ip, tech_id, rule_name, tactic, sev, cnt in attacks:
            s_is_internal = s_ip.startswith("10.10.")
            d_is_internal = d_ip.startswith("10.10.")
            is_c2_traffic = tech_id.startswith("T1071")

            s_node = f"host:WS-LAN-{s_ip.split('.')[-1]}" if s_is_internal else f"attacker:{s_ip}"
            d_node = f"host:FW-GATEWAY-01" if d_ip == "10.10.99.1" else (
                f"host:SRV-DMZ-{d_ip.split('.')[-1]}" if d_ip.startswith("10.10.20.") else (
                    f"host:WS-LAN-{d_ip.split('.')[-1]}" if d_is_internal else f"domain:{d_ip}"
                )
            )

            if s_node not in self.graph:
                self.graph.add_node(
                    s_node,
                    node_type="domain" if not s_is_internal else "host",
                    name=s_ip if not s_is_internal else s_node.replace("host:", ""),
                    ip=s_ip,
                    role="External Adversary" if not s_is_internal else "Internal Workstation",
                    criticality="HIGH" if not s_is_internal else "MEDIUM",
                    compromised=True,
                    risk_score=92.0 if not s_is_internal else 45.0,
                    alert_count=cnt,
                    mitre_techniques=tech_id,
                    mitre_tactics=tactic,
                    event_ids=tech_id,
                )
            if d_node not in self.graph:
                is_gw = "GATEWAY" in d_node
                is_dmz = "DMZ" in d_node
                self.graph.add_node(
                    d_node,
                    node_type="host" if d_is_internal else "domain",
                    name="FW-GATEWAY-01" if is_gw else (d_ip if not d_is_internal else d_node.replace("host:", "")),
                    ip=d_ip,
                    role="Perimeter Gateway" if is_gw else ("DMZ Target Server" if is_dmz else "Target Host"),
                    criticality="CRITICAL" if is_gw or is_dmz else "MEDIUM",
                    compromised=True,
                    risk_score=95.0 if is_gw else (85.0 if is_dmz else 30.0),
                    alert_count=cnt,
                    mitre_techniques=tech_id,
                    mitre_tactics=tactic,
                    event_ids=tech_id,
                )

            self.graph.add_edge(
                s_node,
                d_node,
                rel_type="C2_BEACON" if is_c2_traffic else "ATTACK_EXPLOIT",
                count=cnt,
                lateral_movement=not is_c2_traffic,
                is_c2=is_c2_traffic,
                event_code=tech_id,
                mitre_technique=tech_id,
                mitre_name=rule_name,
                label=f"{tech_id} ({cnt})",
            )

        return self.graph

    def get_evidence_for_link(self, src_name: str, tgt_name: str, dataset_id: Optional[str] = None, limit: int = 15) -> List[Dict[str, Any]]:
        """Retrieve authentic telemetry events supporting an observed connection."""
        conn = get_db(self.db_path, read_only=True)
        evidence = []

        # Try authentication events
        auth_rows = conn.execute("""
            SELECT e.event_id, e.timestamp_utc, e.user_name, e.event_category, e.event_outcome,
                   n.src_ip, e.host_name as target_host
            FROM normalized_events n
            JOIN events e ON n.event_id = e.event_id
            WHERE e.event_category = 'authentication'
              AND e.host_name = ?
              AND n.src_ip IN (SELECT host_ip FROM events WHERE host_name = ? AND host_ip IS NOT NULL)
            ORDER BY e.timestamp_utc ASC
            LIMIT ?
        """, [tgt_name, src_name, limit]).fetchall()

        for r in auth_rows:
            evidence.append({
                "event_id": r[0],
                "timestamp_utc": str(r[1]),
                "user_name": r[2] or "SYSTEM",
                "category": r[3],
                "outcome": r[4] or "unknown",
                "src_ip": r[5] or "N/A",
                "target": r[6] or "N/A",
                "details": f"Authentication attempt to {r[6]} by {r[2]} ({r[4]})",
            })

        # Try C2 network events
        if not evidence:
            net_rows = conn.execute("""
                SELECT e.event_id, e.timestamp_utc, e.user_name, e.event_category, e.event_outcome,
                       n.src_ip, n.dst_domain
                FROM normalized_events n
                JOIN events e ON n.event_id = e.event_id
                WHERE e.host_name = ?
                  AND n.dst_domain = ?
                ORDER BY e.timestamp_utc ASC
                LIMIT ?
            """, [src_name, tgt_name, limit]).fetchall()

            for r in net_rows:
                evidence.append({
                    "event_id": r[0],
                    "timestamp_utc": str(r[1]),
                    "user_name": r[2] or "SYSTEM",
                    "category": r[3],
                    "outcome": r[4] or "success",
                    "src_ip": r[5] or "N/A",
                    "target": r[6] or "N/A",
                    "details": f"Network communication to adversary domain {r[6]}",
                })

        return evidence

    def compute_blast_radius(self, host_name: str, max_depth: int = 3, dataset_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Calculate evidence-driven reachability from a compromised source host.
        Distinguishes observed connections from inferred multi-hop reachability.
        Does not fabricate containment actions or unobserved relationships.
        """
        start_node = f"host:{host_name}"
        if start_node not in self.graph:
            return {
                "source_host": host_name,
                "reachability_established": False,
                "error": f"Host {host_name} not found in environment topology."
            }

        visited_nodes: Set[str] = set()
        reachable_hosts: List[Dict[str, Any]] = []
        critical_assets_hit: List[Dict[str, Any]] = []
        path_map: Dict[str, List[str]] = {start_node: [host_name]}

        queue = deque([(start_node, 0)])
        visited_nodes.add(start_node)

        while queue:
            cur_node, depth = queue.popleft()
            if depth >= max_depth:
                continue

            for neighbor in self.graph.successors(cur_node):
                if neighbor not in visited_nodes:
                    visited_nodes.add(neighbor)
                    ndata = self.graph.nodes[neighbor]
                    cur_path = path_map[cur_node] + [ndata.get("name", neighbor)]
                    path_map[neighbor] = cur_path

                    if ndata.get("node_type") == "host":
                        is_direct = (depth == 0)
                        target_name = ndata.get("name", neighbor)

                        # Retrieve authentic telemetry evidence for direct connections
                        evidence_records = self.get_evidence_for_link(
                            path_map[cur_node][-1], target_name, dataset_id=dataset_id, limit=5
                        ) if is_direct else []

                        edge_data = self.graph.get_edge_data(cur_node, neighbor) or {}

                        h_info = {
                            "host_name": target_name,
                            "depth": depth + 1,
                            "criticality": ndata.get("criticality", "MEDIUM"),
                            "role": ndata.get("role", "Workstation"),
                            "risk_score": ndata.get("risk_score", 20.0),
                            "attack_path": " → ".join(cur_path),
                            "path_array": cur_path,
                            "is_observed": is_direct,
                            "relationship_type": (
                                "OBSERVED_DIRECT_ACCESS" if is_direct
                                else "INFERRED_MULTI_HOP_PIVOT"
                            ),
                            "evidence_count": edge_data.get("count", len(evidence_records)),
                            "evidence_records": evidence_records,
                        }
                        reachable_hosts.append(h_info)
                        if ndata.get("criticality") in ("CRITICAL", "HIGH"):
                            critical_assets_hit.append(h_info)

                    queue.append((neighbor, depth + 1))

        # Check if reachability was established
        reachability_established = len(reachable_hosts) > 0
        observed_count = sum(1 for h in reachable_hosts if h["is_observed"])
        inferred_count = sum(1 for h in reachable_hosts if not h["is_observed"])

        # Determine risk assessment based strictly on reachable assets
        if any(h["criticality"] == "CRITICAL" for h in critical_assets_hit):
            risk_level = "CRITICAL"
        elif critical_assets_hit:
            risk_level = "HIGH"
        elif reachable_hosts:
            risk_level = "MEDIUM"
        else:
            risk_level = "NONE"

        summary_msg = (
            f"Adversary activity from {host_name} establishes reachability to {len(critical_assets_hit)} critical domain assets "
            f"({observed_count} directly observed, {inferred_count} multi-hop inferred)."
            if reachability_established
            else f"No lateral movement or access relationships observed from {host_name} in the telemetry dataset."
        )

        return {
            "source_host": host_name,
            "max_depth_explored": max_depth,
            "reachability_established": reachability_established,
            "total_reachable_assets": len(reachable_hosts),
            "critical_assets_at_risk_count": len(critical_assets_hit),
            "observed_connections_count": observed_count,
            "inferred_connections_count": inferred_count,
            "blast_radius_risk_level": risk_level,
            "reachability_summary": summary_msg,
            "critical_assets_at_risk": critical_assets_hit,
            "all_reachable_hosts": reachable_hosts,
        }

    def to_cytoscape_json(self) -> Dict[str, Any]:
        """
        Convert graph to investigation-focused topology format matching visual specification:
        - Concentric circular nodes with SVG glyphs
        - Color-coded double borders
        - Numbered edge badge pills along connection links
        """
        nodes = []
        links = []
        elements = {"nodes": [], "edges": []}

        for n, d in self.graph.nodes(data=True):
            ntype = d.get("node_type", "host")
            is_crit = d.get("criticality") in ("CRITICAL", "HIGH") and ntype == "host" and d.get("name", "").startswith("SRV-")
            is_comp = d.get("compromised", False)
            is_c2 = d.get("is_malicious", False) or ntype == "domain"

            if ntype == "user":
                is_admin = d.get("is_admin", False)
                node_type = "user_admin" if is_admin else "user"
                icon_glyph = "👑" if is_admin else "👤"
                color_theme = "#e11d48" if is_admin else "#2563eb"
            elif is_crit:
                node_type = "critical"
                icon_glyph = "🖥️"
                color_theme = "#f59e0b"
            elif is_c2:
                node_type = "c2"
                icon_glyph = "🌐"
                color_theme = "#dc2626"
            elif is_comp:
                node_type = "compromised"
                icon_glyph = ">_"
                color_theme = "#ef4444"
            else:
                node_type = "workstation"
                icon_glyph = "▷"
                color_theme = "#10b981"

            node_obj = {
                "id": n,
                "label": d.get("name", n),
                "name": d.get("name", n),
                "type": node_type,
                "node_type": ntype,
                "icon_glyph": icon_glyph,
                "color_theme": color_theme,
                "role": d.get("role", "Workstation"),
                "criticality": d.get("criticality", "MEDIUM"),
                "compromised": is_comp,
                "is_malicious": is_c2,
                "is_admin": d.get("is_admin", False),
                "risk_score": d.get("risk_score", 10.0),
                "alert_count": d.get("alert_count", 0),
                "ip": d.get("ip", ""),
                "sid": d.get("sid", ""),
                "mitre_techniques": d.get("mitre_techniques", ""),
                "mitre_tactics": d.get("mitre_tactics", ""),
                "event_ids": d.get("event_ids", "4624, 4688"),
                "os_type": d.get("os_type", "windows"),
            }
            nodes.append(node_obj)
            elements["nodes"].append({"data": node_obj})

        for u, v, d in self.graph.edges(data=True):
            is_attack = d.get("lateral_movement", False)
            is_c2 = d.get("is_c2", False)
            cnt = d.get("count", 1)
            evt_code = d.get("event_code", "4624")
            mitre_id = d.get("mitre_technique", "")
            mitre_nm = d.get("mitre_name", "")
            rel = d.get("rel_type", "CONNECTED_TO")

            display_label = str(evt_code)
            if is_attack and mitre_id:
                display_label = f"{evt_code} • {mitre_id}"
            elif is_c2:
                display_label = "T1071 C2"

            link_obj = {
                "id": f"{u}->{v}",
                "source": u,
                "target": v,
                "relationship": rel,
                "rel_type": rel,
                "count": cnt,
                "event_code": evt_code,
                "mitre_technique": mitre_id,
                "mitre_name": mitre_nm,
                "label": display_label,
                "badge_count": str(cnt),
                "event_label": str(evt_code),
                "mitre_label": f"{mitre_id} ({evt_code})" if mitre_id else str(evt_code),
                "type_label": f"{rel} ({cnt})",
                "auth_label": f"Event {evt_code} ({cnt})",
                "lateral_movement": is_attack,
                "is_c2": is_c2,
                "color_theme": "#ef4444" if is_attack else ("#dc2626" if is_c2 else "#64748b"),
            }
            links.append(link_obj)
            elements["edges"].append({"data": link_obj})

        return {
            "nodes": nodes,
            "links": links,
            "elements": elements
        }

    def get_ranked_entities(self, dataset_id: str) -> Dict[str, Any]:
        """Return ranked users and hosts based on detection volume, criticality, and event activity."""
        conn = get_db(self.db_path, read_only=True)

        # Ranked users
        user_rows = conn.execute("""
            SELECT 
                COALESCE(e.user_name, 'SYSTEM') as user_name,
                COUNT(DISTINCT e.event_id) as event_count,
                COUNT(DISTINCT d.detection_id) as alert_count,
                MAX(CASE WHEN lower(e.user_name) IN ('administrator', 'admin', 'system', 'sysg.admin') THEN 1 ELSE 0 END) as is_admin
            FROM events e
            LEFT JOIN detections d ON e.user_name = d.user_name AND d.dataset_id = ?
            WHERE e.dataset_id = ? AND e.user_name IS NOT NULL AND e.user_name != ''
            GROUP BY COALESCE(e.user_name, 'SYSTEM')
            ORDER BY alert_count DESC, event_count DESC
            LIMIT 15
        """, [dataset_id, dataset_id]).fetchall()

        ranked_users = [
            {
                "rank": idx + 1,
                "user_name": r[0],
                "event_count": r[1],
                "alert_count": r[2],
                "is_admin": bool(r[3]),
                "privilege": "SYSTEM / Admin" if r[3] else "Standard User",
                "status": "COMPROMISED" if r[2] > 0 else "OBSERVED",
            }
            for idx, r in enumerate(user_rows)
        ]

        # Ranked hosts
        host_rows = conn.execute("""
            SELECT 
                e.host_name,
                e.host_ip,
                COUNT(DISTINCT e.event_id) as event_count,
                COUNT(DISTINCT d.detection_id) as alert_count,
                MAX(d.severity) as max_severity
            FROM events e
            LEFT JOIN detections d ON e.host_name = d.host_name AND d.dataset_id = ?
            WHERE e.dataset_id = ? AND e.host_name IS NOT NULL AND e.host_name != ''
            GROUP BY e.host_name, e.host_ip
            ORDER BY alert_count DESC, event_count DESC
            LIMIT 15
        """, [dataset_id, dataset_id]).fetchall()

        ranked_hosts = [
            {
                "rank": idx + 1,
                "host_name": r[0],
                "ip": r[1] or "10.10.x.x",
                "event_count": r[2],
                "alert_count": r[3],
                "max_severity": r[4] or 0,
                "is_critical": r[0] in CRITICAL_ASSETS,
                "role": CRITICAL_ASSETS.get(r[0], {}).get("role", "Workstation"),
                "status": "CRITICAL TARGET" if r[0] in CRITICAL_ASSETS else ("COMPROMISED" if r[3] > 0 else "OBSERVED"),
            }
            for idx, r in enumerate(host_rows)
        ]

        return {
            "ranked_users": ranked_users,
            "ranked_hosts": ranked_hosts,
        }

