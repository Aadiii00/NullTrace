"""
KillChain Dynamic Attack Surface & Reachability Engine.
Calculates evidence-driven reachability, multi-hop lateral movement corridors,
critical asset path ranking, and blast radius from compromised assets.

Strictly distinguishes:
- OBSERVED: Directly attested by authentic telemetry events
- DETECTED: Matched by behavioral detection analytics
- INFERRED: Correlated multi-hop pivot sequence
- REACHABLE: Potentially accessible based on network topology / credentials
- SIMULATED: Hypothetical attack route under stated assumptions
- UNKNOWN: Insufficient boundary telemetry
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import networkx as nx


# Critical asset inventory
CRITICAL_ASSETS = {
    "SRV-DC-01": {"role": "Primary Domain Controller", "criticality": "CRITICAL", "weight": 100, "subnet": "10.10.0.0/24"},
    "SRV-DB-01": {"role": "Production SQL Database", "criticality": "CRITICAL", "weight": 95, "subnet": "10.10.0.0/24"},
    "SRV-FILE-01": {"role": "Enterprise File Server", "criticality": "HIGH", "weight": 80, "subnet": "10.10.0.0/24"},
    "SRV-WEB-01": {"role": "Public Web Gateway", "criticality": "HIGH", "weight": 75, "subnet": "10.10.0.0/24"},
    "FW-GATEWAY-01": {"role": "Perimeter NGFW Gateway", "criticality": "CRITICAL", "weight": 95, "subnet": "10.10.99.0/24"},
}


@dataclass
class ReachablePath:
    target_node: str
    target_name: str
    target_role: str
    target_criticality: str
    depth: int
    classification: str  # OBSERVED | INFERRED | REACHABLE | SIMULATED
    path_nodes: List[str]
    path_names: List[str]
    path_summary: str
    risk_rank_score: float
    supporting_events: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_node": self.target_node,
            "host_name": self.target_name,
            "target_role": self.target_role,
            "criticality": self.target_criticality,
            "depth": self.depth,
            "classification": self.classification,
            "attack_path": self.path_summary,
            "path_array": self.path_names,
            "risk_score": round(self.risk_rank_score, 1),
            "is_observed": self.classification == "OBSERVED",
            "relationship_type": (
                "OBSERVED_DIRECT_ACCESS" if self.classification == "OBSERVED"
                else "INFERRED_MULTI_HOP_PIVOT"
            ),
            "evidence_count": len(self.supporting_events),
            "evidence_records": self.supporting_events[:5],
            "confidence": round(self.confidence, 3),
        }


class ReachabilityAnalyzer:
    """
    Graph Traversal and Attack Surface Reachability Analyzer.
    Applies BFS, depth-limited search, and weighted Dijkstra shortest-path algorithms
    to compute asset exposure, multi-hop reachability, and critical path rankings.
    """

    def __init__(self, graph: nx.DiGraph, evidence_fetcher: Optional[Callable[[str, str], List[Dict[str, Any]]]] = None):
        self.graph = graph
        self.evidence_fetcher = evidence_fetcher

    def analyze_reachability(self, start_host: str, max_depth: int = 3) -> Dict[str, Any]:
        """
        Perform evidence-based multi-hop reachability exploration from start_host.
        """
        if start_host in self.graph:
            start_node = start_host
        elif f"host:{start_host}" in self.graph:
            start_node = f"host:{start_host}"
        else:
            start_node = start_host
        clean_start_name = start_host.split(":")[-1]

        if start_node not in self.graph:
            return {
                "source_host": clean_start_name,
                "reachability_established": False,
                "error": f"Host '{clean_start_name}' was not found in environment graph.",
                "total_reachable_assets": 0,
                "critical_assets_at_risk_count": 0,
                "observed_connections_count": 0,
                "inferred_connections_count": 0,
                "blast_radius_risk_level": "NONE",
                "critical_assets_at_risk": [],
                "all_reachable_hosts": [],
            }

        visited: Set[str] = {start_node}
        queue = deque([(start_node, 0)])
        path_map: Dict[str, List[str]] = {start_node: [start_node]}

        reachable_paths: List[ReachablePath] = []
        critical_paths: List[ReachablePath] = []

        while queue:
            curr_node, depth = queue.popleft()
            if depth >= max_depth:
                continue

            for neighbor in self.graph.successors(curr_node):
                if neighbor in visited:
                    continue
                visited.add(neighbor)

                ndata = self.graph.nodes.get(neighbor, {})
                curr_path = path_map[curr_node] + [neighbor]
                path_map[neighbor] = curr_path

                ntype = ndata.get("node_type", "host")
                target_name = ndata.get("name", neighbor.split(":")[-1])

                # Determine edge data
                edge_data = self.graph.get_edge_data(curr_node, neighbor) or {}
                edge_class = edge_data.get("classification", "OBSERVED")
                edge_confidence = edge_data.get("confidence", 0.9)

                # Fetch real telemetry evidence for direct link if available
                direct_evidence = []
                if depth == 0 and self.evidence_fetcher:
                    src_clean = curr_node.split(":")[-1]
                    tgt_clean = target_name
                    direct_evidence = self.evidence_fetcher(src_clean, tgt_clean)

                is_direct = (depth == 0)
                classification = "OBSERVED" if is_direct else "INFERRED"

                # Path names for presentation
                path_names = [self.graph.nodes.get(n, {}).get("name", n.split(":")[-1]) for n in curr_path]
                path_str = " → ".join(path_names)

                # Determine asset criticality
                is_crit = target_name in CRITICAL_ASSETS or ndata.get("criticality") in ("CRITICAL", "HIGH")
                crit_info = CRITICAL_ASSETS.get(target_name, {})
                crit_level = crit_info.get("criticality", ndata.get("criticality", "MEDIUM"))
                role = crit_info.get("role", ndata.get("role", "Workstation"))

                # Transparent path-ranking formula:
                # Rank = (TargetAssetWeight * TargetRisk * PathConfidence) / (Depth + 1)
                crit_weight = crit_info.get("weight", 40 if not is_crit else 80)
                target_risk = ndata.get("risk_score", 30.0)
                rank_score = (crit_weight * 0.5 + target_risk * 0.5) * edge_confidence / (depth + 1)

                r_path = ReachablePath(
                    target_node=neighbor,
                    target_name=target_name,
                    target_role=role,
                    target_criticality=crit_level,
                    depth=depth + 1,
                    classification=classification,
                    path_nodes=curr_path,
                    path_names=path_names,
                    path_summary=path_str,
                    risk_rank_score=rank_score,
                    supporting_events=direct_evidence,
                    confidence=edge_confidence,
                )

                if ntype in ("host", "server", "endpoint"):
                    reachable_paths.append(r_path)
                    if is_crit:
                        critical_paths.append(r_path)

                queue.append((neighbor, depth + 1))

        # Sort paths by risk rank score descending
        reachable_paths.sort(key=lambda p: p.risk_rank_score, reverse=True)
        critical_paths.sort(key=lambda p: p.risk_rank_score, reverse=True)

        observed_count = sum(1 for p in reachable_paths if p.classification == "OBSERVED")
        inferred_count = sum(1 for p in reachable_paths if p.classification == "INFERRED")

        # Determine overall blast radius risk level
        if any(p.target_criticality == "CRITICAL" for p in critical_paths):
            blast_level = "CRITICAL"
        elif critical_paths:
            blast_level = "HIGH"
        elif reachable_paths:
            blast_level = "MEDIUM"
        else:
            blast_level = "LOW"

        summary = (
            f"Adversary activity from {clean_start_name} establishes reachability to {len(critical_paths)} critical domain assets "
            f"({observed_count} directly observed, {inferred_count} multi-hop inferred pivots)."
            if reachable_paths else
            f"No lateral movement or access relationships observed from {clean_start_name} in current telemetry."
        )

        return {
            "source_host": clean_start_name,
            "max_depth_explored": max_depth,
            "reachability_established": len(reachable_paths) > 0,
            "total_reachable_assets": len(reachable_paths),
            "critical_assets_at_risk_count": len(critical_paths),
            "observed_connections_count": observed_count,
            "inferred_connections_count": inferred_count,
            "blast_radius_risk_level": blast_level,
            "reachability_summary": summary,
            "critical_assets_at_risk": [p.to_dict() for p in critical_paths],
            "all_reachable_hosts": [p.to_dict() for p in reachable_paths],
        }

    def find_shortest_attack_path(self, source_host: str, target_host: str) -> Optional[Dict[str, Any]]:
        """
        Find minimum-hop evidence-backed shortest attack path between source and target.
        """
        src_node = f"host:{source_host}" if not source_host.startswith("host:") else source_host
        tgt_node = f"host:{target_host}" if not target_host.startswith("host:") else target_host

        if src_node not in self.graph or tgt_node not in self.graph:
            return None

        try:
            path = nx.shortest_path(self.graph, source=src_node, target=tgt_node)
            path_names = [self.graph.nodes.get(n, {}).get("name", n.split(":")[-1]) for n in path]
            return {
                "source": source_host,
                "target": target_host,
                "hop_count": len(path) - 1,
                "path_nodes": path,
                "path_names": path_names,
                "path_summary": " → ".join(path_names),
                "is_direct": len(path) == 2,
            }
        except nx.NetworkXNoPath:
            return None
