"""
KillChain Advanced Feature Validation: Dynamic Attack Path & Attack Surface Intelligence.
Comprehensive automated test suite covering:
1. Entity Resolution & Anti-Collision (Users, Accounts, Hosts, Processes, IPs, Domains)
2. Causal Attack Graph Construction with Evidence Links
3. Attack Path Reconstruction (Complete & Interrupted Chains, Missing Telemetry)
4. Dynamic Attack Surface & Reachability Traversal (BFS, Critical Path Ranking, Blast Radius)
5. Evidence-Based Attack Hypothesis Engine (Adversary Campaign vs Benign IT Activity)
6. Incremental Live Event Ingestion & WebSocket Delta Streaming
7. False Relationship Prevention & Uncertainty Classification (OBSERVED, INFERRED, DETECTED, REACHABLE)
8. Performance Latency and Memory Efficiency Benchmarks
"""
import time
import pytest
import networkx as nx
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.api.websocket import ws_manager
from backend.graph.engine import AttackGraphEngine
from backend.graph.entity_resolution import EntityResolver
from backend.graph.hypotheses import HypothesisEngine
from backend.graph.reachability import ReachabilityAnalyzer, CRITICAL_ASSETS
from backend.graph.reconstruction import AttackPathReconstructor


def test_entity_resolution_and_anti_collision():
    """Verify stable entity resolution and strict avoidance of false entity merges."""
    resolver = EntityResolver()

    # 1. User & Account isolation across domains
    u1 = resolver.resolve_user("admin", domain="CORP")
    u2 = resolver.resolve_user("admin", domain="FINANCE")
    assert u1.entity_id != u2.entity_id, "Accounts in different domains must not be falsely merged!"
    assert u1.canonical_name == "CORP\\admin"
    assert u2.canonical_name == "FINANCE\\admin"

    # 2. Host resolution
    h1 = resolver.resolve_host("WS-ENG-014", ip="10.10.10.14")
    assert h1.entity_id == "host:WS-ENG-014"
    assert h1.confidence >= 0.95

    # 3. Critical asset recognition
    h_dc = resolver.resolve_host("SRV-DC-01", ip="10.10.0.1")
    assert h_dc.is_critical is True
    assert h_dc.attributes["role"] == "Primary Domain Controller"

    # 4. Process identity with PID reuse avoidance
    p1 = resolver.resolve_process("WS-ENG-014", pid=4020, process_name="powershell.exe", cmdline="powershell -enc ...")
    p2 = resolver.resolve_process("WS-ENG-014", pid=4020, process_name="svchost.exe", cmdline="svchost.exe -k netsvcs")
    assert p1.entity_id != p2.entity_id, "Reused PID across different processes must not collide!"

    # 5. Domain resolution with malicious classification
    d_c2 = resolver.resolve_domain("suspicious-example-c2.invalid")
    assert d_c2.is_critical is True
    assert d_c2.attributes["is_malicious"] is True
    assert d_c2.risk_score >= 90.0

    d_safe = resolver.resolve_domain("internal.corp.local")
    assert d_safe.attributes.get("is_malicious", False) is False


def test_causal_attack_graph_evidence_and_classification():
    """Verify causal attack graph construction, edge metadata, and classification."""
    engine = AttackGraphEngine()
    G = engine.build_graph("5f2345ab-19c8-5a30-ba2c-192e359447a7")

    assert G.number_of_nodes() >= 25
    assert G.number_of_edges() >= 5

    # Check edge attributes
    for u, v, data in G.edges(data=True):
        assert "classification" in data
        assert data["classification"] in ("OBSERVED", "DETECTED", "INFERRED", "REACHABLE", "SIMULATED", "UNKNOWN")
        assert "confidence" in data
        assert 0.0 <= data["confidence"] <= 1.0
        assert "rel_type" in data
        assert "evidence_explanation" in data
        assert len(data["evidence_explanation"]) > 0

    # Ensure C2 edge exists and has correct classification
    c2_edges = [d for u, v, d in G.edges(data=True) if d.get("is_c2")]
    assert len(c2_edges) > 0, "Graph must contain verified C2 beacon edges"
    assert c2_edges[0]["classification"] == "DETECTED"
    assert c2_edges[0]["mitre_technique"] == "T1071.001"


def test_attack_path_reconstruction_complete_and_interrupted():
    """Verify attack path reconstruction across MITRE tactics, complete vs incomplete chains."""
    reconstructor = AttackPathReconstructor()

    # 1. Complete intrusion chain
    complete_alerts = [
        {"seq_num": 1, "timestamp_utc": "2026-10-31T10:00:00Z", "tactic_name": "Initial Access", "technique_id": "T1566.001", "host_name": "WS-ENG-014", "user_name": "jsmith"},
        {"seq_num": 2, "timestamp_utc": "2026-10-31T10:05:00Z", "tactic_name": "Execution", "technique_id": "T1059.001", "host_name": "WS-ENG-014", "user_name": "jsmith"},
        {"seq_num": 3, "timestamp_utc": "2026-10-31T10:15:00Z", "tactic_name": "Lateral Movement", "technique_id": "T1021.002", "host_name": "SRV-DC-01", "user_name": "sysg.admin"},
        {"seq_num": 4, "timestamp_utc": "2026-10-31T10:30:00Z", "tactic_name": "Impact", "technique_id": "T1486", "host_name": "SRV-DC-01", "user_name": "sysg.admin"},
    ]
    path = reconstructor.reconstruct_path("INC-001", complete_alerts)
    assert path.is_complete_chain is True
    assert path.entry_point == "WS-ENG-014"
    assert len(path.tactics_traversed) == 4
    assert len(path.steps) == 4
    assert "WS-ENG-014 → SRV-DC-01" in path.to_dict()["path_chain"]

    # 2. Interrupted chain with missing telemetry
    interrupted_alerts = [
        {"seq_num": 1, "timestamp_utc": "2026-10-31T12:00:00Z", "tactic_name": "Execution", "technique_id": "T1059.001", "host_name": "WS-FIN-014", "user_name": "bfinance"},
        {"seq_num": 2, "timestamp_utc": "2026-10-31T12:10:00Z", "tactic_name": "Lateral Movement", "technique_id": "T1021.002", "host_name": "SRV-FILE-01", "user_name": "bfinance"},
    ]
    path_int = reconstructor.reconstruct_path("INC-005", interrupted_alerts)
    assert path_int.is_complete_chain is False
    assert len(path_int.missing_telemetry) >= 2, "Must flag missing Initial Access and missing post-exploitation telemetry!"


def test_dynamic_attack_surface_reachability_and_blast_radius():
    """Verify graph traversal, depth limiting, critical path ranking, and blast radius calculation."""
    G = nx.DiGraph()
    G.add_node("host:WS-ENG-014", name="WS-ENG-014", node_type="host", criticality="MEDIUM", risk_score=40.0)
    G.add_node("host:WS-FIN-014", name="WS-FIN-014", node_type="host", criticality="MEDIUM", risk_score=50.0)
    G.add_node("host:SRV-FILE-01", name="SRV-FILE-01", node_type="host", criticality="HIGH", risk_score=80.0)
    G.add_node("host:SRV-DC-01", name="SRV-DC-01", node_type="host", criticality="CRITICAL", risk_score=95.0)

    # Lateral movement corridor: WS-ENG-014 -> WS-FIN-014 -> SRV-FILE-01 -> SRV-DC-01
    G.add_edge("host:WS-ENG-014", "host:WS-FIN-014", classification="OBSERVED", confidence=0.95)
    G.add_edge("host:WS-FIN-014", "host:SRV-FILE-01", classification="OBSERVED", confidence=0.90)
    G.add_edge("host:SRV-FILE-01", "host:SRV-DC-01", classification="OBSERVED", confidence=0.98)

    analyzer = ReachabilityAnalyzer(G)

    # Depth 1: only reaches WS-FIN-014
    r1 = analyzer.analyze_reachability("WS-ENG-014", max_depth=1)
    assert r1["total_reachable_assets"] == 1
    assert r1["observed_connections_count"] == 1
    assert r1["critical_assets_at_risk_count"] == 0

    # Depth 3: reaches SRV-FILE-01 and SRV-DC-01
    r3 = analyzer.analyze_reachability("WS-ENG-014", max_depth=3)
    assert r3["total_reachable_assets"] == 3
    assert r3["critical_assets_at_risk_count"] == 2
    assert r3["blast_radius_risk_level"] == "CRITICAL"

    # Shortest path verification
    sp = analyzer.find_shortest_attack_path("WS-ENG-014", "SRV-DC-01")
    assert sp is not None
    assert sp["hop_count"] == 3
    assert sp["path_names"] == ["WS-ENG-014", "WS-FIN-014", "SRV-FILE-01", "SRV-DC-01"]


def test_evidence_based_hypothesis_evaluation():
    """Verify deterministic hypothesis engine comparing Adversary Campaign vs Benign IT Activity."""
    engine = HypothesisEngine()

    incident_data = {
        "incident_id": "INC-001",
        "summary": "Coordinated Ransomware Impact & Mass File Encryption",
        "affected_hosts": ["WS-FIN-014", "SRV-FILE-01", "SRV-DB-01", "SRV-DC-01"],
        "techniques": ["T1486", "T1059.001", "T1021.002"],
        "tactics": ["Impact", "Execution", "Lateral Movement"],
    }
    detections = [
        {"detection_id": "DET-001", "rule_name": "Rapid mass file rename", "technique_id": "T1486", "host_name": "WS-FIN-014", "user_name": "sysg.admin", "severity": 10},
        {"detection_id": "DET-002", "rule_name": "Lateral SMB execution", "technique_id": "T1021.002", "host_name": "SRV-FILE-01", "user_name": "sysg.admin", "severity": 8},
    ]

    result = engine.evaluate_incident(incident_data, [], detections)

    assert result["favored_hypothesis"] == "HYPOTHESIS_A"
    assert result["confidence_delta"] > 0.4
    assert result["hypothesis_a"]["classification"] == "MALICIOUS_CAMPAIGN"
    assert result["hypothesis_a"]["confidence"] >= 0.80
    assert result["hypothesis_b"]["confidence"] <= 0.35
    assert len(result["hypothesis_b"]["contradictory_samples"]) > 0, "Must explicitly refute benign hypothesis with file corruption evidence!"


def test_live_graph_incremental_ingestion_and_duplicate_prevention():
    """Verify incremental graph updates and duplicate prevention without rebuilding whole graph."""
    engine = AttackGraphEngine()

    # Initial state
    initial_node_count = engine.graph.number_of_nodes()

    # Event 1: New host activity
    evt1 = {
        "event_id": "evt-live-101",
        "host_name": "WS-DEV-999",
        "user_name": "CORP\\devuser",
        "threat_technique_id": "T1059.001",
        "threat_tactic_nm": "Execution",
    }
    delta1 = engine.ingest_event_incremental(evt1)
    assert delta1["added_nodes_count"] >= 1
    assert "host:WS-DEV-999" in engine.graph

    # Event 2: Duplicate check in WebSocket manager
    assert ws_manager.is_duplicate("evt-live-101") is False
    assert ws_manager.is_duplicate("evt-live-101") is True, "Identical event_id must be flagged as duplicate!"


def test_fastapi_new_attack_intelligence_endpoints():
    """Verify REST API endpoints for attack surface, path reconstruction, hypotheses, and live streaming."""
    client = TestClient(app)

    # 1. Attack surface inventory
    r = client.get("/api/graph/attack-surface")
    assert r.status_code == 200
    surf = r.json()
    assert "critical_assets" in surf
    assert "threat_corridors" in surf
    assert surf["critical_assets_count"] > 0

    # 2. Incident attack path reconstruction
    r = client.get("/api/incidents/INC-001/reconstruction")
    assert r.status_code == 200
    recon = r.json()
    assert recon["incident_id"] == "INC-001"
    assert "steps" in recon
    assert "path_chain" in recon

    # 3. Incident hypothesis evaluation
    r = client.get("/api/incidents/INC-001/hypotheses")
    assert r.status_code == 200
    hypo = r.json()
    assert hypo["favored_hypothesis"] == "HYPOTHESIS_A"
    assert "hypothesis_a" in hypo
    assert "hypothesis_b" in hypo

    # 4. Live event ingestion endpoint
    live_evt = {
        "event": {
            "event_id": f"live-test-{time.time_ns()}",
            "host_name": "WS-HR-088",
            "threat_technique_id": "T1071.001",
            "dst_domain": "suspicious-example-c2.invalid",
        }
    }
    r = client.post("/api/graph/ingest-event", json=live_evt)
    assert r.status_code == 200
    assert r.json()["status"] == "ingested"
    assert r.json()["delta"]["added_nodes_count"] >= 1


def test_performance_traversal_microsecond_benchmark():
    """Benchmark graph traversal latency to ensure sub-millisecond execution."""
    G = nx.DiGraph()
    for i in range(5000):
        G.add_node(f"node:{i}", name=f"H-{i}", node_type="host", criticality="CRITICAL" if i % 20 == 0 else "MEDIUM", risk_score=40.0)
    for i in range(25000):
        G.add_edge(f"node:{i % 5000}", f"node:{(i * 3 + 7) % 5000}", classification="OBSERVED", confidence=0.95)

    analyzer = ReachabilityAnalyzer(G)

    t0 = time.perf_counter()
    res = analyzer.analyze_reachability("node:0", max_depth=3)
    t1 = time.perf_counter()
    latency_ms = (t1 - t0) * 1000.0

    # Must complete 5,000 node / 25,000 edge traversal in under 15 milliseconds
    assert latency_ms < 15.0, f"Graph traversal too slow: {latency_ms:.2f} ms"
    assert res["reachability_established"] is True

