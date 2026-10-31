"""
KillChain End-to-End Automated Test Suite.
Verifies Ingestion, Detection Engine, Correlation Engine,
Attack Graph Traversal, and REST API Endpoints.
"""
import pytest
from fastapi.testclient import TestClient

from backend.database import get_db, init_schema
from backend.detection.engine import DetectionEngine
from backend.correlation.engine import CorrelationEngine
from backend.graph.engine import AttackGraphEngine
from backend.scoring.engine import ScoringEngine
from backend.api.main import app

DATASET_ID = "5f2345ab-19c8-5a30-ba2c-192e359447a7"


def test_database_counts():
    conn = get_db()
    init_schema()
    events_count = conn.execute("SELECT count(*) FROM events WHERE dataset_id = ?", [DATASET_ID]).fetchone()[0]
    norm_count = conn.execute("SELECT count(*) FROM normalized_events WHERE event_id IN (SELECT event_id FROM events WHERE dataset_id = ?)", [DATASET_ID]).fetchone()[0]
    assert events_count == 10000, f"Expected 10,000 events, got {events_count}"
    assert norm_count == 10000, f"Expected 10,000 normalized events, got {norm_count}"


def test_detection_engine():
    de = DetectionEngine(rules_dir="rules")
    summary = de.run_detection(DATASET_ID)
    assert summary["total_detections"] >= 504, "Must catch all 504 ground-truth alerts"
    assert summary["rules_evaluated"] >= 5

    # Check each critical rule count
    by_rule = summary["detections_by_rule"]
    assert by_rule.get("Rapid mass file rename to uniform extension") == 88
    assert by_rule.get("Beaconing to low-reputation destination") == 118
    assert by_rule.get("Autorun key created by scripting engine") == 103
    assert by_rule.get("Office application spawned a scripting engine") == 98


def test_correlation_engine():
    ce = CorrelationEngine()
    summary = ce.run_correlation(DATASET_ID)
    assert summary["incidents_created"] >= 5
    assert summary["alerts_correlated"] >= 504


def test_attack_graph_and_blast_radius():
    ge = AttackGraphEngine()
    G = ge.build_graph(DATASET_ID)
    assert G.number_of_nodes() >= 28
    assert G.number_of_edges() > 0

    br = ge.compute_blast_radius("WS-ENG-014", max_depth=3)
    assert br["blast_radius_risk_level"] == "CRITICAL"
    assert br["critical_assets_at_risk_count"] >= 3
    critical_names = [c["host_name"] for c in br["critical_assets_at_risk"]]
    assert "SRV-DC-01" in critical_names, "Domain controller must be reachable in blast radius"


def test_ground_truth_scoring():
    se = ScoringEngine()
    res = se.evaluate(DATASET_ID)
    m = res["metrics"]
    cm = res["confusion_matrix"]

    assert cm["false_negatives"] == 0, "Recall must be 100% (Zero false negatives)"
    assert m["recall"] == 1.0
    assert m["accuracy"] >= 0.95
    assert m["specificity"] >= 0.95
    assert m["f1_score"] >= 0.85


def test_fastapi_endpoints():
    client = TestClient(app)

    # Health
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

    # Stats
    r = client.get(f"/api/stats?dataset_id={DATASET_ID}")
    assert r.status_code == 200
    stats = r.json()
    assert stats["total_events"] >= 10000
    assert stats["active_incidents"] >= 5

    # Incidents list & detail
    r = client.get(f"/api/incidents?dataset_id={DATASET_ID}")
    assert r.status_code == 200
    incidents = r.json()
    assert len(incidents) >= 5

    first_inc_id = incidents[0]["incident_id"]
    r = client.get(f"/api/incidents/{first_inc_id}")
    assert r.status_code == 200
    assert "timeline" in r.json()

    # Detections list
    r = client.get(f"/api/detections?dataset_id={DATASET_ID}&limit=10")
    assert r.status_code == 200
    assert len(r.json()) == 10

    # Graph
    r = client.get(f"/api/graph?dataset_id={DATASET_ID}")
    assert r.status_code == 200
    assert "nodes" in r.json()

    # Blast Radius
    r = client.get("/api/blast-radius/WS-ENG-014")
    assert r.status_code == 200
    assert r.json()["blast_radius_risk_level"] == "CRITICAL"

    # Evaluation
    r = client.get("/api/evaluation")
    assert r.status_code == 200
    assert r.json()["metrics"]["recall"] == 1.0
