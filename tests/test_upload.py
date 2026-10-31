"""
Test upload endpoint for local security log files.
"""
import io
import pytest
from fastapi.testclient import TestClient
from backend.api.main import app

def test_upload_jsonl_log_file():
    client = TestClient(app)
    
    # Create sample JSONL log content
    sample_content = (
        '{"@timestamp": "2026-10-31T12:00:00Z", "host": {"name": "WS-TEST-001"}, "user": {"name": "CORP\\\\testuser"}, "threat": {"technique": {"id": "T1059.001", "name": "PowerShell Script"}, "tactic": {"name": "Execution"}}, "rule": {"id": "rule-01", "name": "Suspicious PowerShell"}}\n'
        '{"@timestamp": "2026-10-31T12:01:00Z", "host": {"name": "WS-TEST-001"}, "user": {"name": "CORP\\\\testuser"}, "dns": {"question": {"name": "suspicious-example-c2.invalid"}}, "threat": {"technique": {"id": "T1071.001", "name": "C2 Beacon"}, "tactic": {"name": "Command and Control"}}, "rule": {"id": "rule-02", "name": "C2 Domain Beacon"}}\n'
    )
    
    file_bytes = io.BytesIO(sample_content.encode("utf-8"))
    files = {"file": ("test_edr.jsonl", file_bytes, "application/json")}
    
    response = client.post("/api/upload-log", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["total_records"] == 2
    assert "upload-" in data["dataset_id"]
    assert data["detections_count"] >= 1
    assert data["graph_nodes"] >= 2


def test_upload_fortigate_kv_log_file():
    client = TestClient(app)
    
    sample_kv = (
        'date=2026-10-31 time=14:00:00 devname="FW-GATEWAY-01" srcip=192.168.1.100 dstip=10.10.99.1 attack="Apache.Log4j.Error.Log.Remote.Code.Execution" action="blocked"\n'
        'date=2026-10-31 time=14:02:00 devname="FW-GATEWAY-01" srcip=192.168.1.100 dstip=10.10.0.1 attack="ZeroLogon.Netlogon.Privilege.Escalation" action="detected"\n'
    )
    
    file_bytes = io.BytesIO(sample_kv.encode("utf-8"))
    files = {"file": ("firewall_sample.log", file_bytes, "text/plain")}
    
    response = client.post("/api/upload-log", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["total_records"] == 2
    assert data["format"] == "kv_log"
    assert data["detections_count"] >= 1

