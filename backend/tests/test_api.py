"""
Backend API Unit Tests
"""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_root_health():
    res = client.get("/")
    assert res.status_code == 200
    assert res.json()["status"] == "online"

def test_investigate_ssh_brute_force():
    payload = {
        "raw_input": "2026-09-28T09:12:00Z auth.fail 198.51.100.24 user=root count=120 ssh brute force",
        "source": "RAW_SYSLOG_WEBHOOK"
    }
    res = client.post("/api/investigate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "recommendation" in data
    assert data["recommendation"]["resolution_id"] == "RES-SSH-001"
    assert data["recommendation"]["confidence"] >= 0.50

def test_feedback_submission():
    payload = {
        "resolution_id": "RES-SSH-001",
        "incident_id": "INC-2026-0042",
        "feedback_outcome": "success"
    }
    res = client.post("/api/feedback", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["memory_updated"] is True
    assert data["metrics"]["times_used"] > 0
